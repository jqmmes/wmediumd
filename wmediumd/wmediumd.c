/*
 *	wmediumd, wireless medium simulator for mac80211_hwsim kernel module
 *	Copyright (c) 2011 cozybit Inc.
 *
 *	Author:	Javier Lopez	<jlopex@cozybit.com>
 *		Javier Cardona	<javier@cozybit.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *	02110-1301, USA.
 */

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <stdint.h>
#include <getopt.h>
#include <signal.h>
#include <event.h>
#include <math.h>
#include <sys/timerfd.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>

#include "thpool.h"
#include "wmediumd.h"
#include "ieee80211.h"
#include "config.h"
#include "wserver.h"
#include "wmediumd_dynamic.h"
#include "wserver_messages.h"

static struct nl_sock *nl_listen_socket;
static int timer_fd;
static struct itimerspec *expires;
static struct event *ev_cmd;
static struct event *ev_timer;
static struct event_base *cmd_event_base;
static struct event_base *timer_event_base;
static struct event *accept_event;
static int listen_soc;
static struct event_base *server_event_base;

pthread_rwlock_t timer_lock = PTHREAD_RWLOCK_INITIALIZER;

static inline int div_round(int a, int b)
{
	return (a + b - 1) / b;
}

static inline int pkt_duration(int len, int rate)
{
	/* preamble + signal + t_sym * n_sym, rate in 100 kbps */
	return 16 + 4 + 4 * div_round((16 + 8 * len + 6) * 10, 4 * rate);
}

int w_logf(struct wmediumd *ctx, u8 level, const char *format, ...)
{
	va_list(args);
	va_start(args, format);
	if (ctx->log_lvl >= level) {
		return vprintf(format, args);
	}
	return -1;
}

int w_flogf(struct wmediumd *ctx, u8 level, FILE *stream, const char *format, ...)
{
	va_list(args);
	va_start(args, format);
	if (ctx->log_lvl >= level) {
		return vfprintf(stream, format, args);
	}
	return -1;
}

static void wqueue_init(struct wqueue *wqueue, int cw_min, int cw_max)
{
	INIT_LIST_HEAD(&wqueue->frames);
	wqueue->cw_min = cw_min;
	wqueue->cw_max = cw_max;
}

void station_init_queues(struct station *station)
{
	wqueue_init(&station->queues[IEEE80211_AC_BK], 15, 1023);
	wqueue_init(&station->queues[IEEE80211_AC_BE], 15, 1023);
	wqueue_init(&station->queues[IEEE80211_AC_VI], 7, 15);
	wqueue_init(&station->queues[IEEE80211_AC_VO], 3, 7);
}

bool timespec_before(struct timespec *t1, struct timespec *t2)
{
	return t1->tv_sec < t2->tv_sec ||
	       (t1->tv_sec == t2->tv_sec && t1->tv_nsec < t2->tv_nsec);
}

void timespec_add_usec(struct timespec *t, int usec)
{
	t->tv_nsec += usec * 1000;
	if (t->tv_nsec >= 1000000000) {
		t->tv_sec++;
		t->tv_nsec -= 1000000000;
	}
}

// a - b = c
static int timespec_sub(struct timespec *a, struct timespec *b,
			struct timespec *c)
{
	c->tv_sec = a->tv_sec - b->tv_sec;

	if (a->tv_nsec < b->tv_nsec) {
		c->tv_sec--;
		c->tv_nsec = 1000000000 + a->tv_nsec - b->tv_nsec;
	} else {
		c->tv_nsec = a->tv_nsec - b->tv_nsec;
	}

	return 0;
}

void rearm_timer(struct wmediumd *ctx)
{
	struct timespec min_expires;
	struct station *station;
	struct frame *frame;
	int i;
	//printf("rearm_timer\n");

	bool set_min_expires = false;
	//w_logf(ctx, LOG_INFO, "rearm_timer\n");
	/*
	 * Iterate over all the interfaces to find the next frame that
	 * will be delivered, and set the timerfd accordingly.
	 */
	pthread_rwlock_wrlock(&timer_lock);
	list_for_each_entry(station, &ctx->stations, list) {
		for (i = 0; i < IEEE80211_NUM_ACS; i++) {
			frame = list_first_entry_or_null(&station->queues[i].frames,
							 struct frame, list);

			if (frame && (!set_min_expires ||
				      timespec_before(&frame->expires,
						      &min_expires))) {
				set_min_expires = true;
				min_expires = frame->expires;
			}
		}
	}

	if (set_min_expires) {
		memset(expires, 0, sizeof(*expires));
		expires->it_value = min_expires;
		ctx->min_expires_set = true;
		ctx->min_expires = min_expires;
		timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, expires,
				NULL);
	}
	pthread_rwlock_unlock(&timer_lock);
}

void fast_timer_rearm(struct wmediumd *ctx, struct timespec frame_expires) {
	pthread_rwlock_wrlock(&timer_lock);
	if (ctx->min_expires_set && !timespec_before(&frame_expires, &(ctx->min_expires))) goto fast_timer_rearm_out;
	ctx->min_expires_set = true;
	ctx->min_expires = frame_expires;
	memset(expires, 0, sizeof(*expires));
	expires->it_value = frame_expires;
	timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, expires,
			NULL);
	fast_timer_rearm_out:
	pthread_rwlock_unlock(&timer_lock);
}

static inline bool frame_has_a4(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *)frame->data;

	return (hdr->frame_control[1] & (FCTL_TODS | FCTL_FROMDS)) ==
		(FCTL_TODS | FCTL_FROMDS);
}

static inline bool frame_is_mgmt(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *)frame->data;

	return (hdr->frame_control[0] & FCTL_FTYPE) == FTYPE_MGMT;
}

static inline bool frame_is_data(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *)frame->data;

	return (hdr->frame_control[0] & FCTL_FTYPE) == FTYPE_DATA;
}

static inline bool frame_is_data_qos(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *)frame->data;

	return (hdr->frame_control[0] & (FCTL_FTYPE | STYPE_QOS_DATA)) ==
		(FTYPE_DATA | STYPE_QOS_DATA);
}

static inline u8 *frame_get_qos_ctl(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *)frame->data;

	if (frame_has_a4(frame))
		return (u8 *)hdr + 30;
	else
		return (u8 *)hdr + 24;
}

static enum ieee80211_ac_number frame_select_queue_80211(struct frame *frame)
{
	u8 *p;
	int priority;

	if (!frame_is_data(frame))
		return IEEE80211_AC_VO;

	if (!frame_is_data_qos(frame))
		return IEEE80211_AC_BE;

	p = frame_get_qos_ctl(frame);
	priority = *p & QOS_CTL_TAG1D_MASK;

	return ieee802_1d_to_ac[priority];
}

static double dBm_to_milliwatt(int decibel_intf)
{
#define INTF_LIMIT (31)
	int intf_diff = NOISE_LEVEL - decibel_intf;

	if (intf_diff >= INTF_LIMIT)
		return 0.001;

	if (intf_diff <= -INTF_LIMIT)
		return 1000.0;

	return pow(10.0, -intf_diff / 10.0);
}

static double milliwatt_to_dBm(double value)
{
	return 10.0 * log10(value);
}

static int set_interference_duration(struct wmediumd *ctx, int src_idx,
				     int duration, int signal)
{
	int i;

	if (!ctx->intf)
		return 0;

	if (signal >= CCA_THRESHOLD)
		return 0;

	for (i = 0; i < ctx->num_stas; i++) {
		ctx->intf[ctx->num_stas * src_idx + i].duration += duration;
		// use only latest value
		ctx->intf[ctx->num_stas * src_idx + i].signal = signal;
	}

	return 1;
}

static int get_signal_offset_by_interference(struct wmediumd *ctx, int src_idx,
					     int dst_idx)
{
	int i;
	double intf_power;

	if (!ctx->intf)
		return 0;

	intf_power = 0.0;
	for (i = 0; i < ctx->num_stas; i++) {
		if (i == src_idx || i == dst_idx)
			continue;
		if (drand48() < ctx->intf[i * ctx->num_stas + dst_idx].prob_col)
			intf_power += dBm_to_milliwatt(
				ctx->intf[i * ctx->num_stas + dst_idx].signal);
	}

	if (intf_power <= 1.0)
		return 0;

	return (int)(milliwatt_to_dBm(intf_power) + 0.5);
}

bool is_multicast_ether_addr(const u8 *addr)
{
	return 0x01 & addr[0];
}

static struct station *get_station_by_addr(struct wmediumd *ctx, u8 *addr)
{
	struct station *station;

	list_for_each_entry(station, &ctx->stations, list) {
		if (memcmp(station->addr, addr, ETH_ALEN) == 0)
			return station;
	}
	return NULL;
}

void queue_frame(void *args)
	{
	struct wmediumd *ctx = ((struct thpool_arg*)args)->ctx;
	struct station *station = ((struct thpool_arg*)args)->station;
	struct frame *frame = ((struct thpool_arg*)args)->frame;
	struct ieee80211_hdr *hdr = (void *)frame->data;
	u8 *dest = hdr->addr1;
	struct timespec now, target;
	struct wqueue *queue;
	struct frame *tail;
	struct station *tmpsta, *deststa;
	int send_time;
	int cw;
	double error_prob;
	bool is_acked = false;
	bool noack = false;
	int i, j;
	int rate_idx;
	int ac;

	/* TODO configure phy parameters */
	int slot_time = 9;
	int sifs = 16;
	int difs = 2 * slot_time + sifs;

	int retries = 0;

	clock_gettime(CLOCK_MONOTONIC, &now);

	int ack_time_usec = pkt_duration(14, index_to_rate(0, frame->freq)) +
			sifs;

	/*
	 * To determine a frame's expiration time, we compute the
	 * number of retries we might have to make due to radio conditions
	 * or contention, and add backoff time accordingly.  To that, we
	 * add the expiration time of the previous frame in the queue.
	 */

	ac = frame_select_queue_80211(frame);
	queue = &station->queues[ac];

	/* try to "send" this frame at each of the rates in the rateset */
	send_time = 0;
	cw = queue->cw_min;

	int snr = SNR_DEFAULT;

	if (is_multicast_ether_addr(dest)) {
		deststa = NULL;
	} else {
		deststa = get_station_by_addr(ctx, dest);
		if (deststa) {
			snr = ctx->get_link_snr(ctx, station, deststa) -
				get_signal_offset_by_interference(ctx,
					station->index, deststa->index);
			snr += ctx->get_fading_signal(ctx);
		}
	}
	frame->signal = snr + NOISE_LEVEL;

	noack = frame_is_mgmt(frame) || is_multicast_ether_addr(dest);
	double choice = -3.14;

	if (use_fixed_random_value(ctx))
		choice = drand48();

	for (i = 0; i < frame->tx_rates_count && !is_acked; i++) {

		rate_idx = frame->tx_rates[i].idx;

		/* no more rates in MRR */
		if (rate_idx < 0)
			break;

		error_prob = ctx->get_error_prob(ctx, snr, rate_idx,
						 frame->freq, frame->data_len,
						 station, deststa);
		for (j = 0; j < frame->tx_rates[i].count; j++) {
			printf("-------> %d\n", frame->tx_rates_flag[i].flags);
			send_time += difs + pkt_duration(frame->data_len,
				index_to_rate(rate_idx, frame->freq));
				printf("send_time: %d\nack_time_usec: %d\n", send_time, ack_time_usec);
			retries++;

			/* skip ack/backoff/retries for noack frames */
			if (noack) {
				is_acked = true;
				break;
			}

			/* TODO TXOPs */

			/* backoff */
			if (j > 0) {
				//w_logf(ctx, LOG_INFO, "backoff\n");
				send_time += (cw * slot_time) / 2;
				cw = (cw << 1) + 1;
				if (cw > queue->cw_max)
					cw = queue->cw_max;
			}
			if (!use_fixed_random_value(ctx))
				choice = drand48();
			if (choice > error_prob) {
				is_acked = true;
				break;
			}
			send_time += ack_time_usec;
		}
	}
	if (is_acked) {
		frame->tx_rates[i-1].count = j + 1;
		for (; i < frame->tx_rates_count; i++) {
			frame->tx_rates[i].idx = -1;
			frame->tx_rates[i].count = -1;
		}
		frame->flags |= HWSIM_TX_STAT_ACK;
	}

	/*
	 * delivery time starts after any equal or higher prio frame
	 * (or now, if none).
	 */
	target = now;
	for (i = 0; i <= ac; i++) {
		list_for_each_entry(tmpsta, &ctx->stations, list) {
			tail = list_last_entry_or_null(&tmpsta->queues[i].frames,
						       struct frame, list);
			if (tail && timespec_before(&target, &tail->expires))
				target = tail->expires;
		}
		printf("target: %ld.%ld\n", target.tv_sec, target.tv_nsec);
	}

	timespec_add_usec(&target, send_time);
	//timespec_add_usec(&target, 0);

	frame->duration = 0;//send_time;
	frame->expires = now;//target;
	//frame->duration = send_time;
	//frame->expires = target;
	pthread_rwlock_wrlock(&snr_lock);
	list_add_tail(&frame->list, &queue->frames);
	pthread_rwlock_unlock(&snr_lock);
	fast_timer_rearm(ctx, frame->expires);
	send_tx_info_frame_nl(ctx, frame);
}

/*
 * Report transmit status to the kernel.
 */
int send_tx_info_frame_nl(struct wmediumd *ctx, struct frame *frame)
{
	struct nl_sock *sock = nl_listen_socket;//ctx->sock;
	struct nl_msg *msg;
	int ret;

	msg = nlmsg_alloc();
	if (!msg) {
		w_logf(ctx, LOG_ERR, "Error allocating new message MSG!\n");
		return -1;
	}

	if (genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->family_id,
			0, NLM_F_REQUEST, HWSIM_CMD_TX_INFO_FRAME,
			VERSION_NR) == NULL) {
		w_logf(ctx, LOG_ERR, "%s: genlmsg_put failed\n", __func__);
		ret = -1;
		goto out;
	}

	if (nla_put(msg, HWSIM_ATTR_ADDR_TRANSMITTER, ETH_ALEN,
		    frame->sender->hwaddr) ||
	    nla_put_u32(msg, HWSIM_ATTR_FLAGS, frame->flags) ||
	    nla_put_u32(msg, HWSIM_ATTR_SIGNAL, frame->signal) ||
	    nla_put(msg, HWSIM_ATTR_TX_INFO,
		    frame->tx_rates_count * sizeof(struct hwsim_tx_rate),
		    frame->tx_rates) ||
			nla_put(msg, HWSIM_ATTR_TX_INFO_FLAGS,
				frame->tx_rates_flag_count * sizeof( struct hwsim_tx_rate_flag),
				frame->tx_rates_flag) ||
	    nla_put_u64(msg, HWSIM_ATTR_COOKIE, frame->cookie)) {
			w_logf(ctx, LOG_ERR, "%s: Failed to fill a payload\n", __func__);
			ret = -1;
			goto out;
	}
	/*TODO: replace deprecated nl_send_auto_complete */
	ret = nl_send_auto_complete(sock, msg);
	printf("tx_info_flags: %d\n", frame->tx_rates_flag[0].flags);

	if (ret < 0) {
		w_logf(ctx, LOG_ERR, "%s: nl_send_auto failed\n", __func__);
		ret = -1;
		goto out;
	}
	ret = 0;

out:
	nlmsg_free(msg);
	return ret;
}

/*
 * Send a data frame to the kernel for reception at a specific radio.
 */
int send_cloned_frame_msg(struct wmediumd *ctx, struct station *dst,
			  u8 *data, int data_len, int rate_idx, int signal, struct frame *frame)
{
	struct nl_msg *msg;
	struct nl_sock *sock = nl_listen_socket;//ctx->sock;
	int ret;

	msg = nlmsg_alloc();
	if (!msg) {
		w_logf(ctx, LOG_ERR, "Error allocating new message MSG!\n");
		return -1;
	}

	if (genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->family_id,
			0, NLM_F_REQUEST, HWSIM_CMD_FRAME,
			VERSION_NR) == NULL) {
		w_logf(ctx, LOG_ERR, "%s: genlmsg_put failed\n", __func__);
		ret = -1;
		goto out;
	}

	if (nla_put(msg, HWSIM_ATTR_ADDR_RECEIVER, ETH_ALEN,
		    dst->hwaddr) ||
			nla_put(msg, HWSIM_ATTR_ADDR_TRANSMITTER, ETH_ALEN,
					    frame->sender->hwaddr) ||
	    nla_put(msg, HWSIM_ATTR_FRAME, data_len, data) ||
	    nla_put_u32(msg, HWSIM_ATTR_RX_RATE, rate_idx) ||
	    nla_put_u32(msg, HWSIM_ATTR_SIGNAL, signal) ||
			nla_put(msg, HWSIM_ATTR_TX_INFO,
				frame->tx_rates_count * sizeof(struct hwsim_tx_rate),
				frame->tx_rates) ||
			nla_put(msg, HWSIM_ATTR_TX_INFO_FLAGS,
				frame->tx_rates_flag_count * sizeof( struct hwsim_tx_rate_flag),
				frame->tx_rates_flag) ||
			nla_put_u64(msg, HWSIM_ATTR_COOKIE, frame->cookie)) {
			w_logf(ctx, LOG_ERR, "%s: Failed to fill a payload\n", __func__);
			ret = -1;
			goto out;
	}

	printf("tx_cloned_flags: %d\n", frame->tx_rates_flag[0].flags);

	w_logf(ctx, LOG_DEBUG, "cloned msg dest " MAC_FMT " (radio: " MAC_FMT ") len %d\n",
		   MAC_ARGS(dst->addr), MAC_ARGS(dst->hwaddr), data_len);

	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	nl_complete_msg(sock, msg);
	ret = nl_send(sock, msg);
	if (ret < 0) {
		w_logf(ctx, LOG_ERR, "%s: nl_send_auto failed\n", __func__);
		ret = -1;
		goto out;
	}
	ret = 0;

out:
	nlmsg_free(msg);
	return ret;
}

void deliver_frame(void *args)
	{
	struct wmediumd *ctx = ((struct thpool_arg*)args)->ctx;
	struct frame *frame = ((struct thpool_arg*)args)->frame;
	struct ieee80211_hdr *hdr = (void *) frame->data;
	struct station *station;
	u8 *dest = hdr->addr1;
	u8 *src = frame->sender->addr;

	if (frame->flags & HWSIM_TX_STAT_ACK) {
		/* rx the frame on the dest interface */
		list_for_each_entry(station, &ctx->stations, list) {
			if (memcmp(src, station->addr, ETH_ALEN) == 0)
				continue;

			int rate_idx;
			if (is_multicast_ether_addr(dest)) {
				int snr, signal;
				double error_prob;

				/*
				 * we may or may not receive this based on
				 * reverse link from sender -- check for
				 * each receiver.
				 */
				snr = ctx->get_link_snr(ctx, frame->sender,
							station);
				snr += ctx->get_fading_signal(ctx);
				signal = snr + NOISE_LEVEL;

				if (set_interference_duration(ctx,
					frame->sender->index, frame->duration,
					signal))
					continue;

				snr -= get_signal_offset_by_interference(ctx,
					frame->sender->index, station->index);
				rate_idx = frame->tx_rates[0].idx;
				error_prob = ctx->get_error_prob(ctx,
					(double)snr, rate_idx, frame->freq,
					frame->data_len, frame->sender,
					station);

				if (drand48() <= error_prob) {
					w_logf(ctx, LOG_INFO, "Dropped mcast from "
						   MAC_FMT " to " MAC_FMT " at receiver\n",
						   MAC_ARGS(src), MAC_ARGS(station->addr));
					continue;
				}

				send_cloned_frame_msg(ctx, station,
						      frame->data,
						      frame->data_len,
							  rate_idx, signal, frame);

			} else if (memcmp(dest, station->addr, ETH_ALEN) == 0) {
				if (set_interference_duration(ctx,
					frame->sender->index, frame->duration,
					frame->signal))
					continue;
				rate_idx = frame->tx_rates[0].idx;
				send_cloned_frame_msg(ctx, station,
						      frame->data,
						      frame->data_len,
							  rate_idx, frame->signal, frame);
			}
		}
	} else
		set_interference_duration(ctx, frame->sender->index,
					  frame->duration, frame->signal);
	/*TODO free frame - need to control that tx_info has been sent before cloned message */
	//free(frame);
}

void deliver_expired_frames_queue(struct wmediumd *ctx,
				  struct list_head *queue,
				  struct timespec *now)
{
	struct frame *frame, *tmp;
	bool expired_frame_delivered_flag = false;
	list_for_each_entry_safe(frame, tmp, queue, list) {
		if (timespec_before(&frame->expires, now)) {
			list_del(&frame->list);
			struct thpool_arg *thpool_arg_data_ptr = malloc(sizeof(thpool_arg_data));
			thpool_arg_data_ptr->ctx = ctx;
			thpool_arg_data_ptr->frame = frame;
			thpool_add_work(ctx->thpool, (void *)deliver_frame, thpool_arg_data_ptr);
			expired_frame_delivered_flag |= 1;
		} else {
			break;
		}
	}
	if (ctx->min_expires_set) ctx->min_expires_set = false;
	if (expired_frame_delivered_flag & 1) rearm_timer(ctx);
}

void deliver_expired_frames(struct wmediumd *ctx)
{
	struct timespec now, _diff;
	struct station *station;
	//struct list_head *l;
	int i, j, duration;

	clock_gettime(CLOCK_MONOTONIC, &now);
	list_for_each_entry(station, &ctx->stations, list) {
		/*int q_ct[IEEE80211_NUM_ACS] = {};
		for (i = 0; i < IEEE80211_NUM_ACS; i++) {
			list_for_each(l, &station->queues[i].frames) {
				q_ct[i]++;
			}
		}
		w_logf(ctx, LOG_DEBUG, "[" TIME_FMT "] Station " MAC_FMT
					   " BK %d BE %d VI %d VO %d\n",
			   TIME_ARGS(&now), MAC_ARGS(station->addr),
			   q_ct[IEEE80211_AC_BK], q_ct[IEEE80211_AC_BE],
			   q_ct[IEEE80211_AC_VI], q_ct[IEEE80211_AC_VO]);*/

		for (i = 0; i < IEEE80211_NUM_ACS; i++)
			deliver_expired_frames_queue(ctx, &station->queues[i].frames, &now);
	}
	w_logf(ctx, LOG_DEBUG, "\n\n");

	if (!ctx->intf)
		return;

	timespec_sub(&now, &ctx->intf_updated, &_diff);
	duration = (_diff.tv_sec * 1000000) + (_diff.tv_nsec / 1000);
	if (duration < 10000) // calc per 10 msec
		return;

	// update interference
	for (i = 0; i < ctx->num_stas; i++)
		for (j = 0; j < ctx->num_stas; j++) {
			if (i == j)
				continue;
			// probability is used for next calc
			ctx->intf[i * ctx->num_stas + j].prob_col =
				ctx->intf[i * ctx->num_stas + j].duration /
				(double)duration;
			ctx->intf[i * ctx->num_stas + j].duration = 0;
		}

	clock_gettime(CLOCK_MONOTONIC, &ctx->intf_updated);
}

static
int nl_err_cb(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(&nlerr->msg);
	struct wmediumd *ctx = arg;

	w_flogf(ctx, LOG_ERR, stderr, "nl: cmd %d, seq %d: %s\n", gnlh->cmd,
			nlerr->msg.nlmsg_seq, strerror(abs(nlerr->error)));

	return NL_SKIP;
}


static void threaded_process_messages_cb(struct wmediumd *ctx, struct nl_msg *msg) {
	struct nlattr *attrs[HWSIM_ATTR_MAX+1];
	/* netlink header */
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	/* generic netlink header*/
	struct genlmsghdr *gnlh = nlmsg_data(nlh);

	struct station *sender;
	struct frame *frame;
	struct ieee80211_hdr *hdr;
	u8 *src;
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	if (gnlh->cmd == HWSIM_CMD_FRAME) {
		/* we get the attributes*/
		genlmsg_parse(nlh, 0, attrs, HWSIM_ATTR_MAX, NULL);
		if (attrs[HWSIM_ATTR_ADDR_TRANSMITTER]) {
			u8 *hwaddr = (u8 *)nla_data(attrs[HWSIM_ATTR_ADDR_TRANSMITTER]);

			unsigned int data_len =
				nla_len(attrs[HWSIM_ATTR_FRAME]);
			char *data = (char *)nla_data(attrs[HWSIM_ATTR_FRAME]);
			unsigned int flags =
				nla_get_u32(attrs[HWSIM_ATTR_FLAGS]);
			unsigned int tx_rates_len =
				nla_len(attrs[HWSIM_ATTR_TX_INFO]);
			struct hwsim_tx_rate *tx_rates =
				(struct hwsim_tx_rate *)
				nla_data(attrs[HWSIM_ATTR_TX_INFO]);

			unsigned int tx_rates_flags_len =
				nla_len(attrs[HWSIM_ATTR_TX_INFO_FLAGS]);
			struct hwsim_tx_rate_flag *tx_rates_flag =
				(struct hwsim_tx_rate_flag *)
				nla_data(attrs[HWSIM_ATTR_TX_INFO_FLAGS]);

			u64 cookie = nla_get_u64(attrs[HWSIM_ATTR_COOKIE]);
			u32 freq;
			freq = attrs[HWSIM_ATTR_FREQ] ?
					nla_get_u32(attrs[HWSIM_ATTR_FREQ]) : 2412;

			hdr = (struct ieee80211_hdr *)data;
			src = hdr->addr2;

			if (data_len < 6 + 6 + 4)
				return;

			sender = get_station_by_addr(ctx, src);
			if (!sender) {
				w_flogf(ctx, LOG_ERR, stderr, "Unable to find sender station " MAC_FMT "\n", MAC_ARGS(src));
				return;
			}
			memcpy(sender->hwaddr, hwaddr, ETH_ALEN);

			frame = malloc(sizeof(*frame) + data_len);
			if (!frame)
				return;

			memcpy(frame->data, data, data_len);
			frame->data_len = data_len;
			frame->flags = flags;
			frame->cookie = cookie;
			frame->freq = freq;
			frame->sender = sender;
			sender->freq = freq;
			frame->tx_rates_count =
				tx_rates_len / sizeof(struct hwsim_tx_rate);
			memcpy(frame->tx_rates, tx_rates,
						 min(tx_rates_len, sizeof(frame->tx_rates)));
			frame->tx_rates_flag_count =
				tx_rates_flags_len / sizeof(struct hwsim_tx_rate_flag);
			memcpy(frame->tx_rates_flag, tx_rates_flag,
						 min(tx_rates_flags_len, sizeof(frame->tx_rates_flag)));
			printf("rcv_flags: %d\n", frame->tx_rates_flag[0].flags);

			struct thpool_arg *thpool_arg_data_ptr = malloc(sizeof(thpool_arg_data));
			thpool_arg_data_ptr->ctx = ctx;
			thpool_arg_data_ptr->station = sender;
			thpool_arg_data_ptr->frame = frame;
			thpool_add_work(ctx->thpool, (void *)queue_frame, thpool_arg_data_ptr);
		}
	}
}

/*
 * Handle events from the kernel.  Process CMD_FRAME events and queue them
 * for later delivery with the scheduler.
 */
static int process_messages_cb(struct nl_msg *msg, void *arg)
{
	threaded_process_messages_cb(arg, msg);
	return 0;
}

/*
 * Register with the kernel to start receiving new frames.
 */
int send_register_msg(struct wmediumd *ctx)
{
	struct nl_sock *sock = nl_listen_socket;//ctx->sock;
	struct nl_msg *msg;
	int ret;

	msg = nlmsg_alloc();
	if (!msg) {
		w_logf(ctx, LOG_ERR, "Error allocating new message MSG!\n");
		return -1;
	}

	if (genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->family_id,
			0, NLM_F_REQUEST, HWSIM_CMD_REGISTER,
			VERSION_NR) == NULL) {
		w_logf(ctx, LOG_ERR, "%s: genlmsg_put failed\n", __func__);
		ret = -1;
		goto out;
	}

	nl_complete_msg(sock, msg);
	ret = nl_send(sock, msg);
	if (ret < 0) {
		w_logf(ctx, LOG_ERR, "%s: nl_send_auto failed\n", __func__);
		ret = -1;
		goto out;
	}
	ret = 0;

out:
	nlmsg_free(msg);
	return ret;
}

static void sock_event_cb(int fd, short what, void *data)
{
	nl_recvmsgs_default(nl_listen_socket);//ctx->sock);
}

/*
 * Setup netlink socket and callbacks.
 */
static int init_netlink(struct wmediumd *ctx)
{
	struct nl_sock *sock;
	int ret;

	ctx->cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!ctx->cb) {
		w_logf(ctx, LOG_ERR, "Error allocating netlink callbacks\n");
		return -1;
	}

	sock = nl_socket_alloc_cb(ctx->cb);
	if (!sock) {
		w_logf(ctx, LOG_ERR, "Error allocating netlink socket\n");
		return -1;
	}

	nl_listen_socket = sock;

	ret = genl_connect(sock);
	if (ret < 0) {
		w_logf(ctx, LOG_ERR, "Error connecting netlink socket ret=%d\n", ret);
		return -1;
	}

	ctx->family_id = genl_ctrl_resolve(sock, "MAC80211_HWSIM");
	if (ctx->family_id < 0) {
		w_logf(ctx, LOG_ERR, "Family MAC80211_HWSIM not registered\n");
		return -1;
	}

	ctx->min_expires_set = false;

	nl_cb_set(ctx->cb, NL_CB_MSG_IN, NL_CB_CUSTOM, process_messages_cb, ctx);
	nl_cb_err(ctx->cb, NL_CB_CUSTOM, nl_err_cb, ctx);

	return 0;
}

/*
 *	Print the CLI help
 */
void print_help(int exval)
{
	printf("wmediumd v%s - a wireless medium simulator\n", VERSION_STR);
	printf("wmediumd [-h] [-V] [-s] [-l LOG_LVL] [-x FILE] -c FILE\n\n");

	printf("  -h              print this help and exit\n");
	printf("  -V              print version and exit\n\n");

	printf("  -l LOG_LVL      set the logging level\n");
	printf("                  LOG_LVL: RFC 5424 severity, values 0 - 7\n");
	printf("                  >= 3: errors are logged\n");
	printf("                  >= 5: startup msgs are logged\n");
	printf("                  >= 6: dropped packets are logged (default)\n");
	printf("                  == 7: all packets will be logged\n");
	printf("  -c FILE         set input config file\n");
	printf("  -x FILE         set input PER file\n");
	printf("  -s              start the server on a socket\n");
	printf("  -d              use the dynamic complex mode\n");
	printf("                  (server only with matrices for each connection)\n");

	exit(exval);
}

static void timer_cb(int fd, short what, void *data)
{
	struct wmediumd *ctx = data;
	pthread_rwlock_wrlock(&snr_lock);
	memset(expires, 0, sizeof(*expires));
	timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, expires,
			NULL);
	ctx->move_stations(ctx);
	deliver_expired_frames(ctx);
	pthread_rwlock_unlock(&snr_lock);
}

static void on_listen_event(int fd, short what, void *wctx) {
    UNUSED(fd);
    UNUSED(what);
    struct accept_context *actx = malloc(sizeof(struct accept_context));
    if (!actx) return;
    actx->wctx = wctx;
    actx->server_socket = fd;
    actx->thread = malloc(sizeof(pthread_t));
    if (!actx->thread) {
        free(actx);
        return;
    }
    actx->client_socket = accept_connection(actx->server_socket);
    if (actx->client_socket >= 0)
				thpool_add_work(((struct wmediumd*)wctx)->thpool, (void*)handle_accepted_connection, actx);
}


void main_loop_thread(void *args) {
	struct wmediumd *ctx = args;
	bool start_server = true;

	/* init libevent */
	event_init();

	/* init netlink */
	if (init_netlink(ctx) < 0)
		return;

	ev_cmd = event_new(cmd_event_base, nl_socket_get_fd(nl_listen_socket), EV_READ | EV_PERSIST, sock_event_cb, ctx);
	event_add(ev_cmd, NULL);

	/* setup timers */
	timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
	expires = malloc(sizeof(struct itimerspec));
	clock_gettime(CLOCK_MONOTONIC, &(ctx->intf_updated));
	clock_gettime(CLOCK_MONOTONIC, &(ctx->next_move));
	ctx->next_move.tv_sec += MOVE_INTERVAL;
	ev_timer = event_new(timer_event_base, timer_fd, EV_READ | EV_PERSIST, timer_cb, ctx);
	event_add(ev_timer, NULL);

	/* register for new frames */
	if (send_register_msg(ctx) == 0) {
		w_logf(ctx, LOG_NOTICE, "REGISTER SENT!\n");
	}

	if (start_server == true) {
		listen_soc = create_listen_socket(ctx);
		if (listen_soc < 0) {
				goto dispatch;
		}
		evutil_make_socket_nonblocking(listen_soc);
		accept_event = event_new(server_event_base, listen_soc, EV_READ | EV_PERSIST, on_listen_event, ctx);
		event_add(accept_event, NULL);
	}

	dispatch:
	/* enter libevent main loop */
	event_dispatch();

	if (start_server == true)
		stop_wserver();
}

int main(int argc, char *argv[])
{
	int opt;
	struct wmediumd ctx;
	char *config_file = NULL;
	char *per_file = NULL;

	setvbuf(stdout, NULL, _IOLBF, BUFSIZ);

	if (argc == 1) {
		fprintf(stderr, "This program needs arguments....\n\n");
		print_help(EXIT_FAILURE);
	}

	ctx.log_lvl = 6;
	unsigned long int parse_log_lvl;
	char* parse_end_token;
	bool start_server = false;
	bool full_dynamic = false;

	while ((opt = getopt(argc, argv, "hVc:l:x:sd")) != -1) {
		switch (opt) {
		case 'h':
			print_help(EXIT_SUCCESS);
			break;
		case 'V':
			printf("wmediumd v%s - a wireless medium simulator "
			       "for mac80211_hwsim\n", VERSION_STR);
			exit(EXIT_SUCCESS);
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'x':
			printf("Input packet error rate file: %s\n", optarg);
			per_file = optarg;
			break;
		case ':':
			printf("wmediumd: Error - Option `%c' "
			       "needs a value\n\n", optopt);
			print_help(EXIT_FAILURE);
			break;
		case 'l':
			parse_log_lvl = strtoul(optarg, &parse_end_token, 10);
			if ((parse_log_lvl == ULONG_MAX && errno == ERANGE) ||
			     optarg == parse_end_token || parse_log_lvl > 7) {
				printf("wmediumd: Error - Invalid RFC 5424 severity level: "
							   "%s\n\n", optarg);
				print_help(EXIT_FAILURE);
			}
			ctx.log_lvl = parse_log_lvl;
			break;
		case 'd':
			full_dynamic = true;
			break;
		case 's':
			start_server = true;
			break;
		case '?':
			printf("wmediumd: Error - No such option: "
			       "`%c'\n\n", optopt);
			print_help(EXIT_FAILURE);
			break;
		}

	}

	if (optind < argc)
		print_help(EXIT_FAILURE);

	if (full_dynamic) {
		if (config_file) {
			printf("%s: cannot use dynamic complex mode with config file\n", argv[0]);
			print_help(EXIT_FAILURE);
		}

		if (!start_server) {
			printf("%s: dynamic complex mode requires the server option\n", argv[0]);
			print_help(EXIT_FAILURE);
		}

		w_logf(&ctx, LOG_NOTICE, "Using dynamic complex mode instead of config file\n");
	} else {
		if (!config_file) {
			printf("%s: config file must be supplied\n", argv[0]);
			print_help(EXIT_FAILURE);
		}

		w_logf(&ctx, LOG_NOTICE, "Input configuration file: %s\n", config_file);
	}
	INIT_LIST_HEAD(&ctx.stations);
	if (load_config(&ctx, config_file, per_file, full_dynamic))
		return EXIT_FAILURE;

	ctx.thpool = thpool_init(10);

	thpool_add_work(ctx.thpool, (void *)main_loop_thread, &ctx);
	thpool_wait(ctx.thpool);
	free(nl_listen_socket);
	free(ctx.cb);
	free(ctx.intf);
	free(ctx.per_matrix);

	return EXIT_SUCCESS;
}
