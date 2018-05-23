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

#ifndef WMEDIUMD_H_
#define WMEDIUMD_H_

#define HWSIM_TX_CTL_REQ_TX_STATUS	1
#define HWSIM_TX_CTL_NO_ACK		(1 << 1)
#define HWSIM_TX_STAT_ACK		(1 << 2)

#define HWSIM_CMD_REGISTER 1
#define HWSIM_CMD_FRAME 2
#define HWSIM_CMD_TX_INFO_FRAME 3

#define BIT(nr)	(1UL << (nr))

/**
 * enum hwsim_attrs - hwsim netlink attributes
 *
 * @HWSIM_ATTR_UNSPEC: unspecified attribute to catch errors
 *
 * @HWSIM_ATTR_ADDR_RECEIVER: MAC address of the radio device that
 *	the frame is broadcasted to
 * @HWSIM_ATTR_ADDR_TRANSMITTER: MAC address of the radio device that
 *	the frame was broadcasted from
 * @HWSIM_ATTR_FRAME: Data array
 * @HWSIM_ATTR_FLAGS: mac80211 transmission flags, used to process
	properly the frame at user space
 * @HWSIM_ATTR_RX_RATE: estimated rx rate index for this frame at user
	space
 * @HWSIM_ATTR_SIGNAL: estimated RX signal for this frame at user
	space
 * @HWSIM_ATTR_TX_INFO: ieee80211_tx_rate array
 * @HWSIM_ATTR_COOKIE: sk_buff cookie to identify the frame
 * @HWSIM_ATTR_CHANNELS: u32 attribute used with the %HWSIM_CMD_CREATE_RADIO
 *	command giving the number of channels supported by the new radio
 * @HWSIM_ATTR_RADIO_ID: u32 attribute used with %HWSIM_CMD_DESTROY_RADIO
 *	only to destroy a radio
 * @HWSIM_ATTR_REG_HINT_ALPHA2: alpha2 for regulatoro driver hint
 *	(nla string, length 2)
 * @HWSIM_ATTR_REG_CUSTOM_REG: custom regulatory domain index (u32 attribute)
 * @HWSIM_ATTR_REG_STRICT_REG: request REGULATORY_STRICT_REG (flag attribute)
 * @HWSIM_ATTR_SUPPORT_P2P_DEVICE: support P2P Device virtual interface (flag)
 * @HWSIM_ATTR_USE_CHANCTX: used with the %HWSIM_CMD_CREATE_RADIO
 *	command to force use of channel contexts even when only a
 *	single channel is supported
 * @HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE: used with the %HWSIM_CMD_CREATE_RADIO
 *	command to force radio removal when process that created the radio dies
 * @HWSIM_ATTR_RADIO_NAME: Name of radio, e.g. phy666
 * @HWSIM_ATTR_NO_VIF:  Do not create vif (wlanX) when creating radio.
 * @HWSIM_ATTR_FREQ: Frequency at which packet is transmitted or received.
 * @__HWSIM_ATTR_MAX: enum limit
 */
enum {
	HWSIM_ATTR_UNSPEC,
	HWSIM_ATTR_ADDR_RECEIVER,
	HWSIM_ATTR_ADDR_TRANSMITTER,
	HWSIM_ATTR_FRAME,
	HWSIM_ATTR_FLAGS,
	HWSIM_ATTR_RX_RATE,
	HWSIM_ATTR_SIGNAL,
	HWSIM_ATTR_TX_INFO,
	HWSIM_ATTR_COOKIE,
	HWSIM_ATTR_CHANNELS,
	HWSIM_ATTR_RADIO_ID,
	HWSIM_ATTR_REG_HINT_ALPHA2,
	HWSIM_ATTR_REG_CUSTOM_REG,
	HWSIM_ATTR_REG_STRICT_REG,
	HWSIM_ATTR_SUPPORT_P2P_DEVICE,
	HWSIM_ATTR_USE_CHANCTX,
	HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
	HWSIM_ATTR_RADIO_NAME,
	HWSIM_ATTR_NO_VIF,
	HWSIM_ATTR_FREQ,
	HWSIM_ATTR_PAD,
	HWSIM_ATTR_TX_INFO_FLAGS,
	__HWSIM_ATTR_MAX,
};
#define HWSIM_ATTR_MAX (__HWSIM_ATTR_MAX - 1)




/**
 * enum hwsim_tx_rate_flags - per-rate flags set by the rate control algorithm.
 *	Inspired by structure mac80211_rate_control_flags. New flags may be
 *	appended, but old flags not deleted, to keep compatibility for
 *	userspace.
 *
 * These flags are set by the Rate control algorithm for each rate during tx,
 * in the @flags member of struct ieee80211_tx_rate.
 *
 * @MAC80211_HWSIM_TX_RC_USE_RTS_CTS: Use RTS/CTS exchange for this rate.
 * @MAC80211_HWSIM_TX_RC_USE_CTS_PROTECT: CTS-to-self protection is required.
 *	This is set if the current BSS requires ERP protection.
 * @MAC80211_HWSIM_TX_RC_USE_SHORT_PREAMBLE: Use short preamble.
 * @MAC80211_HWSIM_TX_RC_MCS: HT rate.
 * @MAC80211_HWSIM_TX_RC_VHT_MCS: VHT MCS rate, in this case the idx field is
 *	split into a higher 4 bits (Nss) and lower 4 bits (MCS number)
 * @MAC80211_HWSIM_TX_RC_GREEN_FIELD: Indicates whether this rate should be used
 *	in Greenfield mode.
 * @MAC80211_HWSIM_TX_RC_40_MHZ_WIDTH: Indicates if the Channel Width should be
 *	40 MHz.
 * @MAC80211_HWSIM_TX_RC_80_MHZ_WIDTH: Indicates 80 MHz transmission
 * @MAC80211_HWSIM_TX_RC_160_MHZ_WIDTH: Indicates 160 MHz transmission
 *	(80+80 isn't supported yet)
 * @MAC80211_HWSIM_TX_RC_DUP_DATA: The frame should be transmitted on both of
 *	the adjacent 20 MHz channels, if the current channel type is
 *	NL80211_CHAN_HT40MINUS or NL80211_CHAN_HT40PLUS.
 * @MAC80211_HWSIM_TX_RC_SHORT_GI: Short Guard interval should be used for this
 *	rate.
 */
enum hwsim_tx_rate_flags {
	MAC80211_HWSIM_TX_RC_USE_RTS_CTS		= BIT(0),
	MAC80211_HWSIM_TX_RC_USE_CTS_PROTECT		= BIT(1),
	MAC80211_HWSIM_TX_RC_USE_SHORT_PREAMBLE	= BIT(2),

	/* rate index is an HT/VHT MCS instead of an index */
	MAC80211_HWSIM_TX_RC_MCS			= BIT(3),
	MAC80211_HWSIM_TX_RC_GREEN_FIELD		= BIT(4),
	MAC80211_HWSIM_TX_RC_40_MHZ_WIDTH		= BIT(5),
	MAC80211_HWSIM_TX_RC_DUP_DATA		= BIT(6),
	MAC80211_HWSIM_TX_RC_SHORT_GI		= BIT(7),
	MAC80211_HWSIM_TX_RC_VHT_MCS			= BIT(8),
	MAC80211_HWSIM_TX_RC_80_MHZ_WIDTH		= BIT(9),
	MAC80211_HWSIM_TX_RC_160_MHZ_WIDTH		= BIT(10),
};



#define VERSION_NR 1

#define SNR_DEFAULT 30
#define GAIN_DEFAULT 5
#define GAUSS_RANDOM_DEFAULT 1
#define HEIGHT_DEFAULT 1
#define AP_DEFAULT 2

#include <stdint.h>
#include <stdbool.h>
#include <syslog.h>
#include <stdio.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <pthread.h>

#include "list.h"
#include "ieee80211.h"
#include "thpool.h"

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define TIME_FMT "%lld.%06lld"
#define TIME_ARGS(a) ((unsigned long long)(a)->tv_sec), ((unsigned long long)(a)->tv_nsec/1000)

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARGS(a) a[0],a[1],a[2],a[3],a[4],a[5]

#ifndef min
#define min(x,y) ((x) < (y) ? (x) : (y))
#endif

#define NOISE_LEVEL	(-91)
#define CCA_THRESHOLD	(-90)

/**
 * struct hwsim_tx_rate - rate selection/status
 *
 * @idx: rate index to attempt to send with
 * @count: number of tries in this rate before going to the next rate
 *
 * A value of -1 for @idx indicates an invalid rate and, if used
 * in an array of retry rates, that no more rates should be tried.
 *
 * When used for transmit status reporting, the driver should
 * always report the rate and number of retries used.
 *
 */
struct hwsim_tx_rate_flag {
	int8_t idx;
	uint16_t flags;
};


struct wqueue {
	struct list_head frames;
	int cw_min;
	int cw_max;
};

struct station {
	int index;
	u8 addr[ETH_ALEN];		/* virtual interface mac address */
	u8 hwaddr[ETH_ALEN];		/* hardware address of hwsim radio */
	double x, y, z;			/* position of the station [m] */
	double dir_x, dir_y;		/* direction of the station [meter per MOVE_INTERVAL] */
	int tx_power;			/* transmission power [dBm] */
	int gain;			/* Antenna Gain [dBm] */
	//int height;			/* Antenna Height [m] */
	int gRandom;     /* Gaussian Random */
	int isap; 		/* verify whether the node is ap */
	double freq;			/* frequency [Mhz] */
	struct wqueue queues[IEEE80211_NUM_ACS];
	struct list_head list;
};

struct wmediumd {
	int timerfd;

	//struct nl_sock *sock;

	int num_stas;
	struct list_head stations;
	struct station **sta_array;
	int *snr_matrix;
	double *error_prob_matrix;
	double **station_err_matrix;
	struct intf_info *intf;
	struct timespec intf_updated;
#define MOVE_INTERVAL	(3) /* station movement interval [sec] */
	struct timespec next_move;
	void *path_loss_param;
	float *per_matrix;
	int per_matrix_row_num;
	int per_matrix_signal_min;
	int fading_coefficient;
	int noise_threshold;


	struct nl_cb *cb;
	int family_id;

	int (*get_link_snr)(struct wmediumd *, struct station *,
			    struct station *);
	double (*get_error_prob)(struct wmediumd *, double, unsigned int, u32,
				 int, struct station *, struct station *);
	int (*calc_path_loss)(void *, struct station *,
			      struct station *);
	void (*move_stations)(struct wmediumd *);
	int (*get_fading_signal)(struct wmediumd *);

	u8 log_lvl;

	//testing
	struct timespec min_expires;	/* frame delivery (absolute) */
	bool min_expires_set;
	threadpool thpool;

	//struct nl_msg *msg;
};

typedef struct thpool_arg {
	void *ctx;
	//struct nl_msg* msg;
	void *station;
	void *frame;
} thpool_arg_data, *thpool_arg_data_ptr;

struct hwsim_tx_rate {
	signed char idx;
	unsigned char count;
};

struct frame {
	struct list_head list;		/* frame queue list */
	struct timespec expires;	/* frame delivery (absolute) */
	bool acked;
	u64 cookie;
	u32 freq;
	int flags;
	int signal;
	int duration;
	int tx_rates_count;
	int tx_rates_flag_count;
	struct station *sender;
	struct hwsim_tx_rate tx_rates[IEEE80211_TX_MAX_RATES];
	struct hwsim_tx_rate_flag tx_rates_flag[IEEE80211_TX_MAX_RATES];
	size_t data_len;
	u8 data[0];			/* frame contents */
};

struct log_distance_model_param {
	double path_loss_exponent;
	double Xg;
};

struct itu_model_param {
	int nFLOORS;
	int lF;
	int pL;
};

struct log_normal_shadowing_model_param {
	int sL;
	double path_loss_exponent;
};

struct free_space_model_param {
	int sL;
};

struct two_ray_ground_model_param {
	int sL;
};

struct intf_info {
	int signal;
	int duration;
	double prob_col;
};

unsigned int tx_info_frame[1000];

void station_init_queues(struct station *station);
double get_error_prob_from_snr(double snr, unsigned int rate_idx, u32 freq,
			       int frame_len);
bool timespec_before(struct timespec *t1, struct timespec *t2);
int set_default_per(struct wmediumd *ctx);
int read_per_file(struct wmediumd *ctx, const char *file_name);
int w_logf(struct wmediumd *ctx, u8 level, const char *format, ...);
int w_flogf(struct wmediumd *ctx, u8 level, FILE *stream, const char *format, ...);
int index_to_rate(size_t index, u32 freq);
int send_tx_info_frame_nl(struct wmediumd *ctx, struct frame *frame);

#endif /* WMEDIUMD_H_ */
