/* BBR (Bottleneck Bandwidth and RTT) congestion control
 *
 * BBR is a model-based congestion control algorithm that aims for low queues,
 * low loss, and (bounded) Reno/CUBIC coexistence. To maintain a model of the
 * network path, it uses measurements of bandwidth and RTT, as well as (if they
 * occur) packet loss and/or shallow-threshold ECN signals. Note that although
 * it can use ECN or loss signals explicitly, it does not require either; it
 * can bound its in-flight data based on its estimate of the BDP.
 *
 * The model has both higher and lower bounds for the operating range:
 *   lo: bw_lo, inflight_lo: conservative short-term lower bound
 *   hi: bw_hi, inflight_hi: robust long-term upper bound
 * The bandwidth-probing time scale is (a) extended dynamically based on
 * estimated BDP to improve coexistence with Reno/CUBIC; (b) bounded by
 * an interactive wall-clock time-scale to be more scalable and responsive
 * than Reno and CUBIC.
 *
 * Here is a state transition diagram for BBR:
 *
 *             |
 *             V
 *    +---> STARTUP  ----+
 *    |        |         |
 *    |        V         |
 *    |      DRAIN   ----+
 *    |        |         |
 *    |        V         |
 *    +---> PROBE_BW ----+
 *    |      ^    |      |
 *    |      |    |      |
 *    |      +----+      |
 *    |                  |
 *    +---- PROBE_RTT <--+
 *
 * A BBR flow starts in STARTUP, and ramps up its sending rate quickly.
 * When it estimates the pipe is full, it enters DRAIN to drain the queue.
 * In steady state a BBR flow only uses PROBE_BW and PROBE_RTT.
 * A long-lived BBR flow spends the vast majority of its time remaining
 * (repeatedly) in PROBE_BW, fully probing and utilizing the pipe's bandwidth
 * in a fair manner, with a small, bounded queue. *If* a flow has been
 * continuously sending for the entire min_rtt window, and hasn't seen an RTT
 * sample that matches or decreases its min_rtt estimate for 10 seconds, then
 * it briefly enters PROBE_RTT to cut inflight to a minimum value to re-probe
 * the path's two-way propagation delay (min_rtt). When exiting PROBE_RTT, if
 * we estimated that we reached the full bw of the pipe then we enter PROBE_BW;
 * otherwise we enter STARTUP to try to fill the pipe.
 *
 * BBR is described in detail in:
 *   "BBR: Congestion-Based Congestion Control",
 *   Neal Cardwell, Yuchung Cheng, C. Stephen Gunn, Soheil Hassas Yeganeh,
 *   Van Jacobson. ACM Queue, Vol. 14 No. 5, September-October 2016.
 *
 */
#ifndef USER_BBR_H
#define USER_BBR_H

#include "netinet/sctp_callout.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
#define USER_BBR_BW_SCALE 24
#define USER_BBR_BW_UNIT (1U << USER_BBR_BW_SCALE)

#define USER_BBR_SCALE 8 /* scaling factor for fractions in BBR (e.g. gains) */
#define USER_BBR_UNIT (1U << USER_BBR_SCALE)

/* ProbeRTT 维持低速进入时间 */
#define USER_BBR_PROBE_RTT_MODE_MS 200

/* min_rtt window（秒） */
#define USER_BBR_MIN_RTT_WIN_SEC 10

/* probe_rtt 触发间隔（毫秒） */
#define USER_BBR_PROBE_RTT_WIN_MS 5000

/* cwnd 最小包数（以 packets 为单位, mss)*/
#define USER_BBR_CWND_MIN_TARGET_PKTS 4

/* pacing margin（百分比） */
#define USER_BBR_PACING_MARGIN_PERCENT 1

/* BBRv3 pacing gains（整数化并按 USER_BBR_SCALE 缩放） */
#define USER_BBR_PACING_GAIN_UP (USER_BBR_UNIT * 5 / 4)      /* 1.25 */
#define USER_BBR_PACING_GAIN_DOWN (USER_BBR_UNIT * 75 / 100) /* 0.75 */
#define USER_BBR_PACING_GAIN_CRUISE (USER_BBR_UNIT)          /* 1.00 */
#define USER_BBR_PACING_GAIN_REFILL (USER_BBR_UNIT)          /* 1.00 */

/* Startup full_bw 的增长门限和检测轮数 */
#define USER_BBR_FULL_BW_THRESH (USER_BBR_UNIT * 5 / 4) /* >=1.25× 才算新带宽 */
#define USER_BBR_FULL_BW_CNT 3                          /* 连续 3 轮不增长则结束 STARTUP */

/* Loss β: inflight_lo 和 bw_lo 的乘法衰减因子 */
#define USER_BBR_BETA (USER_BBR_UNIT * 30 / 100) /* 0.30 */


typedef enum {
	USER_BBR_MODE_STARTUP = 0,
	USER_BBR_MODE_DRAIN,
	USER_BBR_MODE_PROBE_BW,
	USER_BBR_MODE_PROBE_RTT,
} user_bbr_mode_t;

typedef enum {
	USER_BBR_PHASE_PROBE_UP = 0,
	USER_BBR_PHASE_PROBE_DOWN,
	USER_BBR_PHASE_PROBE_CRUISE,
	USER_BBR_PHASE_PROBE_REFILL,
} user_bbr_probe_phase_t;

/* -----------------------------------------------------
 *  rate_sample: constructed when ACK is received and passed to BBR
 * -----------------------------------------------------
 *
 *  Note: `round_start` is not filled by the caller,
 *        it is set by BBR internally in on_ack.
 *
 *  Callers only need to ensure that the fields correspond to the status of their protocol stack:
 *    delivered: the number of bytes ACKed in this ack
 *    delivered_delta: the delta delivered bytes since this packet send
 *    interval_us: the time window for this rate sample 
 *    rtt_us: RTT (microseconds), or -1 if no RTT
 *    lost: the number of lost packets in this sample (byte-based, not strictly required but fill in the number of packets if possible)
 *    tx_in_flight_bytes: the number of in-flight bytes when this ACK arrives
 *    is_app_limited: whether it is app-limited
 *    delivered_ce: ECN CE marking bytes
 *    is_acking_tlp_retrans_seq: whether it is an ACK for a TLP retransmission sequence
 *    acked_sacked: the number of bytes ACKED or SACKED
 *    prior_delivered_bytes: the cumulative delivered bytes at the start of this rate sample
 *
 */
struct user_bbr_rate_sample {
	uint64_t delivered; 		
	uint64_t delivered_delta; 
	int64_t interval_us;   	 // delta time
	int32_t rtt_us;

	int64_t tx_in_flight_bytes;
	bool is_app_limited;

	int32_t acked_sacked;

	uint64_t prior_delivered_bytes;  // cumulative delivered bytes at this sample sent time 

	/* BBR internal used：round_start detection */
	bool round_start;
};

/* -------------------------
 *   Opaque BBR instance
 * ------------------------- */


/* bbr algorithm structure */
struct user_bbr {
	/* config */
	uint32_t mss_bytes;
	uint32_t init_cwnd_bytes;

	/* outputs */
	uint32_t snd_cwnd_bytes;
	uint64_t pacing_rate_bps;

	/* runtime bookkeeping */
	uint64_t bytes_in_flight; /* maintained by on_packet_sent/on_ack/on_loss */

	uint64_t next_rtt_delivered; /* delivered value that indicates next round start */
	bool round_start;            /* last ACK triggered round_start */

	/* rate/window samples */
	uint32_t bw_hi[2];  /* windowed max (scaled: packets/usec << BW_SCALE) */
	uint32_t bw_lo;     /* lower bound scaled */
	uint32_t bw_latest; /* latest sample scaled */

	/* inflight bounds (bytes) */
	uint32_t inflight_hi_bytes;
	uint32_t inflight_lo_bytes;
	uint32_t inflight_latest_bytes; /* latest delivered bytes sample */

	/* pacing control at send*/
	uint64_t next_send_time_us;

	/* start-up detection */
	uint32_t full_bw; /* scaled bw (same units as bw_hi) */
	uint8_t full_bw_cnt;
	bool full_bw_reached;

	/* RTT/probe RTT */
	uint32_t min_rtt_us;
	uint64_t min_rtt_stamp_us;
	uint32_t probe_rtt_min_us;
	uint64_t probe_rtt_min_stamp_us;
	uint64_t probe_rtt_done_time_us;
	bool probe_rtt_round_done;
	user_bbr_mode_t prior_mode; /* mode before Probe RTT */
	uint32_t prior_snd_cwnd_bytes; /* cwnd before Probe RTT */

	/* mode and probe phase */
	user_bbr_mode_t mode;
	user_bbr_probe_phase_t cycle_idx;
	uint64_t cycle_start_time_us;

	/* track rounds used by PROBE_BW cycle transitions */
	uint8_t rounds_since_probe;

	/* pacing/cwnd gains (scaled by USER_BBR_UNIT) */
	uint32_t pacing_gain;
	uint32_t cwnd_gain;

	/* misc */
	bool initialized;
	bool try_fast_path;
	bool idle_restart;

	/* ack aggregation */
	uint32_t extra_acked_bytes[2];
	uint8_t extra_acked_win_idx;
	uint8_t extra_acked_win_rtts;

	/* app limited flag*/
	bool app_limited; 		  
	uint32_t app_limited_until; /* threshold that exit app_limited mode */ 

	/* ECN (not implemented) */
	// bool ecn_eligible;
	// uint32_t ecn_alpha; /* scaled by USER_BBR_UNIT */
	// uint64_t alpha_last_delivered_bytes;
	// uint64_t alpha_last_delivered_ce_bytes;

	/* bbr timers */
	sctp_os_timer_t probe_rtt_timer; // PROBE_RTT timer
	uint32_t timer_ticks; // current tick count of timer 

	uint64_t delivered_bytes;   /* accumulated delivered total bytes */
};



struct user_bbr* user_bbr_create(uint32_t mss_bytes, uint32_t init_cwnd_bytes, uint64_t now_us);

void user_bbr_destroy(struct user_bbr *bbr);

/* Send event: must be called once per packet sent (update inflight) */
void user_bbr_on_packet_sent(struct user_bbr *bbr, uint32_t bytes);

/* ACK event: rate_sample must be filled */
void user_bbr_on_ack(struct user_bbr *bbr, const struct user_bbr_rate_sample *rs, uint64_t now_us);

/* Loss event: lost_bytes must be consistent with the protocol stack */
// NOTE: not used
void user_bbr_on_loss(struct user_bbr *bbr, uint32_t lost_bytes, uint64_t now_us);

/* Query the current BBR output pacing rate (bytes/sec) */
uint64_t user_bbr_get_pacing_rate_bps(const struct user_bbr *bbr);

/* Query the current BBR output cwnd (bytes) */
uint32_t user_bbr_get_cwnd_bytes(const struct user_bbr *bbr);

/* Timer: called every 10ms (ProbeRTT timeout correction) */
void user_bbr_on_timer(struct user_bbr *bbr, uint64_t now_us);

/* Debug */
void user_bbr_debug_dump(const struct user_bbr *bbr, char *buf, size_t buflen);
void user_bbr_debug_dump_with_timestamp(const struct user_bbr *bbr);

/* Helper Functions*/
uint64_t user_bbr_now_usec(void);
uint32_t user_bbr_bdp_bytes(const struct user_bbr *bbr, uint32_t bw_scaled,
                              uint32_t gain_scaled);

#endif /* USER_BBR_H */
