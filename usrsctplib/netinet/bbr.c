/* user_bbr.c
 *
 * User-space BBR v3 core logic (a minimal implementation).
 * Works with the public API declared in user_bbr.h
 *
 * Notes:
 *  - This implementation focuses on correctness of the control logic,
 *    not on hyper-optimized micro-optimizations.
 *  - The SCTP stack  MUST at least:
 *      * call user_bbr_on_packet_sent(...) when it actually sends bytes
 *      * build a proper user_bbr_rate_sample for user_bbr_on_ack(...)
 *        including .prior_delivered_bytes and .tx_in_flight_bytes
 *      * (optionally)call user_bbr_on_loss(...) on loss events
 *
 */

#include "netinet/sctp_callout.h"
#include "netinet/sctputil.h"
#include "bbr.h"
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/* Forward declarations */
static uint32_t sample_bw_from_rate_sample(const struct user_bbr *bbr,
                                           const struct user_bbr_rate_sample *rs);
static void bbr_take_max_bw_sample(struct user_bbr *bbr, uint32_t bw_sample);
static void bbr_advance_max_bw_filter(struct user_bbr *bbr);
static void bbr_update_min_rtt(struct user_bbr *bbr, const struct user_bbr_rate_sample *rs,
                               uint64_t now_us);
static void bbr_update_gains(struct user_bbr *bbr);
static void bbr_set_pacing_rate_internal(struct user_bbr *bbr, uint32_t bw_scaled,
                                         uint32_t gain_scaled);
static void bbr_set_cwnd_internal(struct user_bbr *bbr, const struct user_bbr_rate_sample *rs,
                                  uint32_t bw_scaled, uint32_t gain_scaled);
static uint32_t bbr_bdp_bytes(const struct user_bbr *bbr, uint32_t bw_scaled, uint32_t gain_scaled);
// static void bbr_reset_congestion_signals(struct user_bbr *bbr);
static void bbr_update_model(struct user_bbr *bbr, const struct user_bbr_rate_sample *rs);
static void bbr_update_cycle_phase(struct user_bbr *bbr, const struct user_bbr_rate_sample *rs,
                                   uint64_t now_us);
static void bbr_exit_probe_rtt(struct user_bbr *bbr);
static void bbr_check_probe_rtt_done(struct user_bbr *bbr, uint64_t now_us);

void bbr_timer_init(struct user_bbr *bbr);
// PROBE_RTT timeout callback
static void bbr_probe_rtt_timeout(void *arg);
void bbr_start_probe_rtt_timer(struct user_bbr *bbr);
void bbr_stop_probe_rtt_timer(struct user_bbr *bbr);

/* monotonic time */
uint64_t user_bbr_now_usec(void) {
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		/* fallback to gettimeofday (not monotonic) */
		struct timeval tv;
		gettimeofday(&tv, NULL);
		return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
	}
	return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

/* Public API implementations */

struct user_bbr *user_bbr_create(uint32_t mss_bytes, uint32_t init_cwnd_bytes, uint64_t now_us) {
	if (now_us == 0)
		now_us = user_bbr_now_usec();
	struct user_bbr *b = calloc(1, sizeof(*b));
	if (!b)
		return NULL;

	b->mss_bytes = mss_bytes ? mss_bytes : 1460;
	b->init_cwnd_bytes =
	    init_cwnd_bytes ? init_cwnd_bytes : (b->mss_bytes * USER_BBR_CWND_MIN_TARGET_PKTS);
	b->snd_cwnd_bytes = b->init_cwnd_bytes;
	b->pacing_rate_bps = 0;
	b->next_send_time_us = user_bbr_now_usec();
	b->bytes_in_flight = 0;
	b->delivered_bytes = 0;
	b->next_rtt_delivered = 0;
	b->round_start = true;

	b->bw_hi[0] = b->bw_hi[1] = 0;
	b->bw_lo = ~0U;
	b->bw_latest = 0;

	b->inflight_hi_bytes = ~0U;
	b->inflight_lo_bytes = ~0U;
	b->inflight_latest_bytes = 0;

	b->full_bw = 0;
	b->full_bw_cnt = 0;
	b->full_bw_reached = false;

	b->min_rtt_us = (uint32_t)-1;
	b->min_rtt_stamp_us = now_us;
	b->probe_rtt_min_us = (uint32_t)-1;
	b->probe_rtt_min_stamp_us = now_us;
	b->probe_rtt_done_time_us = 0;
	b->probe_rtt_round_done = false;

	b->mode = USER_BBR_MODE_STARTUP;
	b->cycle_idx = USER_BBR_PHASE_PROBE_CRUISE;
	b->cycle_start_time_us = now_us;

	b->pacing_gain = USER_BBR_UNIT * 277 / 100 + 1; /* approx kernel startup */
	b->cwnd_gain = USER_BBR_UNIT * 2885 / 1000;     /* 2 / ln(2) = 2.885 */

	b->initialized = true;
	b->try_fast_path = false;
	b->idle_restart = false;

	b->rounds_since_probe = 0;

	b->extra_acked_bytes[0] = b->extra_acked_bytes[1] = 0;
	b->extra_acked_win_idx = 0;
	b->extra_acked_win_rtts = 0;

    b->delivered_bytes = 0;
    b->app_limited_until = 0;
    b->app_limited = true;
	bbr_timer_init(b);
	return b;
}

/* Called when a packet is sent (caller should do this before queuing the bytes). */
void user_bbr_on_packet_sent(struct user_bbr *bbr, uint32_t bytes) {
	if (!bbr || bytes == 0)
		return;
	bbr->bytes_in_flight += bytes;
}

/* Called on ACK processing with a filled rate_sample.
 */
void user_bbr_on_ack(struct user_bbr *bbr, const struct user_bbr_rate_sample *rs_in,
                     uint64_t now_us) {
	if (!bbr || !rs_in)
		return;
	if (now_us == 0)
		now_us = user_bbr_now_usec();

	/* Copy sample to mutable local, because we will set round_start here
	 */
	struct user_bbr_rate_sample rs = *rs_in;

	/* 1) Round start detection (packet-timed rounds)
	 * Kernel: if prior_delivered >= next_rtt_delivered -> round_start
	 * Caller must provide prior_delivered_bytes (delivered at start of sample)
	 */
	if (rs.prior_delivered_bytes >= bbr->next_rtt_delivered) {
		rs.is_app_limited = rs.is_app_limited; /* keep app-limited */
		bbr->round_start = true;
		/* next round starts when cumulative delivered >= current delivered_total + ???.
		 * Kernel sets next_rtt_delivered = delivered_total + 1 when round_start, but here we'll
		 * set it to current delivered_total +  (cwnd / mss) * mss to approximate one cwnd.
		 */
		bbr->next_rtt_delivered =
		    bbr->delivered_bytes +
		    (bbr->snd_cwnd_bytes ? bbr->snd_cwnd_bytes : bbr->init_cwnd_bytes);
	} else {
		// new rtt round start
		bbr->round_start = false;
	}

	/* 2) Update delivered_total and bytes_in_flight using acked_sacked */
	if (rs.delivered > 0) {
		bbr->delivered_bytes += (uint64_t)rs.delivered;
		/* reduce bytes_in_flight by acked bytes - caller must ensure correctness */
		if ((uint64_t)rs.delivered <= bbr->bytes_in_flight)
			bbr->bytes_in_flight -= (uint64_t)rs.delivered;
		else
			bbr->bytes_in_flight = 0;
		bbr->idle_restart = false;
	}

	/* 3) bandwidth sample */
	uint32_t bw_sample_scaled = sample_bw_from_rate_sample(bbr, &rs);
	if (bw_sample_scaled > 0) {
		if (bbr->mode == USER_BBR_MODE_STARTUP) {
 		   bbr_take_max_bw_sample(bbr, bw_sample_scaled);
		} else {
    		if (!rs.is_app_limited || bw_sample_scaled >= MAX(bbr->bw_hi[0], bbr->bw_hi[1])) {
        		bbr_take_max_bw_sample(bbr, bw_sample_scaled);
    		}
		}
        // if(bw_sample_scaled > bbr->bw_latest){
        //     // bw pkts/usec >> BW_SCALE
		// 	uint64_t bw_bps = (uint64_t)(bw_sample_scaled * bbr->mss_bytes) * 1000000ULL / (uint64_t)USER_BBR_BW_UNIT;
        //     printf("[BBR][BW] new bw sample: %llu kbps\n", bw_bps / 1000ULL);
        // }
		bbr->bw_latest = MAX(bbr->bw_latest, bw_sample_scaled);
		if (rs.delivered > 0)
			bbr->inflight_latest_bytes = (uint32_t)rs.delivered;
	}

	/* 4) ack aggregation: rotate window on round_start */
	if (bbr->round_start) {
		/* advance window idx every round */
		bbr->extra_acked_win_idx = (bbr->extra_acked_win_idx + 1) & 1;
		bbr->extra_acked_bytes[bbr->extra_acked_win_idx] = 0;
		/* age rtts counter */
		if (bbr->extra_acked_win_rtts < 255)
			bbr->extra_acked_win_rtts++;
	}

	if (rs.acked_sacked > 0 && rs.interval_us > 0) {
		/* expected = bw_hi * epoch_us / (1<<BW_SCALE) * mss? Kernel uses packets based math.
		 * approximate expected bytes in epoch using bw_hi[0] (packets/usec<<BW_SCALE)
		 */
		uint64_t epoch_us = (uint64_t)rs.interval_us;
		uint64_t expected_pkts =
		    ((uint64_t)MAX(bbr->bw_hi[0], bbr->bw_hi[1]) * epoch_us) >> USER_BBR_BW_SCALE;
		uint64_t expected_bytes = expected_pkts * bbr->mss_bytes;
		uint32_t extra = 0;
		if ((uint64_t)rs.acked_sacked > expected_bytes)
			extra = (uint32_t)((uint64_t)rs.acked_sacked - expected_bytes);

		if (extra > bbr->extra_acked_bytes[bbr->extra_acked_win_idx])
			bbr->extra_acked_bytes[bbr->extra_acked_win_idx] = extra;
	}

	/* 5) update min RTT / probe RTT */
	bbr_update_min_rtt(bbr, &rs, now_us);

	/* 6) update model (full_bw detection, inflight_hi growth, etc.) */
	bbr_update_model(bbr, &rs);

	/* 7) update gains (mode -> pacing_gain/cwnd_gain) */
	bbr_update_gains(bbr);

	/* 8) compute effective bw estimate: min(max_bw, bw_lo) */
	uint32_t max_bw_scaled = MAX(bbr->bw_hi[0], bbr->bw_hi[1]);
	uint32_t bw_est_scaled = (bbr->bw_lo == ~0U) ? max_bw_scaled : MIN(max_bw_scaled, bbr->bw_lo);

	/* 9) set pacing rate & cwnd */
	bbr_set_pacing_rate_internal(bbr, bw_est_scaled, bbr->pacing_gain);
	bbr_set_cwnd_internal(bbr, &rs, bw_est_scaled, bbr->cwnd_gain);

	/* 10) update probe/cycle logic */
	bbr_update_cycle_phase(bbr, &rs, now_us);

	/* 11) check probe_rtt completion */
	bbr_check_probe_rtt_done(bbr, now_us);
}

/* On loss: reduce lower bounds conservatively */
void user_bbr_on_loss(struct user_bbr *bbr, uint32_t lost_bytes, uint64_t now_us) {
	(void)now_us;
	if (!bbr)
		return;
	/* update bw_lo as max(bw_latest, bw_lo * (1 - beta)) */
	uint32_t loss_cut = USER_BBR_UNIT - USER_BBR_BETA; /* scaled */
	if (bbr->bw_lo == ~0U) {
		bbr->bw_lo = bbr->bw_latest ? bbr->bw_latest : 1;
	} else {
		uint64_t reduced = ((uint64_t)bbr->bw_lo * (uint64_t)loss_cut) >> USER_BBR_SCALE;
		bbr->bw_lo = MAX(bbr->bw_latest, (uint32_t)reduced);
	}

	/* inflight lo bytes */
	if (bbr->inflight_lo_bytes == (uint32_t)-1) {
		bbr->inflight_lo_bytes =
		    bbr->inflight_latest_bytes ? bbr->inflight_latest_bytes : bbr->mss_bytes * 2;
	} else {
		uint64_t reduced =
		    ((uint64_t)bbr->inflight_lo_bytes * (uint64_t)loss_cut) >> USER_BBR_SCALE;
		bbr->inflight_lo_bytes = MAX(bbr->inflight_latest_bytes, (uint32_t)reduced);
	}

	/* reduce bytes in flight accounting if needed */
	if ((uint64_t)lost_bytes <= bbr->bytes_in_flight)
		bbr->bytes_in_flight -= lost_bytes;
	else
		bbr->bytes_in_flight = 0;

	/* mark that startup may have encountered congestion */
	if (bbr->mode == USER_BBR_MODE_STARTUP)
		bbr->full_bw_reached = true; /* be conservative */
}

uint64_t user_bbr_get_pacing_rate_bps(const struct user_bbr *bbr) {
	if (!bbr)
		return 0;
	return bbr->pacing_rate_bps;
}

uint32_t user_bbr_get_cwnd_bytes(const struct user_bbr *bbr) {
	if (!bbr)
		return 0;
	return bbr->snd_cwnd_bytes;
}

/* Timer tick: used for probe_rtt expiry and optional filter advancing */
void user_bbr_on_timer(struct user_bbr *bbr, uint64_t now_us) {
	if (!bbr)
		return;
	if (now_us == 0)
		now_us = user_bbr_now_usec();

	printf("[BBR][TIMER] PROBE_RTT timeout\n");
	bbr_check_probe_rtt_done(bbr, now_us);

	/* Optionally, if long time since cycle_start, advance bw window to avoid stale data */
	/* keep simple: if more than 10s since cycle start, advance filter */
	if (now_us - bbr->cycle_start_time_us > 10000000ULL) {
		bbr_advance_max_bw_filter(bbr);
		bbr->cycle_start_time_us = now_us;
	}
}

/* Debug dumps */
void user_bbr_debug_dump(const struct user_bbr *bbr, char *buf, size_t buflen) {
	if (!bbr || !buf || buflen == 0)
		return;
	int n = snprintf(buf, buflen,
	                 "mode=%d,phase=%d,cwnd=%u,pacing=%" PRIu64
	                 ",minrtt=%u,bw_hi0=%u,bw_hi1=%u,bw_lo=%u,"
	                 "inflight_hi=%u,inflight_lo=%u,delivered=%" PRIu64,
	                 (int)bbr->mode, (int)bbr->cycle_idx, bbr->snd_cwnd_bytes, bbr->pacing_rate_bps,
	                 bbr->min_rtt_us, bbr->bw_hi[0], bbr->bw_hi[1], bbr->bw_lo,
	                 bbr->inflight_hi_bytes, bbr->inflight_lo_bytes, bbr->delivered_bytes);
	(void)n;
}

void user_bbr_debug_dump_with_timestamp(const struct user_bbr *bbr) {
	char buffer[512];
	struct timeval tv;
	gettimeofday(&tv, NULL);
	user_bbr_debug_dump(bbr, buffer, sizeof(buffer));
	printf("[BBR_DEBUG][%ld.%06d] %s\n", tv.tv_sec, (int)tv.tv_usec, buffer);
}


static uint32_t sample_bw_from_rate_sample(const struct user_bbr *bbr,
                                           const struct user_bbr_rate_sample *rs) {
	if (!bbr || !rs)
		return 0;
	// printf("rs.delivered=%lld, rs.interval_us=%lld\n", rs->delivered, rs->interval_us);

	if (rs->interval_us <= 0)
		return 0;
	if (rs->delivered_delta <= 0)
		return 0;

	uint64_t packets = ((uint64_t)rs->delivered_delta + bbr->mss_bytes - 1) / bbr->mss_bytes;
	if (packets == 0)
		packets = 1;
	// printf("[BBR][BW][2] speed %llu Bytes/s\n", rs->delivered_delta * 1000000ULL / rs->interval_us);
	/* scaled_bw = ceil(packets * BW_UNIT / interval_us) */
	uint64_t scaled = (packets * (uint64_t)USER_BBR_BW_UNIT + (uint64_t)rs->interval_us - 1) /
	                  (uint64_t)rs->interval_us;
	if (scaled > (uint64_t)UINT32_MAX)
		scaled = UINT32_MAX;
	return (uint32_t)scaled;
}

static void bbr_take_max_bw_sample(struct user_bbr *bbr, uint32_t bw_sample) {
	if (!bbr)
		return;
	if (bw_sample > bbr->bw_hi[1])
		bbr->bw_hi[1] = bw_sample;
}

static void bbr_advance_max_bw_filter(struct user_bbr *bbr) {
	if (!bbr)
		return;
	if (bbr->bw_hi[1] == 0)
		return;
	bbr->bw_hi[0] = bbr->bw_hi[1];
	bbr->bw_hi[1] = 0;
}

/* update min RTT and possibly enter probe_rtt */
static void bbr_update_min_rtt(struct user_bbr *bbr, const struct user_bbr_rate_sample *rs,
                               uint64_t now_us) {
	if (!bbr || !rs)
		return;
	if (now_us == 0)
		now_us = user_bbr_now_usec();

	 /* Track recent windowed min_rtt */
	if (rs->rtt_us > 0) {
        if ((int32_t)bbr->probe_rtt_min_us == -1 || rs->rtt_us < (int32_t)bbr->probe_rtt_min_us) {
			printf("[BBR][update_min_rtt] new probe_rtt_min_us: %u us (old %u us)\n", rs->rtt_us, bbr->probe_rtt_min_us);
            bbr->probe_rtt_min_us = rs->rtt_us;
            bbr->probe_rtt_min_stamp_us = now_us;
		} 
		if((int32_t)bbr->min_rtt_us == -1 || rs->rtt_us < (int32_t)bbr->min_rtt_us) {
			printf("[BBR][update_min_rtt] new min_rtt_us: %u us (old %u us)\n", rs->rtt_us, bbr->min_rtt_us);
			bbr->min_rtt_us = rs->rtt_us;
			bbr->min_rtt_stamp_us = now_us;
		}
	}

	// if not update for long time, enter PROBE_RTT
	 if (now_us - bbr->probe_rtt_min_stamp_us >
        USER_BBR_PROBE_RTT_WIN_MS * 1000ULL &&
        !bbr->idle_restart &&
        bbr->mode != USER_BBR_MODE_PROBE_RTT) {
		/* enter PROBE_RTT: save cwnd and reduce to small drain cwnd */
		bbr->prior_snd_cwnd_bytes = bbr->snd_cwnd_bytes;
		bbr->prior_mode = bbr->mode;

		bbr->mode = USER_BBR_MODE_PROBE_RTT;
		bbr->snd_cwnd_bytes = bbr->mss_bytes * USER_BBR_CWND_MIN_TARGET_PKTS;

		bbr->probe_rtt_done_time_us = now_us + USER_BBR_PROBE_RTT_MODE_MS * 1000ULL;

		bbr->probe_rtt_round_done = false;
		/* the caller should detect that app-limited is toggled accordingly */
		printf("[BBR][update_min_rtt] rrt expire, entering PROBE_RTT mode, min_rtt_us=%u, store prior cwnd=%u, prior mode=%d\n", bbr->min_rtt_us, bbr->prior_snd_cwnd_bytes, bbr->prior_mode);
	}
}

static void bbr_exit_probe_rtt(struct user_bbr *bbr) {
	if (!bbr)
		return;

	/* Refresh long-term minRTT */
    bbr->min_rtt_us = bbr->probe_rtt_min_us;
    bbr->min_rtt_stamp_us = bbr->probe_rtt_min_stamp_us;

    /* Reset window tracker */
    bbr->probe_rtt_min_us = (uint32_t)-1;
	bbr->probe_rtt_min_stamp_us = 0;

    /* Restore state */
    bbr->mode = bbr->prior_mode;
    bbr->snd_cwnd_bytes =
        MAX(bbr->prior_snd_cwnd_bytes, bbr->init_cwnd_bytes);

    bbr->probe_rtt_done_time_us = 0;
    bbr->probe_rtt_round_done = false;

	printf("[BBR][PROBE_RTT] exiting PROBE_RTT, restoring cwnd to %u bytes\n",
	       bbr->prior_snd_cwnd_bytes);
}

static void bbr_check_probe_rtt_done(struct user_bbr *bbr, uint64_t now_us) {
	if (!bbr) return;
	if (!now_us) now_us = user_bbr_now_usec();
    if (!bbr->probe_rtt_done_time_us) return;

    if (now_us >= bbr->probe_rtt_done_time_us)
        bbr_exit_probe_rtt(bbr);
}

/* update pacing/cwnd gains from mode/phase */
static void bbr_update_gains(struct user_bbr *bbr) {
	if (!bbr)
		return;
	switch (bbr->mode) {
	case USER_BBR_MODE_STARTUP:
		bbr->pacing_gain = USER_BBR_UNIT * 277 / 100 + 1;
		bbr->cwnd_gain = USER_BBR_UNIT * 2885 / 1000; // 2 / ln(2) = 2.885
		break;
	case USER_BBR_MODE_DRAIN:
		bbr->pacing_gain = (USER_BBR_UNIT * 1000) / 2885; /* approx drain */
		bbr->cwnd_gain = USER_BBR_UNIT * 2;
		break;
	case USER_BBR_MODE_PROBE_BW:
		switch (bbr->cycle_idx) {
		case USER_BBR_PHASE_PROBE_UP:
			bbr->pacing_gain = USER_BBR_PACING_GAIN_UP;
			break;
		case USER_BBR_PHASE_PROBE_DOWN:
			bbr->pacing_gain = USER_BBR_PACING_GAIN_DOWN;
			break;
		case USER_BBR_PHASE_PROBE_CRUISE:
			bbr->pacing_gain = USER_BBR_PACING_GAIN_CRUISE;
			break;
		case USER_BBR_PHASE_PROBE_REFILL:
			bbr->pacing_gain = USER_BBR_PACING_GAIN_REFILL;
			break;
		default:
			bbr->pacing_gain = USER_BBR_UNIT;
			break;
		}
		bbr->cwnd_gain = USER_BBR_UNIT * 2;
		break;
	case USER_BBR_MODE_PROBE_RTT:
		bbr->pacing_gain = USER_BBR_UNIT;
		bbr->cwnd_gain = USER_BBR_UNIT;
		break;
	default:
		bbr->pacing_gain = USER_BBR_UNIT;
		bbr->cwnd_gain = USER_BBR_UNIT;
		break;
	}
}

/* convert bw_scaled (packets/usec << BW_SCALE) and gain to bytes/sec */
static void bbr_set_pacing_rate_internal(struct user_bbr *bbr, uint32_t bw_scaled,
                                         uint32_t gain_scaled) {
	if (!bbr)
		return;
	if (bw_scaled == 0) {
		bbr->pacing_rate_bps = 0;
		return;
	}

	/* rate = bw_scaled * mss * gain / (1<<USER_BBR_SCALE) * 1e6 / (1<<BW_SCALE) */
	uint64_t rate = (uint64_t)bw_scaled * (uint64_t)bbr->mss_bytes;
	rate = (rate * (uint64_t)gain_scaled) >> USER_BBR_SCALE; /* packets/usec * mss */
	rate = (rate * 1000000ULL) >> USER_BBR_BW_SCALE;         /* bytes/sec */
	uint64_t margin = (100 - USER_BBR_PACING_MARGIN_PERCENT);
	rate = (rate * margin) / 100;
	if (rate == 0)
		rate = 1;
	bbr->pacing_rate_bps = rate;
}

uint32_t user_bbr_bdp_bytes(const struct user_bbr *bbr, uint32_t bw_scaled,
                              uint32_t gain_scaled){
	return bbr_bdp_bytes(bbr, bw_scaled, gain_scaled);
}

/* compute BDP in bytes using bw_scaled and gain */
/* bw_scaled: packets/usec << BW_SCALE 
   gain_scaled: gain * USER_BBR_UNIT*/
static uint32_t bbr_bdp_bytes(const struct user_bbr *bbr, uint32_t bw_scaled,
                              uint32_t gain_scaled) {
	if (!bbr)
		return 0;
	
	if (bbr->min_rtt_us == (uint32_t)-1 && bbr->probe_rtt_min_us == (uint32_t)-1)
		return bbr->init_cwnd_bytes;

	// if min_rtt_us is not set, fallback to use probe_rtt_min_us ( we still probing rtt)
	uint32_t min_rtt_us = (bbr->min_rtt_us != (uint32_t)-1) ? bbr->min_rtt_us : bbr->probe_rtt_min_us;

	uint64_t w = (uint64_t)bw_scaled * (uint64_t)min_rtt_us; /* packets << USER_BBR_BW_SCALE */
	uint64_t packets_times_gain =
	    (w * (uint64_t)gain_scaled) / USER_BBR_UNIT; 		 /* still << USER_BBR_BW_SCALE */
	uint64_t packets = (packets_times_gain + USER_BBR_BW_UNIT - 1) / USER_BBR_BW_UNIT;
	if (packets == 0)
		packets = 1;
	uint64_t bytes = packets * (uint64_t)bbr->mss_bytes;
	// printf("[BBR][BDP] bw_scaled=%u, min_rtt_us=%u, win bytes=%llu\n", bw_scaled, bbr->min_rtt_us, w);
	uint32_t min_bytes = bbr->mss_bytes * USER_BBR_CWND_MIN_TARGET_PKTS;
	if (bytes < min_bytes){
		bytes = min_bytes;
	}
	if (bytes > UINT32_MAX)
		return UINT32_MAX;
	return (uint32_t)bytes;
}

/* set cwnd based on bdp, inflight bounds and acked bytes */
static void bbr_set_cwnd_internal(struct user_bbr *bbr, const struct user_bbr_rate_sample *rs,
                                  uint32_t bw_scaled, uint32_t gain_scaled) {
	if (!bbr || !rs)
		return;

		 if (bbr->mode == USER_BBR_MODE_STARTUP) {
			bbr->snd_cwnd_bytes = bbr->snd_cwnd_bytes * bbr->cwnd_gain / USER_BBR_UNIT;
        	uint32_t min_growth = bbr->mss_bytes * 2; 
        	if (rs->acked_sacked > 0) {
            	bbr->snd_cwnd_bytes += MAX(rs->acked_sacked, (int32_t)min_growth);
        	} else {
            	bbr->snd_cwnd_bytes += min_growth;
        	}
        // printf("[BBR][STARTUP] force grow: cwnd to =%u\n", bbr->snd_cwnd_bytes);
		return;
    }

	uint32_t target =
	    bbr_bdp_bytes(bbr, bw_scaled ? bw_scaled : 1, gain_scaled ? gain_scaled : USER_BBR_UNIT);

	/* include ack aggregation allowance */
	uint32_t extra_aggr = MAX(bbr->extra_acked_bytes[0], bbr->extra_acked_bytes[1]);
	uint64_t target_plus = (uint64_t)target + (uint64_t)extra_aggr;

	/* enforce inflight_hi/lo bounds (hi may be large if unset) */
	uint32_t hi = (bbr->inflight_hi_bytes == (uint32_t)-1)
	                  ? (uint32_t)target_plus
	                  : MIN((uint32_t)target_plus, bbr->inflight_hi_bytes);
	uint32_t lo = (bbr->inflight_lo_bytes == (uint32_t)-1) ? 0 : bbr->inflight_lo_bytes;
	uint32_t final_target = MAX(lo, hi);
	// printf("[BBR][SET_CWND] target=%u, extra_aggr=%u, target_plus=%llu, inflight_hi=%u, "
	//        "inflight_lo=%u, final_target=%u\n",
	//        target, extra_aggr, target_plus, bbr->inflight_hi_bytes, bbr->inflight_lo_bytes,
	//        final_target);

	/* increase cwnd by acked bytes, but cap at final_target */
	bbr->snd_cwnd_bytes += (uint32_t)rs->acked_sacked;
	if (bbr->snd_cwnd_bytes >= final_target) {
		bbr->snd_cwnd_bytes = final_target;
		bbr->try_fast_path = true;
	}

	/* minimum cwnd */
	uint32_t cwnd_min = bbr->mss_bytes * USER_BBR_CWND_MIN_TARGET_PKTS;
	if (bbr->snd_cwnd_bytes < cwnd_min)
		bbr->snd_cwnd_bytes = cwnd_min;
   
}

/* update model: full_bw detection and inflight_hi growth during PROBE_UP */
static void bbr_update_model(struct user_bbr *bbr, const struct user_bbr_rate_sample *rs) {
	if (!bbr || !rs)
		return;

	uint32_t bmax = MAX(bbr->bw_hi[0], bbr->bw_hi[1]);
	if (bmax == 0)
		return;

	if (!bbr->full_bw_reached) {
		if (bbr->full_bw == 0) {
			bbr->full_bw = bmax;
			bbr->full_bw_cnt = 0;
		} else {
			uint32_t prev_full_bw = bbr->full_bw;
			/* require non app-limited samples to count for full bw */
			if (!rs->is_app_limited &&
			    bmax >= (uint32_t)((uint64_t)bbr->full_bw * USER_BBR_FULL_BW_THRESH >>
			                       USER_BBR_SCALE)) {
				bbr->full_bw = bmax;
				bbr->full_bw_cnt = 0;
				printf("[BBR][STARTUP][UPDATE MODEL] growing 1.25x\n");

			} else {
				bbr->full_bw_cnt++;
				printf("[BBR][STARTUP][UPDATE MODEL] not growing 1.25x, cnt =%u, curent full bw %u, previous %u\n", bbr->full_bw_cnt, bbr->full_bw, prev_full_bw);
				if (bbr->full_bw_cnt >= USER_BBR_FULL_BW_CNT) {
					printf("[BBR][STARTUP][UPDATE MODEL]entering DRAIN phase, full bw reached, current full "
					       "bw %u(scaled) pkt/usec, previous full bw %u (scaled)\n",
					       bbr->full_bw, prev_full_bw);
					bbr->full_bw_reached = true;
					/* transition to PROBE_BW after STARTUP finishes */
					if (bbr->mode == USER_BBR_MODE_STARTUP) {
						bbr->mode = USER_BBR_MODE_DRAIN;
					}
				}
			}
		}
	}

	/* PROBE_UP inflight_hi growth: if in probe_up and we have meaningful tx_in_flight */
	if (bbr->mode == USER_BBR_MODE_PROBE_BW && bbr->cycle_idx == USER_BBR_PHASE_PROBE_UP) {
		/* if caller provided tx_in_flight_bytes (rs->tx_in_flight_bytes), use it to seed/raise
		 * inflight_hi */
		if (rs->tx_in_flight_bytes > 0) {
			if (bbr->inflight_hi_bytes == (uint32_t)-1)
				bbr->inflight_hi_bytes = (uint32_t)rs->tx_in_flight_bytes;
			else {
				/* gently increase inflight_hi toward observed tx_in_flight or by mss */
				uint32_t inc = bbr->mss_bytes;
				if (rs->tx_in_flight_bytes > (int64_t)bbr->inflight_hi_bytes)
					bbr->inflight_hi_bytes = (uint32_t)rs->tx_in_flight_bytes;
				else
					bbr->inflight_hi_bytes = bbr->inflight_hi_bytes + inc;
			}
		} else {
			/* No tx_in_flight provided: increase by mss */
			if (bbr->inflight_hi_bytes == (uint32_t)-1)
				bbr->inflight_hi_bytes = bbr->mss_bytes * 4;
			else
				bbr->inflight_hi_bytes += bbr->mss_bytes;
		}
	}
}

/* Update probe cycle phase driven by packet-timed round_start */
static void bbr_update_cycle_phase(struct user_bbr *bbr, const struct user_bbr_rate_sample *rs,
                                   uint64_t now_us) {
	(void)now_us;
	if (!bbr || !rs)
		return;
	if (!bbr->full_bw_reached)
		return;

	if (bbr->mode == USER_BBR_MODE_DRAIN) {
   		uint32_t bdp = bbr_bdp_bytes(bbr, bbr->bw_latest, bbr->cwnd_gain);
    	if (bbr->bytes_in_flight <= bdp) {
        	/* DRAIN done，enter PROBE_BW */
        	bbr->mode = USER_BBR_MODE_PROBE_BW;
        	bbr->cycle_idx = USER_BBR_PHASE_PROBE_CRUISE;
        	bbr->cycle_start_time_us = now_us;

        	printf("[BBR][CYCLE] exit DRAIN -> PROBE_BW, inflight=%llu bdp=%u\n",
               	bbr->bytes_in_flight, bdp);
    	}
    	return;
	}

	if (bbr->mode != USER_BBR_MODE_PROBE_BW)
		return;

	/* use bbr->round_start which we computed in on_ack */
	if (!bbr->round_start){
		return;
	}

	switch (bbr->cycle_idx) {
	case USER_BBR_PHASE_PROBE_UP:
		// printf("[BBR][CYCLE] advancing cycle phase from %d to %d\n", bbr->cycle_idx, USER_BBR_PHASE_PROBE_DOWN);
		/* after one round in UP, move to DOWN */
		bbr->cycle_idx = USER_BBR_PHASE_PROBE_DOWN;
		break;
	case USER_BBR_PHASE_PROBE_DOWN:
		// printf("[BBR][CYCLE] advancing cycle phase from %d to %d\n", bbr->cycle_idx, USER_BBR_PHASE_PROBE_CRUISE);
		bbr->cycle_idx = USER_BBR_PHASE_PROBE_CRUISE;
		break;
	case USER_BBR_PHASE_PROBE_CRUISE:
		/* after some rounds go to REFILL */
		bbr->rounds_since_probe++;
		// printf("[BBR][CYCLE] advancing cycle phase from %d , rounds_since_probe=%d\n",
		    //    bbr->cycle_idx, bbr->rounds_since_probe);
		if (bbr->rounds_since_probe >= 8) {
			// printf("[BBR][CYCLE] cruise phase done, advancing cycle phase from %d to %d\n", bbr->cycle_idx, USER_BBR_PHASE_PROBE_REFILL);
			bbr->cycle_idx = USER_BBR_PHASE_PROBE_REFILL;
			bbr->rounds_since_probe = 0;
		}
		break;
	case USER_BBR_PHASE_PROBE_REFILL:
		bbr->cycle_idx = USER_BBR_PHASE_PROBE_UP;
		/* rotate bw window when a full cycle completed */
		bbr_advance_max_bw_filter(bbr);
		break;
	default:
		bbr->cycle_idx = USER_BBR_PHASE_PROBE_UP;
		break;
	}
	bbr->cycle_start_time_us = now_us ? now_us : user_bbr_now_usec();
}

void bbr_timer_init(struct user_bbr *bbr) {
	printf("[BBR][TIMER INIT] Initializing BBR timers\n");
	sctp_os_timer_init(&bbr->probe_rtt_timer);

	bbr->timer_ticks = sctp_get_tick_count();
}

/* PROBE_RTT timeout callback */
static void bbr_probe_rtt_timeout(void *arg) {
	struct user_bbr *bbr = (struct user_bbr *)arg;
	user_bbr_on_timer(bbr, user_bbr_now_usec());
}

void bbr_start_probe_rtt_timer(struct user_bbr *bbr) {
	// uint32_t current_ticks = sctp_get_tick_count();
	uint32_t timeout_ticks = sctp_msecs_to_ticks(200); // 200ms

	sctp_os_timer_start(&bbr->probe_rtt_timer, timeout_ticks, bbr_probe_rtt_timeout, bbr);
}

void bbr_stop_probe_rtt_timer(struct user_bbr *bbr) { sctp_os_timer_stop(&bbr->probe_rtt_timer); }
