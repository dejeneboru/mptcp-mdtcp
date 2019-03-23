
/*
 *	 Multipath Datacenter TCP(MDTCP)-a Coupled Congestion Control for Datacenter
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer & Author:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Octavian Purdila <octavian.purdila@intel.com>
 *	John Ronan <jronan@tssg.org>
 *	Catalin Nicutar <catalin.nicutar@gmail.com>
 *	Brandon Heller <brandonh@stanford.edu>
 *      Dejene Boru Oljira <oljideje@kau.se>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <net/tcp.h>
#include <net/mptcp.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/ktime.h>

#define MDTCP_MAX_ALPHA	1024U

struct mdtcp {	
	u64  beta;
	bool forced_update;
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 mdtcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 loss_cwnd;


};

/*mdtcp specifics*/
static unsigned int mdtcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(mdtcp_shift_g, uint, 0644);
MODULE_PARM_DESC(mdtcp_shift_g, "parameter g for updating mdtcp_alpha");

static unsigned int mdtcp_alpha_on_init __read_mostly = MDTCP_MAX_ALPHA;
module_param(mdtcp_alpha_on_init, uint, 0644);
MODULE_PARM_DESC(mdtcp_alpha_on_init, "parameter for initial alpha value");

static unsigned int mdtcp_clamp_alpha_on_loss __read_mostly;
module_param(mdtcp_clamp_alpha_on_loss, uint, 0644);
MODULE_PARM_DESC(mdtcp_clamp_alpha_on_loss,
		"parameter for clamping alpha on loss");
static unsigned int mdtcp_debug __read_mostly = 0; 
module_param(mdtcp_debug, uint, 0644);
MODULE_PARM_DESC(mdtcp_debug, "enable debug");

static unsigned int beta_scale __read_mostly = 1024; 
module_param(beta_scale, uint, 0644);
MODULE_PARM_DESC(beta_scale, "scale beta for precision");

/*end mdtcp*/


static struct tcp_congestion_ops mdtcp_reno;

static inline int mdtcp_sk_can_send(const struct sock *sk)
{
	return mptcp_sk_can_send(sk) && tcp_sk(sk)->srtt_us;
}

static inline u64 mdtcp_get_beta(const struct sock *meta_sk)
{
	return ((struct mdtcp *)inet_csk_ca(meta_sk))->beta;
}

static inline void mdtcp_set_beta(const struct sock *meta_sk, u64 beta)
{
	((struct mdtcp *)inet_csk_ca(meta_sk))->beta = beta;
}


static inline bool mdtcp_get_forced(const struct sock *meta_sk)
{
	return ((struct mdtcp *)inet_csk_ca(meta_sk))->forced_update;
}

static inline void mdtcp_set_forced(const struct sock *meta_sk, bool force)
{
	((struct mdtcp *)inet_csk_ca(meta_sk))->forced_update = force;
}

static void mdtcp_reset(const struct tcp_sock *tp, struct mdtcp *ca)
{
	ca->next_seq = tp->snd_nxt;
	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
}



static u32 mdtcp_ssthresh(struct sock *sk)
{
	struct mdtcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	//u32 reduction;
	ca->loss_cwnd = tp->snd_cwnd;

	/* Always reduce by at least 1MSS when receiving marks.*/
	//reduction = max((tp->snd_cwnd * ca->mdtcp_alpha) >> 11U, 1U);
	//return max(tp->snd_cwnd - reduction, 2U);

	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->mdtcp_alpha) >> 11U), 2U);


}

/* Minimal DCTP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */

static void mdtcp_ce_state_0_to_1(struct sock *sk)
{
	struct mdtcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (!ca->ce_state) {
		/* State has changed from CE=0 to CE=1, force an immediate
		 * ACK to reflect the new CE state. If an ACK was delayed,
		 * send that first to reflect the prior CE state.
		 */
		if (inet_csk(sk)->icsk_ack.pending & ICSK_ACK_TIMER)
			__tcp_send_ack(sk, ca->prior_rcv_nxt);
		//inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
		tcp_enter_quickack_mode(sk, 1);
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 1;
	tp->ecn_flags |= TCP_ECN_DEMAND_CWR;

}

static void mdtcp_ce_state_1_to_0(struct sock *sk)
{
	struct mdtcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (ca->ce_state) {
		/* State has changed from CE=1 to CE=0, force an immediate
		 * ACK to reflect the new CE state. If an ACK was delayed,
		 * send that first to reflect the prior CE state.
		 */
		if (inet_csk(sk)->icsk_ack.pending & ICSK_ACK_TIMER)
			__tcp_send_ack(sk, ca->prior_rcv_nxt);
		//inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
		tcp_enter_quickack_mode(sk, 1);
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 0;
	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;

}



static void mdtcp_update_alpha(struct sock *sk, u32 flags)

{

	struct tcp_sock *tp = tcp_sk(sk);
	struct mdtcp *ca = inet_csk_ca(sk);
	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = inet_csk(sk)->icsk_ack.rcv_mss;
	if (acked_bytes) {
		ca->acked_bytes_total += acked_bytes;
		ca->prior_snd_una = tp->snd_una;
		if (flags & CA_ACK_ECE)
			ca->acked_bytes_ecn += acked_bytes;
	}

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {
		u64 bytes_ecn = ca->acked_bytes_ecn;
		u32 alpha = ca->mdtcp_alpha;
		/* alpha = (1 - g) * alpha + g * F */
		alpha -= min_not_zero(alpha, alpha >> mdtcp_shift_g);
		if (bytes_ecn) {
			/* If mdtcp_shift_g == 1, a 32bit value would overflow
			 * after 8 Mbytes.
			 */
			bytes_ecn <<= (10 - mdtcp_shift_g);
			do_div(bytes_ecn, max(1U, ca->acked_bytes_total));
			alpha = min(alpha + (u32)bytes_ecn, MDTCP_MAX_ALPHA);
		}


		WRITE_ONCE(ca->mdtcp_alpha, alpha);

		if (mpcb && mdtcp_debug && alpha)
			printk("cwnd: %u dctcp-alpha: %u bytes_ecn: %u acked_bytes: %u  rtt: %u no.subflows %u pi: %d \n",tp->snd_cwnd,ca->mdtcp_alpha,\
					ca->acked_bytes_ecn, ca->acked_bytes_total,tp->srtt_us >> 3,mpcb->cnt_established,tp->mptcp->path_index);

		mdtcp_reset(tp, ca);
	}



}

static u32 mdtcp_cwnd_undo(struct sock *sk)
{
	const struct mdtcp *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static void mdtcp_recalc_beta( const struct sock *sk)
{     	

	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	struct sock *sub_sk;
	u64 beta = 1;

	int best_rtt = 1,can_send=0;

	if (!mpcb)
		return;

	if (mpcb->cnt_established <= 1)
		goto exit;

	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);

		if (!mdtcp_sk_can_send(sub_sk))
			continue;
		can_send++;
		/* We need to look for the path, that provides the minimum RTT*/

		if (best_rtt == 1 || sub_tp->srtt_us < best_rtt)
			best_rtt = sub_tp->srtt_us;


	}

	/* No subflow is able to send - we don't care anymore */
	if (unlikely(!can_send)){
		beta = beta_scale;
		goto exit;
	}

	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);
		if (!mdtcp_sk_can_send(sub_sk))
			continue;
		beta += div_u64((u64)beta_scale * sub_tp->snd_cwnd * best_rtt, sub_tp->srtt_us);
	}

	if (unlikely(!beta))
		beta = beta_scale;

exit:
	mdtcp_set_beta(mptcp_meta_sk(sk), beta);

}

static void mdtcp_init(struct sock *sk)
{       

	const struct tcp_sock *tp = tcp_sk(sk);
	struct mdtcp *ca = inet_csk_ca(sk);
	if (mptcp(tcp_sk(sk)) && ((tp->ecn_flags & TCP_ECN_OK) ||
				(sk->sk_state == TCP_LISTEN ||
				 sk->sk_state == TCP_CLOSE))) {

		mdtcp_set_forced(mptcp_meta_sk(sk), 0);
		mdtcp_set_beta(mptcp_meta_sk(sk), beta_scale);

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;
		ca->mdtcp_alpha = min(mdtcp_alpha_on_init, MDTCP_MAX_ALPHA);

		ca->loss_cwnd = 0;
		ca->ce_state = 0;

		mdtcp_reset(tp, ca);
		return;

	} else if (!mptcp(tcp_sk(sk)) && ((tp->ecn_flags & TCP_ECN_OK) ||
				(sk->sk_state == TCP_LISTEN ||
				 sk->sk_state == TCP_CLOSE))) {

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;
		ca->mdtcp_alpha = min(mdtcp_alpha_on_init, MDTCP_MAX_ALPHA);
		ca->loss_cwnd = 0;
		ca->ce_state = 0;
		mdtcp_reset(tp, ca);
		return;

	}

	/* If we do not mdtcp, behave like reno: return */
	inet_csk(sk)->icsk_ca_ops = &mdtcp_reno;
	INET_ECN_dontxmit(sk);

}


static void mdtcp_react_to_loss(struct sock *sk)
{
	struct mdtcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->loss_cwnd = tp->snd_cwnd;
	/* Stay fair with reno/cubic (RFC-style) */
	tp->snd_ssthresh = max(tp->snd_cwnd >> 1U, 2U);
}

static void mdtcp_state(struct sock *sk, u8 ca_state)
{
       if (ca_state == TCP_CA_Recovery && ca_state != inet_csk(sk)->icsk_ca_state)
	        /* React to the first fast retransmission of this window. */
		mdtcp_react_to_loss(sk);


	if (mptcp(tcp_sk(sk)))
		mdtcp_set_forced(mptcp_meta_sk(sk), 1);


	if (mdtcp_clamp_alpha_on_loss && ca_state == TCP_CA_Loss) {
		struct mdtcp *ca = inet_csk_ca(sk);

		/* If this extension is enabled, we clamp mdtcp_alpha to
		 * max on packet loss; the motivation is that mdtcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 * Additionnally, this will cause the next cwnd reduction
		 * computed by dctcp_ssthresh() to be quite large even if the
		 * loss was a one time event due to the historical term in
		 * dctcp_alpha's EWMA.
		 */
		ca->mdtcp_alpha = MDTCP_MAX_ALPHA;
	}
}

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w),
 * for every packet that was ACKed.
 */
void mdtcp_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked)
{
	/* If credits accumulated at a higher w, apply them gently now. */
	if (tp->snd_cwnd_cnt >= w) {
		tp->snd_cwnd_cnt = 0;
		tp->snd_cwnd++;
	}

	tp->snd_cwnd_cnt += acked;
	if (tp->snd_cwnd_cnt >= w) {
		u32 delta = tp->snd_cwnd_cnt / w;
		tp->snd_cwnd_cnt -= delta * w;
		tp->snd_cwnd += delta;
	}
	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
}

static void mdtcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct mptcp_cb *mpcb = tp->mpcb;
	int snd_cwnd = 0,snd_cwnd_old=0;
	u64 beta;


	if (!mptcp(tp) ) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	if (!tcp_is_cwnd_limited(sk))
		return;
	if (tcp_in_slow_start(tp)) {
		/* In "safe" area, increase. */
		tcp_slow_start(tp, acked);
		mdtcp_recalc_beta(sk);
		return;
	}
	if (mpcb->cnt_established > 1) { 

		if (mdtcp_get_forced(mptcp_meta_sk(sk)) ) {
			mdtcp_recalc_beta(sk);
			mdtcp_set_forced(mptcp_meta_sk(sk), 0);
		}

		beta = mdtcp_get_beta(mptcp_meta_sk(sk));

		/* This may happen, if at the initialization, the mpcb
		 * was not yet attached to the sock, and thus
		 * initializing beta failed.
		 */
		if (unlikely(!beta))
			beta = beta_scale;

		snd_cwnd = (int) div_u64(beta, beta_scale);

		if (snd_cwnd < tp->snd_cwnd)
			snd_cwnd = tp->snd_cwnd;
		//snd_cwnd_old = snd_cwnd;
		if (mpcb->cnt_established == 2) { 

			mdtcp_cong_avoid_ai(tp, snd_cwnd, acked);
			mdtcp_recalc_beta(sk);

		} else { 

			if (tp->snd_cwnd_cnt >= snd_cwnd) {
				if (tp->snd_cwnd < tp->snd_cwnd_clamp) {
					tp->snd_cwnd++;
					mdtcp_recalc_beta(sk);
				}

				tp->snd_cwnd_cnt = 0;
			} else {
				tp->snd_cwnd_cnt++;
			}

		}

	} else {

		snd_cwnd = tp->snd_cwnd;
		mdtcp_cong_avoid_ai(tp, snd_cwnd, acked);
	}


}


static void mdtcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{      
	struct tcp_sock *tp = tcp_sk(sk);

	switch (ev) {

		case CA_EVENT_ECN_IS_CE:
			mdtcp_ce_state_0_to_1(sk);
			break;
		case CA_EVENT_ECN_NO_CE:
			mdtcp_ce_state_1_to_0(sk);
			break;
		case CA_EVENT_LOSS:
			/* React to a RTO if not other ssthresh reduction took place
			 * inside this window.
			 */
			 mdtcp_react_to_loss(sk);
			if(mptcp(tp))
				mdtcp_recalc_beta(sk);
			break;

		default:
			/* Don't care for the rest. */
			break;
	}


}

static struct tcp_congestion_ops mdtcp __read_mostly = {
	.init		= mdtcp_init,
	.in_ack_event   = mdtcp_update_alpha,
	.ssthresh	= mdtcp_ssthresh,
	.cong_avoid	= mdtcp_cong_avoid,
	.undo_cwnd	= mdtcp_cwnd_undo,
	.cwnd_event	= mdtcp_cwnd_event,
	.set_state	= mdtcp_state,
	.owner		= THIS_MODULE,
	.flags		= TCP_CONG_NEEDS_ECN,
	.name		= "mdtcp",
};

static struct tcp_congestion_ops mdtcp_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.owner		= THIS_MODULE,
	.name		= "mdtcp-reno",
};


static int __init mdtcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct mdtcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&mdtcp);
}

static void __exit mdtcp_unregister(void)
{
	tcp_unregister_congestion_control(&mdtcp);
}

module_init(mdtcp_register);
module_exit(mdtcp_unregister);

MODULE_AUTHOR("Christoph Paasch, Sébastien Barré, Daniel Borkmann, Florian Westphal, Glenn Judd, Dejene Boru Oljira");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MDTCP COUPLED CONGESTION CONTROL ALGORITHM");
MODULE_VERSION("0.1");
