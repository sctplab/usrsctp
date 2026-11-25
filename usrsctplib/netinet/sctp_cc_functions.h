// Add these declarations
void sctp_cwnd_update_exit_pf_common(struct sctp_tcb *stcb, struct sctp_nets *net);
void sctp_hs_cwnd_update_after_sack(struct sctp_tcb *stcb, struct sctp_nets *net);
void sctp_htcp_cwnd_update_after_sack(struct sctp_tcb *stcb, struct sctp_nets *net);
void sctp_htcp_cwnd_update_after_ecn_echo(struct sctp_tcb *stcb, struct sctp_nets *net);
void sctp_cwnd_update_rtcc_packet_transmitted(struct sctp_tcb *stcb, struct sctp_nets *net);
void sctp_cwnd_prepare_rtcc_net_for_sack(struct sctp_tcb *stcb, struct sctp_nets *net);
void sctp_rtt_rtcc_calculated(struct sctp_tcb *stcb, struct sctp_nets *net);
