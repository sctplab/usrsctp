/*
 * lwip_smoke.c - minimal init / socket / close smoke test for the lwIP
 * backend of usrsctp (SCTP_USE_LWIP).
 *
 * Goal: prove that a build with `-Dsctp_use_lwip=ON` links and that the
 * basic `usrsctp_init` -> `usrsctp_socket` -> `usrsctp_close` ->
 * `usrsctp_finish` lifecycle does not crash.  This is not a functional
 * SCTP-over-lwIP loopback test; it only validates that the lwIP-backed
 * build is well-formed.
 *
 * Exit codes:
 *   0 - success ("lwip_smoke: PASS" printed)
 *   1 - failure (a usrsctp call returned an unexpected value)
 */
#include <stdio.h>
#include <stdlib.h>

#include "usrsctp.h"

static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
	(void)addr;
	(void)buf;
	(void)length;
	(void)tos;
	(void)set_df;
	return 0;
}

int
main(void)
{
	struct socket *sock;

	usrsctp_init(0, conn_output, NULL);

	sock = usrsctp_socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP,
	                      NULL, NULL, 0, NULL);
	if (sock == NULL) {
		fprintf(stderr, "lwip_smoke: usrsctp_socket() returned NULL\n");
		usrsctp_finish();
		return 1;
	}

	usrsctp_close(sock);

	while (usrsctp_finish() != 0) {
		/* finish may need a few iterations to tear down internal
		 * state; in a smoke test we just spin briefly. */
	}

	printf("lwip_smoke: PASS\n");
	return 0;
}
