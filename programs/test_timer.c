#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <usrsctp.h>
#include <stdarg.h>

int
main(void) 
{
	int i;
	void *p;

	usrsctp_init(0, NULL, NULL);
#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif
	printf("Entering the loop\n");
	p = &i;
	for (i = 0; i < 100000; i++) {
		usrsctp_register_address(p);
		usrsctp_deregister_address(p);
	}
	printf("Exited the loop\n");
	while (usrsctp_finish() != 0) {
#ifdef _WIN32
		Sleep(1000);
#else
		sleep(1);
#endif
	}
	return (0);
}
