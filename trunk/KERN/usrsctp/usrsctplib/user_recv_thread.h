/* __Userspace__ user_recv_thread.h header file for creating recv thread */



/* raw socket to be used for both incoming and outgoing packets */
extern int userspace_rawsctp; /* needs to be declared = -1 */
extern int userspace_rawsctp6;

/* udp socket to be used for both incoming and outgoing packets */
extern int userspace_udpsctp; /* needs to be declared = -1 */
extern int userspace_udpsctp6;

/* routing socket used for route lookups */
extern int userspace_route;

void recv_thread_init();

#define RECV_THREAD_INIT    recv_thread_init

