#define SCTP 1
#define SCTP_DEBUG 1

/* SCTP_PROCESS_LEVEL_LOCKS uses sctp_process_lock.h within sctp_pcb.h 
 *  otherwise if undefined (i.e. below is commented out), we will use 
 *  sctp_lock_userspace.h .
 */
#define SCTP_PROCESS_LEVEL_LOCKS 1
//#define SCTP_PER_SOCKET_LOCKING 1

/* uncomment the below in order to make the CRC32c disabled */
/*#define SCTP_WITH_NO_CSUM 1*/

/* forces routes to have MTU 1500. user mbuf implementation doesn't have
 *  efficient jumbo support yet.
 */
#define SCTP_USERSPACE_ROUTE_USE_MTU_1500 1


/* makes use of the send callback only at a threshold if 1, and whenever the callback
 *  is not NULL if 0.
 */
#define SCTP_USERSPACE_SEND_CALLBACK_USE_THRESHOLD 0
