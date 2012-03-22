#ifndef DATACHAN_H

#define DATA_CHANNEL_PPID_CONTROL   1
#define DATA_CHANNEL_PPID_DOMSTRING 2
#define DATA_CHANNEL_PPID_BINARY    3

struct rtcweb_datachannel_msg {
  uint8_t  msg_type;
  uint8_t  channel_type;  
  uint16_t flags;
  uint16_t reverse_stream;
  uint16_t reliability_params;
  /* msg_type_data follows */
} SCTP_PACKED;

/* msg_type values: */
#define DATA_CHANNEL_OPEN                     0
#define DATA_CHANNEL_OPEN_RESPONSE            1

/* channel_type values: */
#define DATA_CHANNEL_RELIABLE                 0
#define DATA_CHANNEL_RELIABLE_STREAM          1
#define DATA_CHANNEL_UNRELIABLE               2
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT  3
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED   4

/* flags values: */
#define DATA_CHANNEL_FLAG_OUT_OF_ORDER_ALLOWED 0x0001
/* all other bits reserved and should be set to 0 */

/* msg_type_data contains: */
/*
   for DATA_CHANNEL_OPEN:
      a DOMString label for the data channel
   for DATA_CHANNEL_OPEN_RESPONSE:
      a 16-bit value for errors or 0 for no error
*/

#define ERR_DATA_CHANNEL_ALREADY_OPEN   0
#define ERR_DATA_CHANNEL_NONE_AVAILABLE 1

#endif
