
#ifndef _FUZZER_COMMON_H_
#define _FUZZER_COMMON_H_

#define SCTP_PACKED __attribute__((packed))

struct sctp_chunk_header {
	uint8_t chunk_type;	/* chunk type */
	uint8_t chunk_flags;	/* chunk flags */
	uint16_t chunk_length;	/* chunk length */
	/* optional params follow */
} SCTP_PACKED;

struct sctp_init_chunk {
	struct sctp_chunk_header ch;
	uint32_t initiate_tag;	/* initiate tag */
	uint32_t a_rwnd;	/* a_rwnd */
	uint16_t num_outbound_streams;	/* OS */
	uint16_t num_inbound_streams;	/* MIS */
	uint32_t initial_tsn;	/* I-TSN */
	/* optional param's follow */
} SCTP_PACKED;



#endif
