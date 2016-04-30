#ifndef __DECODE_UDP_H__
#define __DECODE_UDP_H__

/* UDP header structure */
typedef struct UDPHdr_
{
    uint16_t uh_sport;  /* source port */
    uint16_t uh_dport;  /* destination port */
    uint16_t uh_len;    /* length */
    uint16_t uh_sum;    /* checksum */
} UDPHdr;


#define UDP_HEADER_LEN         8

#define UDP_GET_RAW_LEN(udph)                (udph)->uh_len
#define UDP_GET_RAW_SRC_PORT(udph)           (udph)->uh_sport
#define UDP_GET_RAW_DST_PORT(udph)           (udph)->uh_dport

#define UDP_GET_LEN(p)                       UDP_GET_RAW_LEN(((UDPHdr *)(p->transport_header)))
#define UDP_GET_SRC_PORT(p)                  UDP_GET_RAW_SRC_PORT(((UDPHdr *)(p->transport_header)))
#define UDP_GET_DST_PORT(p)                  UDP_GET_RAW_DST_PORT(((UDPHdr *)(p->transport_header)))



#endif
