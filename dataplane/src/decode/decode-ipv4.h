#ifndef __DECODE_IPV4_H__
#define __DECODE_IPV4_H__

#include <mbuf.h>
#include "decode.h"


/* IP flags. */
#define IP_CE       0x8000      /* Flag: "Congestion"       */
#define IP_DF       0x4000      /* Flag: "Don't Fragment"   */
#define IP_MF       0x2000      /* Flag: "More Fragments"   */
#define IP_OFFSET   0x1FFF      /* "Fragment Offset" part   */


#define IPV4_HEADER_LEN           20    /**< Header length */

#define IPV4_PKTLEN_MAX    65535


typedef struct IPV4Hdr_
{
    uint8_t ip_verhl;     /**< version & header length */
    uint8_t ip_tos;       /**< type of service */
    uint16_t ip_len;      /**< length */
    uint16_t ip_id;       /**< id */
    uint16_t ip_off;      /**< frag offset */
    uint8_t ip_ttl;       /**< time to live */
    uint8_t ip_proto;     /**< protocol (tcp, udp, etc) */
    uint16_t ip_csum;     /**< checksum */
    uint32_t src_addr;      /**< source address */
    uint32_t dst_addr;      /**< destination address */
} IPV4Hdr;


#define IPV4_GET_RAW_VER(ip4h)            (((ip4h)->ip_verhl & 0xf0) >> 4)
#define IPV4_GET_RAW_HLEN(ip4h)           ((ip4h)->ip_verhl & 0x0f)
#define IPV4_GET_RAW_IPTOS(ip4h)          ((ip4h)->ip_tos)
#define IPV4_GET_RAW_IPLEN(ip4h)          ((ip4h)->ip_len)
#define IPV4_GET_RAW_IPID(ip4h)           ((ip4h)->ip_id)
#define IPV4_GET_RAW_IPOFFSET(ip4h)       ((ip4h)->ip_off)
#define IPV4_GET_RAW_IPTTL(ip4h)          ((ip4h)->ip_ttl)
#define IPV4_GET_RAW_IPPROTO(ip4h)        ((ip4h)->ip_proto)
#define IPV4_GET_RAW_IPSRC(ip4h)          ((ip4h)->src_addr)
#define IPV4_GET_RAW_IPDST(ip4h)          ((ip4h)->dst_addr)

/* ONLY call these functions after making sure that:
 * 1. p->ip4h is set
 * 2. p->ip4h is valid (len is correct)
 */
#define IPV4_GET_VER(p) \
    IPV4_GET_RAW_VER((IPV4Hdr *)((p)->network_header))
#define IPV4_GET_HLEN(p) \
    (IPV4_GET_RAW_HLEN((IPV4Hdr *)((p)->network_header)) << 2)
#define IPV4_GET_IPTOS(p) \
    IPV4_GET_RAW_IPTOS((IPV4Hdr *)((p)->network_header))
#define IPV4_GET_IPLEN(p) \
    IPV4_GET_RAW_IPLEN((IPV4Hdr *)((p)->network_header))
#define IPV4_GET_IPSRC(p) \
    (IPV4_GET_RAW_IPSRC((IPV4Hdr *)((p)->network_header)))
#define IPV4_GET_IPDST(p) \
    (IPV4_GET_RAW_IPDST((IPV4Hdr *)((p)->network_header)))
#define IPV4_GET_IPID(p) \
   (IPV4_GET_RAW_IPID((IPV4Hdr *)((p)->network_header)))
/* _IPV4_GET_IPOFFSET: get the content of the offset header field in host order */
#define _IPV4_GET_IPOFFSET(p) \
    IPV4_GET_RAW_IPOFFSET((IPV4Hdr *)((p)->network_header))


/* IPV4_GET_IPOFFSET: get the final offset */
#define IPV4_GET_IPOFFSET(p) \
    (_IPV4_GET_IPOFFSET(p) & 0x1fff)
/* IPV4_GET_RF: get the RF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_RF(p) \
    (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x8000) >> 15)
/* IPV4_GET_DF: get the DF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_DF(p) \
    (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x4000) >> 14)
/* IPV4_GET_MF: get the MF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_MF(p) \
    (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x2000) >> 13)
#define IPV4_GET_IPTTL(p) \
     IPV4_GET_RAW_IPTTL((IPV4Hdr *)(p->network_header))
#define IPV4_GET_IPPROTO(p) \
    IPV4_GET_RAW_IPPROTO((IPV4Hdr *)((p)->network_header))


#define IPV4_SET_RAW_VER(ip4h, value)     ((ip4h)->ip_verhl = (((ip4h)->ip_verhl & 0x0f) | (value << 4)))
#define IPV4_SET_RAW_HLEN(ip4h, value)    ((ip4h)->ip_verhl = (((ip4h)->ip_verhl & 0xf0) | (value & 0x0f)))
#define IPV4_SET_RAW_IPTOS(ip4h, value)   ((ip4h)->ip_tos = value)
#define IPV4_SET_RAW_IPLEN(ip4h, value)   ((ip4h)->ip_len = value)
#define IPV4_SET_RAW_IPPROTO(ip4h, value) ((ip4h)->ip_proto = value)
#define IPV4_SET_RAW_IPCSUM(ip4h, value) ((ip4h)->ip_csum = value)


#define IPV4_SET_IPLEN(p, value) \
    IPV4_SET_RAW_IPLEN((IPV4Hdr *)(p->network_header), value)

#define IPV4_SET_IPCSUM(p, value) \
    IPV4_SET_RAW_IPCSUM((IPV4Hdr *)(p->network_header), value)







#define IPV4_IS_FRAGMENT(p) \
    (IPV4_GET_IPOFFSET(p) > 0 || IPV4_GET_MF(p) == 1)


#define PROTO_ICMP       1
#define PROTO_TCP        6  /**< tcp */
#define PROTO_UDP       17  /**< user datagram protocol */
#define PROTO_OSPF      89


static inline uint16_t IPV4CalculateChecksum(uint16_t *pkt, uint16_t hlen)
{
    uint32_t csum = pkt[0];

    csum += pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[6] + pkt[7] + pkt[8] +
        pkt[9];

    hlen -= 20;
    pkt += 10;

    if (hlen == 0) {
        ;
    } else if (hlen == 4) {
        csum += pkt[0] + pkt[1];
    } else if (hlen == 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
    } else if (hlen == 12) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5];
    } else if (hlen == 16) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7];
    } else if (hlen == 20) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9];
    } else if (hlen == 24) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11];
    } else if (hlen == 28) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13];
    } else if (hlen == 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15];
    } else if (hlen == 36) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15] + pkt[16] + pkt[17];
    } else if (hlen == 40) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15] + pkt[16] + pkt[17] + pkt[18] + pkt[19];
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t) ~csum;
}



extern int DecodeIPV4(mbuf_t *mbuf, uint8_t *pkt, uint16_t len);




#endif