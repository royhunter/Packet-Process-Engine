#ifndef __DECODE_VLAN_H__
#define __DECODE_VLAN_H__
#include <sec-common.h>
#include <decode.h>
#include <mbuf.h>


#define ETHERNET_TYPE_VLAN          0x8100
/** Vlan header struct */
typedef struct VLANHdr_ {
    uint16_t vlan_cfi;
    uint16_t protocol;  /**< protocol field */
} VLANHdr;

/** VLAN header length */
#define VLAN_HEADER_LEN 4


#define GET_VLAN_PROTO(vlanh)       ((vlanh)->protocol)


extern int DecodeVLAN(mbuf_t *mbuf, uint8_t *pkt, uint16_t len);

#endif
