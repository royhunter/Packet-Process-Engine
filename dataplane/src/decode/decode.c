#include <sec-common.h>
#include <decode.h>
#include <mbuf.h>
#include "output.h"
#include <dp_cmd.h>
#include <decode-ethernet.h>
#include <decode-ipv4.h>

extern uint32_t unsupport_proto_action;
extern int DecodeEthernet(mbuf_t *mbuf, uint8_t *pkt, uint16_t len);


/*
 * decode pakcet l2->l3->l4
 * if result is DECODE_OK, not need to free anything, the packet data will pass to the next module
 * if result is DECODE_DROP, decode function must destroy the packet data,include packet buffer and mbuf
 */

void Decode(mbuf_t *m)
{
    LOGDBG(SEC_DECODE_DBG_BIT, "==========>enter decode()\n");
	if( DECODE_OK != DecodeEthernet(m, GET_PKT_DATA(m), GET_PKT_LEN(m)))
    {
        output_drop_proc(m);
    }

	return;
}


void Decode_unsupport_proto_handle(mbuf_t *mbuf)
{
    if(unsupport_proto_action == 1)/*fw*/
    {
        output_fw_proc(mbuf);
    }
    else if(unsupport_proto_action == 0)/*drop*/
    {
        output_drop_proc(mbuf);
    }
    else
    {
        printf("Decode_unsupport_proto_handle error action\n");
    }
}


void test_packet_send(void)
{
    mbuf_t *m = MBUF_CREATE(100);
    EthernetHdr *pethh = (EthernetHdr *)m->pkt_ptr;

    pethh->eth_dst[0] = 0x1;
    pethh->eth_dst[1] = 0x2;
    pethh->eth_dst[2] = 0x3;
    pethh->eth_dst[3] = 0x4;
    pethh->eth_dst[4] = 0x5;
    pethh->eth_dst[5] = 0x6;
    pethh->eth_src[0] = 0x1;
    pethh->eth_src[1] = 0x6;
    pethh->eth_src[2] = 0x5;
    pethh->eth_src[3] = 0x4;
    pethh->eth_src[4] = 0x3;
    pethh->eth_src[5] = 0x2;
    pethh->eth_type = 0x33;

    IPV4Hdr *iph = (IPV4Hdr *)((uint8_t *)(m->pkt_ptr) + sizeof(EthernetHdr));
    iph->dst_addr = 0x01010101;
    iph->src_addr = 0x04040404;

    oct_tx_process_sw(m, 0);

}


