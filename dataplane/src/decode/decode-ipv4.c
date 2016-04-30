#include <sec-common.h>
#include <sec-util.h>
#include <mbuf.h>
#include "decode-ethernet.h"
#include "decode-vlan.h"
#include "decode-ipv4.h"
#include "decode-statistic.h"
#include "decode-defrag.h"
#include "oct-rxtx.h"
#include "dp_log.h"
#include "output.h"
#include "route.h"
#include "dp_attack.h"
#include "dp_cmd.h"


extern int DecodeTCP(mbuf_t *mbuf, uint8_t *pkt, uint16_t len);
extern int DecodeUDP(mbuf_t *mbuf, uint8_t *pkt, uint16_t len);
extern int DecodeICMP(mbuf_t *mbuf, uint8_t *pkt, uint16_t len);







static int DecodeIPV4Packet(mbuf_t *mbuf, uint8_t *pkt, uint16_t len)
{

    if (unlikely(len < IPV4_HEADER_LEN)) {
        STAT_IPV4_HEADER_ERR;
        DP_Log_Func(mbuf);
        return DECODE_DROP;
    }

    if (unlikely(IP_GET_RAW_VER(pkt) != 4)) {
        STAT_IPV4_VERSION_ERR;
        DP_Log_Func(mbuf);
        return DECODE_DROP;
    }

    mbuf->network_header = (void *)pkt;

    if (unlikely(IPV4_GET_HLEN(mbuf) < IPV4_HEADER_LEN)) {
        STAT_IPV4_HEADER_ERR;
        DP_Log_Func(mbuf);
        return DECODE_DROP;
    }

    if (unlikely(IPV4_GET_IPLEN(mbuf) < IPV4_GET_HLEN(mbuf))) {
        STAT_IPV4_LEN_ERR;
        DP_Log_Func(mbuf);
        return DECODE_DROP;
    }

    if (unlikely(len < IPV4_GET_IPLEN(mbuf))) {
        STAT_IPV4_LEN_ERR;
        DP_Log_Func(mbuf);
        return DECODE_DROP;
    }

    mbuf->ipv4.sip = IPV4_GET_IPSRC(mbuf);
    mbuf->ipv4.dip = IPV4_GET_IPDST(mbuf);

    LOGDBG(SEC_IPV4_DBG_BIT, "sip is %d.%d.%d.%d\n",
            mbuf->ipv4.sip >> 24 & 0xff,
            mbuf->ipv4.sip >> 16 & 0xff,
            mbuf->ipv4.sip >> 8 & 0xff,
            mbuf->ipv4.sip & 0xff);
    LOGDBG(SEC_IPV4_DBG_BIT, "dip is %d.%d.%d.%d\n",
            mbuf->ipv4.dip >> 24 & 0xff,
            mbuf->ipv4.dip >> 16 & 0xff,
            mbuf->ipv4.dip >> 8 & 0xff,
            mbuf->ipv4.dip & 0xff);

    /*TODO: DecodeIPV4Options*/

    return DECODE_OK;
}

/*
  *  @mbuf
  *  @pkt:    start of network header
  *  @len:    length of network packet
  */
int DecodeIPV4(mbuf_t *mbuf, uint8_t *pkt, uint16_t len)
{
    int ihl;
    mbuf_t *nmbuf;

    LOGDBG(SEC_IPV4_DBG_BIT, "=========>enter DecodeIPV4()\n");

    if (unlikely(DECODE_OK != DecodeIPV4Packet (mbuf, pkt, len))) {
        return DECODE_DROP;
    }

    mbuf->proto = IPV4_GET_IPPROTO(mbuf);

    nmbuf = mbuf; /*maybe cache or not , so switch it*/

    /* If a fragment, pass off for re-assembly. */
    if(IPV4_IS_FRAGMENT(mbuf) && mbuf->proto != PROTO_OSPF )
    {
        LOGDBG(SEC_DEFRAG_DBG_BIT, "this is a fragment\n");

        ihl = IPV4_GET_HLEN(mbuf);
        mbuf->defrag_id = IPV4_GET_IPID(mbuf);
        mbuf->frag_offset = IPV4_GET_IPOFFSET(mbuf) << 3;
        mbuf->frag_len = len - ihl;

        LOGDBG(SEC_DEFRAG_DBG_BIT, "frag offset is %d, frag len is %d\n", mbuf->frag_offset, mbuf->frag_len);

        if(0 == mbuf->frag_len)
        {
            DP_Log_Func(mbuf);
            STAT_FRAG_LEN_ERR;
            return DECODE_DROP;
        }

        nmbuf = Defrag(mbuf);
        if(NULL == nmbuf)
        {
            return DECODE_OK;
        }
    }

    LOGDBG(SEC_IPV4_DBG_BIT, "protocol is %d\n", nmbuf->proto);

    /* check what next decoder to invoke */
    switch (nmbuf->proto) {
        case PROTO_TCP:
        {
            STAT_IPV4_RECV_OK;
            if(DECODE_OK != DecodeTCP(nmbuf,
                                    (void *)((uint8_t *)(nmbuf->network_header)+ IPV4_GET_HLEN(nmbuf)),
                                    IPV4_GET_IPLEN(nmbuf) - IPV4_GET_HLEN(nmbuf))){
                output_drop_proc(nmbuf);
            }
            return DECODE_OK;
        }
        case PROTO_UDP:
        {
            STAT_IPV4_RECV_OK;

            if(DECODE_OK != DP_Attack_UdpPacketMonitor(nmbuf))
            {
                output_drop_proc(nmbuf);
                return DECODE_OK;
            }

            if(DECODE_OK != DecodeUDP(nmbuf,
                                (void *)((uint8_t *)(nmbuf->network_header)+ IPV4_GET_HLEN(nmbuf)),
                                IPV4_GET_IPLEN(nmbuf) - IPV4_GET_HLEN(nmbuf))){
                output_drop_proc(nmbuf);
            }
            return DECODE_OK;
        }
    #ifdef ROUTE_PROC_ENABLE
        case PROTO_ICMP:
        {

            if(DECODE_OK != DP_Pingdeath_Attack_Monitor(nmbuf))
            {
                output_drop_proc(nmbuf);
                return DECODE_OK;
            }

            if(DECODE_OK != DP_Attack_PingPacketMonitor(nmbuf))
            {
                output_drop_proc(nmbuf);
                return DECODE_OK;
            }

            if(PKTBUF_IS_SW(nmbuf))
            {
                if(PKT_IS_IP_FRAG_COMP(nmbuf))//free ip fragments
                {
                    mbuf_t *head;
                    mbuf_t *next;
                    head = nmbuf->fragments;
                    while(head)
                    {
                        next = head->next;

                        packet_sw2hw(head);
                        if(SEC_OK != oct_pow_se2linux(head))
                        {
                            STAT_IPV4_ICMP_SE2LINUX_FAIL;
                        }
                        else
                        {
                            STAT_IPV4_ICMP_SE2LINUX_OK;
                            STAT_IPV4_RECV_OK;
                        }
                        head = next;
                    }
                    PKT_CLEAR_IP_FRAG_COMP(nmbuf);
                    PACKET_DESTROY_ALL(nmbuf);
                }

                return DECODE_OK;
            }
            else
            {
                if(SEC_OK != oct_pow_se2linux(nmbuf))
                {
                    STAT_IPV4_ICMP_SE2LINUX_FAIL;
                    return DECODE_DROP;
                }
                else
                {
                    STAT_IPV4_ICMP_SE2LINUX_OK;
                    STAT_IPV4_RECV_OK;
                    return DECODE_OK;
                }
            }
        }
        case PROTO_OSPF:
        {
            if(SEC_OK != oct_pow_se2linux(nmbuf))
            {
                STAT_IPV4_OSPF_SE2LINUX_FAIL;
                return DECODE_DROP;
            }
            else
            {
                STAT_IPV4_OSPF_SE2LINUX_OK;
                STAT_L2_RECV_OK;
                return DECODE_OK;
            }
        }
    #endif
        default:
        {
            LOGDBG(SEC_IPV4_DBG_BIT, "unsupport protocol %d\n",IPV4_GET_IPPROTO(nmbuf));
            STAT_IPV4_UNSUPPORT;
        #if 0
            output_fw_proc(nmbuf);
        #else
            Decode_unsupport_proto_handle(nmbuf);
        #endif
            return DECODE_OK;
        }
    }

    return DECODE_OK;
}

