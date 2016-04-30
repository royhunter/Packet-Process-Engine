#include "sec-common.h"
#include <mbuf.h>
#include <sec-util.h>
#include "decode.h"


#include "decode-ethernet.h"
#include "decode-vlan.h"
#include "decode-ipv4.h"
#include "decode-statistic.h"
#include "dp_log.h"
#include "oct-rxtx.h"
#include "output.h"
#include "route.h"
#include "dp_cmd.h"


/*
  *   @mbuf:
  *   @pkt:    start of l2 header
  *   @len:    len of l2 packet
  */
int DecodeEthernet(mbuf_t *mbuf, uint8_t *pkt, uint16_t len)
{
    EthernetHdr *pethh;

    LOGDBG(SEC_ETHERNET_DBG_BIT, "==============>enter DecodeEthernet\n");

    if (unlikely(len < ETHERNET_HEADER_LEN))
    {
        STAT_L2_HEADER_ERR;
        DP_Log_Func(mbuf);
        return DECODE_DROP;
    }

    pethh = (EthernetHdr *)(pkt);

    if((0 == pethh->eth_dst[0]
        && 0 == pethh->eth_dst[1]
        && 0 == pethh->eth_dst[2]
        && 0 == pethh->eth_dst[3]
        && 0 == pethh->eth_dst[4]
        && 0 == pethh->eth_dst[5]) ||
        (0 == pethh->eth_src[0]
        && 0 == pethh->eth_src[1]
        && 0 == pethh->eth_src[2]
        && 0 == pethh->eth_src[3]
        && 0 == pethh->eth_src[4]
        && 0 == pethh->eth_src[5]))
    {
        STAT_L2_HEADER_ERR;
        DP_Log_Func(mbuf);
        return DECODE_DROP;
    }


    mbuf->ethh = (void *)pethh;

    LOGDBG(SEC_ETHERNET_DBG_BIT, "dst mac is %x:%x:%x:%x:%x:%x\n",
        pethh->eth_dst[0],pethh->eth_dst[1],
        pethh->eth_dst[2],pethh->eth_dst[3],
        pethh->eth_dst[4],pethh->eth_dst[5]);

    LOGDBG(SEC_ETHERNET_DBG_BIT, "src mac is %x:%x:%x:%x:%x:%x\n",
        pethh->eth_src[0],pethh->eth_src[1],
        pethh->eth_src[2],pethh->eth_src[3],
        pethh->eth_src[4],pethh->eth_src[5]);

    LOGDBG(SEC_ETHERNET_DBG_BIT, "eth type is 0x%x\n", pethh->eth_type);

    memcpy(mbuf->eth_dst, pethh->eth_dst, 6);
    memcpy(mbuf->eth_src, pethh->eth_src, 6);

    switch (pethh->eth_type) {
        case ETHERNET_TYPE_IP:
        {
            STAT_L2_RECV_OK;
            return DecodeIPV4(mbuf, pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);
        }
    #ifdef ROUTE_PROC_ENABLE
        case ETHERNET_TYPE_ARP:
        {
            if(SEC_OK != oct_pow_se2linux(mbuf))
            {
                STAT_L2_ARP_SE2LINUX_FAIL;
                return DECODE_DROP;
            }
            else
            {
                STAT_L2_ARP_SE2LINUX_OK;
                STAT_L2_RECV_OK;
                return DECODE_OK;
            }
        }
    #endif
        case ETHERNET_TYPE_VLAN:
        case ETHERNET_TYPE_8021QINQ:
        {
            STAT_L2_RECV_OK;
            return DecodeVLAN(mbuf, pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);
        }
        default:
        {
            LOGDBG(SEC_ETHERNET_DBG_BIT, "ether type %04x not supported", pethh->eth_type);
            STAT_L2_UNSUPPORT;
        #if 0
            output_fw_proc(mbuf);
        #endif
            Decode_unsupport_proto_handle(mbuf);
            return DECODE_OK;
        }
    }

    return DECODE_OK;
}

