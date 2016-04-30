#include "decode-ethernet.h"
#include "decode-vlan.h"
#include "decode-statistic.h"
#include "mbuf.h"
#include "dp_log.h"
#include "output.h"
#include "route.h"
#include "oct-rxtx.h"
#include "dp_cmd.h"


extern int DecodeIPV4(mbuf_t *mbuf, uint8_t *pkt, uint16_t len);




/*
 * current support  one layer vlan
 *   @mbuf:
 *   @pkt:    start of vlan header
 *   @len:    len of packet from vlan header
 */
int DecodeVLAN(mbuf_t *mb, uint8_t *pkt, uint16_t len)
{
    uint32_t proto;
    VLANHdr *pvh;

    if(len < VLAN_HEADER_LEN)
    {
        STAT_VLAN_HEADER_ERR;
        DP_Log_Func(mb);
        return DECODE_DROP;
    }

    if (mb->vlan_idx >= 1)
    {
        STAT_VLAN_LAYER_EXCEED;
        return DECODE_DROP;
    }

    mb->vlanh = (void *)pkt;
    pvh = (VLANHdr *)(pkt);

    proto = GET_VLAN_PROTO(pvh);

    mb->vlan_idx = 1;

    switch (proto) {
        case ETHERNET_TYPE_IP:
        {
            STAT_VLAN_RECV_OK;
            return DecodeIPV4(mb, pkt + VLAN_HEADER_LEN, len - VLAN_HEADER_LEN);
        }
#ifdef ROUTE_PROC_ENABLE
        case ETHERNET_TYPE_ARP:
        {
            if(SEC_OK != oct_pow_se2linux(mb))
            {
                STAT_VLAN_ARP_SE2LINUX_FAIL;
                return DECODE_DROP;
            }
            else
            {
                STAT_VLAN_ARP_SE2LINUX_OK;
                STAT_VLAN_RECV_OK;
                return DECODE_OK;
            }
        }
#endif
        case ETHERNET_TYPE_VLAN:
        case ETHERNET_TYPE_8021QINQ:
        {
            STAT_VLAN_RECV_OK;
            return DecodeVLAN(mb, pkt + VLAN_HEADER_LEN, len - VLAN_HEADER_LEN);
        }
        default:
            LOGDBG(SEC_ETHERNET_DBG_BIT, "vlan:ether type %04x not supported", proto);
            STAT_VLAN_UNSUPPORT;
        #if 0
            output_fw_proc(mb);
        #else
            Decode_unsupport_proto_handle(mb);
        #endif
            return DECODE_OK;
    }

    STAT_VLAN_RECV_OK;
    return DECODE_OK;
}

