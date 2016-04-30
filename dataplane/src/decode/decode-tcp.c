#include <mbuf.h>
#include <sec-common.h>
#include "decode.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"
#include "decode-statistic.h"
#include <dp_acl.h>
#include <flow.h>
#include "dp_log.h"
#include "output.h"
#include <dp_attack.h>


extern int StreamTcpPacket(mbuf_t *mbuf);



static int DecodeTCPOptions(mbuf_t *m, uint8_t *pkt, uint16_t len)
{

    TCPOpt tcp_opts[TCP_OPTMAX];
    uint8_t tcp_opt_cnt = 0;

    uint16_t plen = len;
    while (plen)
    {
        /* single byte options */
        if (*pkt == TCP_OPT_EOL) {
            break;
        } else if (*pkt == TCP_OPT_NOP) {
            pkt++;
            plen--;

        /* multibyte options */
        } else {
            if (plen < 2) {
                break;
            }

            /* we already know that the total options len is valid,
             * so here the len of the specific option must be bad.
             * Also check for invalid lengths 0 and 1. */
            if (unlikely(*(pkt+1) > plen || *(pkt+1) < 2)) {
                //ENGINE_SET_INVALID_EVENT(p, TCP_OPT_INVALID_LEN);
                return -1;
            }

            tcp_opts[tcp_opt_cnt].type = *pkt;
            tcp_opts[tcp_opt_cnt].len  = *(pkt+1);
            if (plen > 2)
                tcp_opts[tcp_opt_cnt].data = (pkt+2);
            else
                tcp_opts[tcp_opt_cnt].data = NULL;

            /* we are parsing the most commonly used opts to prevent
             * us from having to walk the opts list for these all the
             * time. */
            switch (tcp_opts[tcp_opt_cnt].type) {
                case TCP_OPT_WS:
                    if (tcp_opts[tcp_opt_cnt].len != TCP_OPT_WS_LEN) {
                        //ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (m->tcpvars.ws != NULL) {
                            //ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            m->TCP_OPTS[0].type = tcp_opts[tcp_opt_cnt].type;
                            m->TCP_OPTS[0].len = tcp_opts[tcp_opt_cnt].len;
                            m->TCP_OPTS[0].data = tcp_opts[tcp_opt_cnt].data;
                            m->tcpvars.ws = &m->TCP_OPTS[0];
                        }
                    }
                    break;
            #if 0
                case TCP_OPT_MSS:
                    if (m->TCP_OPTS[m->TCP_OPTS_CNT].len != TCP_OPT_MSS_LEN) {
                        //ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (m->tcpvars.mss != NULL) {
                            //ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            m->tcpvars.mss = &m->TCP_OPTS[m->TCP_OPTS_CNT];
                        }
                    }
                    break;
                case TCP_OPT_SACKOK:
                    if (m->TCP_OPTS[m->TCP_OPTS_CNT].len != TCP_OPT_SACKOK_LEN) {
                        //ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (m->tcpvars.sackok != NULL) {
                            //ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            m->tcpvars.sackok = &m->TCP_OPTS[m->TCP_OPTS_CNT];
                        }
                    }
                    break;
                case TCP_OPT_TS:
                    if (m->TCP_OPTS[m->TCP_OPTS_CNT].len != TCP_OPT_TS_LEN) {
                        //ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (m->tcpvars.ts != NULL) {
                            //ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            m->tcpvars.ts = &m->TCP_OPTS[m->TCP_OPTS_CNT];
                        }
                    }
                    break;
                case TCP_OPT_SACK:
                    LOGDBG(SEC_TCP_DBG_BIT, "SACK option, len %u", m->TCP_OPTS[m->TCP_OPTS_CNT].len);
                    if (m->TCP_OPTS[m->TCP_OPTS_CNT].len < TCP_OPT_SACK_MIN_LEN ||
                            m->TCP_OPTS[m->TCP_OPTS_CNT].len > TCP_OPT_SACK_MAX_LEN ||
                            !((m->TCP_OPTS[m->TCP_OPTS_CNT].len - 2) % 8 == 0))
                    {
                        //ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (m->tcpvars.sack != NULL) {
                            //ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            m->tcpvars.sack = &m->TCP_OPTS[m->TCP_OPTS_CNT];
                        }
                    }
                    break;
            #endif
            }

            pkt += tcp_opts[tcp_opt_cnt].len;
            plen -= (tcp_opts[tcp_opt_cnt].len);
            tcp_opt_cnt++;
        }
    }
    return 0;
}



static int DecodeTCPPacket(mbuf_t *mbuf, uint8_t *pkt, uint16_t len)
{
    uint8_t hlen;
    uint8_t tcp_opt_len;

    if (unlikely(len < TCP_HEADER_LEN)) {
        STAT_TCP_HEADER_ERR;
        DP_Log_Func(mbuf);
        return DECODE_DROP;
    }

    mbuf->transport_header = (void *)pkt;

    hlen = TCP_GET_HLEN(mbuf);
    if (unlikely(len < hlen)) {
        STAT_TCP_LEN_ERR;
        DP_Log_Func(mbuf);
        return DECODE_DROP;
    }

    tcp_opt_len = hlen - TCP_HEADER_LEN;
    if (unlikely(tcp_opt_len > TCP_OPTLENMAX)) {
        STAT_TCP_LEN_ERR;
        DP_Log_Func(mbuf);
        return DECODE_DROP;
    }

    if(TCP_IS_SYN(mbuf))
    {
        if(DECODE_DROP == DP_Land_Attack_Monitor(mbuf))
        {
            return DECODE_DROP;
        }

        if(DECODE_DROP == DP_Attack_SynPacketMonitor(mbuf))
        {
            return DECODE_DROP;
        }
    }

    if (likely(tcp_opt_len > 0)) {
        DecodeTCPOptions(mbuf, pkt + TCP_HEADER_LEN, tcp_opt_len);
    }

    mbuf->sport = TCP_GET_SRC_PORT(mbuf);
    mbuf->dport = TCP_GET_DST_PORT(mbuf);

    LOGDBG(SEC_TCP_DBG_BIT, "src port is %d\n", mbuf->sport);
    LOGDBG(SEC_TCP_DBG_BIT, "dst port is %d\n", mbuf->dport);
    LOGDBG(SEC_TCP_DBG_BIT, "core %d, tag is 0x%x\n", LOCAL_CPU_ID, mbuf->tag);

    mbuf->payload = pkt + hlen;
    mbuf->payload_len = len - hlen;

    return DECODE_OK;
}


/*
  *  @mbuf
  *  @pkt:    start of transport header
  *  @len:    length of transport packet
  */
int DecodeTCP(mbuf_t *mbuf, uint8_t *pkt, uint16_t len)
{

    LOGDBG(SEC_TCP_DBG_BIT, "\n=========>enter DecodeTCP\n");

    if (unlikely(DecodeTCPPacket(mbuf, pkt, len) != DECODE_OK)) {
        return DECODE_DROP;
    }

    STAT_TCP_RECV_OK;

#if 0
    if(ACL_RULE_ACTION_DROP == DP_Acl_Lookup(mbuf))
    {
        STAT_ACL_DROP;
        output_drop_proc(mbuf);
        return DECODE_OK;
    }

    STAT_ACL_FW;
#endif

    FlowHandlePacket(mbuf);

    return DECODE_OK;
}
