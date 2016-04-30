#ifndef __DECODE_STATISTIC_H__
#define __DECODE_STATISTIC_H__

#include <sec-common.h>
#include <oct-common.h>


struct recv_count
{
    uint64_t recv_packet_count;
    uint64_t recv_packet_bytes;

    uint64_t recv_packet_count_sum;
    uint64_t recv_packet_bytes_sum;
};

struct rx_stat
{
    uint64_t grp_err;
    uint64_t rx_fromhwport_err;
    uint64_t rx_fromlinux_err;
    uint64_t addr_err;
    uint64_t rx_fromhwport_ok;
    uint64_t rx_fromlinux_ok;
};

struct ether_stat
{
    uint64_t headerlen_err;
    uint64_t unsupport;
    uint64_t rx_ok;
    uint64_t arp_se2linux_ok;
    uint64_t arp_se2linux_fail;
};

struct vlan_stat
{
    uint64_t headerlen_err;
    uint64_t vlanlayer_exceed;
    uint64_t unsupport;
    uint64_t rx_ok;
    uint64_t arp_se2linux_fail;
    uint64_t arp_se2linux_ok;
};

struct ipv4_stat
{
    uint64_t headerlen_err;
    uint64_t version_err;
    uint64_t pktlen_err;
    uint64_t unsupport;
    uint64_t rx_ok;
    uint64_t icmp_se2linux_ok;
    uint64_t icmp_se2linux_fail;
    uint64_t ospf_se2linux_ok;
    uint64_t ospf_se2linux_fail;
};

struct icmp_stat
{
    uint64_t rx_ok;
    uint64_t drop;
};

struct frag_stat
{
    uint64_t fraglen_err;
    uint64_t fcb_no;
    uint64_t hw2sw_err;
    uint64_t fcb_full;
    uint64_t cache_full;
    uint64_t defrag_err;
    uint64_t setup_err;
    uint64_t out_oversize;
    uint64_t cache_ok;
    uint64_t reasm_ok;
};

struct udp_stat
{
    uint64_t headerlen_err;
    uint64_t pktlen_err;
    uint64_t rx_ok;
};

struct tcp_stat
{
    uint64_t headerlen_err;
    uint64_t pktlen_err;
    uint64_t rx_ok;
};

struct acl_stat
{
    uint64_t drop;
    uint64_t fw;
};


struct flow_stat
{
    uint64_t node_nomem;
    uint64_t proc_ok;
    uint64_t proc_fail;
    uint64_t proc_drop;
    uint64_t tcp_no_syn_first;
};

struct tx_stat
{
    uint64_t port_err;
    uint64_t hw_send_err;
    uint64_t sw_desc_err;
    uint64_t sw_send_err;
    uint64_t send_over;
};

struct tcpstream_track_stat
{
    uint64_t SYN_ACK_COUNT;
    uint64_t SYN_COUNT;
    uint64_t RST_COUNT;
    uint64_t RST_BUT_NO_SESSION;
    uint64_t FIN_BUT_NO_SESSION;
    uint64_t MIDSTREAM_OR_ONESIDE_DISABLE;
    uint64_t MIDSTREAM_DISABLE;
    uint64_t ONESIDE_DISABLE;
    uint64_t SESSION_NO_MEM;
    uint64_t FIN_INVALID_ACK;
    uint64_t FIN_OUT_OF_WINDOW;
    uint64_t SESSION_PARAM_ERR;
    uint64_t WHS3_SYNACK_TOSERVER_SYN_RECV;
    uint64_t WHS3_SYNACK_SEQ_MISMATCH;
    uint64_t WHS3_SYNACK_RESEND_WITH_DIFFERENT_ACK;
    uint64_t WHS3_SYN_TOCLIENT_ON_SYN_RECV;
    uint64_t WHS3_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV;
    uint64_t WHS3_SYNACK_IN_WRONG_DIRECTION;
    uint64_t WHS3_ACK_IN_WRONG_DIR;
    uint64_t WHS3_RIGHT_SEQ_WRONG_ACK_EVASION;
    uint64_t WHS3_WRONG_SEQ_WRONG_ACK;
    uint64_t WHS3_ASYNC_WRONG_SEQ;
    uint64_t WHS3_SYNACK_WITH_WRONG_ACK;
    uint64_t WHS4_WRONG_SEQ;
    uint64_t WHS4_INVALID_ACK;
    uint64_t WHS4_SYNACK_WITH_WRONG_ACK;
    uint64_t WHS4_SYNACK_WITH_WRONG_SYN;
    uint64_t EST_INVALID_ACK;
    uint64_t EST_PKT_BEFORE_LAST_ACK;
    uint64_t EST_PACKET_OUT_OF_WINDOW;
    uint64_t EST_SYNACK_RESEND;
    uint64_t EST_SYNACK_TOSERVER;
    uint64_t EST_SYNACK_RESEND_WITH_DIFFERENT_ACK;
    uint64_t EST_SYNACK_RESEND_WITH_DIFF_SEQ;
    uint64_t EST_SYN_TOCLIENT;
    uint64_t EST_SYN_RESEND_DIFF_SEQ;
    uint64_t EST_SYN_RESEND;
    uint64_t PKT_RETRANSMISSION;
    uint64_t FIN2_FIN_WRONG_SEQ;
    uint64_t FIN2_INVALID_ACK;
    uint64_t FIN2_ACK_WRONG_SEQ;
    uint64_t FIN1_FIN_WRONG_SEQ;
    uint64_t FIN1_INVALID_ACK;
    uint64_t FIN1_ACK_WRONG_SEQ;
    uint64_t SHUTDOWN_SYN_RESEND;
    uint64_t CLOSEWAIT_FIN_OUT_OF_WINDOW;
    uint64_t CLOSING_ACK_WRONG_SEQ;
    uint64_t CLOSEWAIT_INVALID_ACK;
    uint64_t CLOSING_INVALID_ACK;
    uint64_t CLOSEWAIT_PKT_BEFORE_LAST_ACK;
    uint64_t CLOSEWAIT_ACK_OUT_OF_WINDOW;
    uint64_t LASTACK_ACK_WRONG_SEQ;
    uint64_t LASTACK_INVALID_ACK;
    uint64_t TIMEWAIT_ACK_WRONG_SEQ;
    uint64_t TIMEWAIT_INVALID_ACK;
    uint64_t PKT_INVALID_ACK;
    uint64_t PKT_BAD_WINDOW_UPDATE;
    uint64_t PKT_BROKEN_ACK;

};

struct tcpstream_reasm_stat {
    uint64_t REASM_BEFORE_RA_BASE;
    uint64_t REASM_SEG_NO_MEM;
    uint64_t REASM_HW2SW_ERR;
    uint64_t REASM_CACHE;
    uint64_t REASM_NO_NEED_REASM;
    uint64_t REASM_SETUP_FAIL;
    uint64_t REASM_OK;
    uint64_t REASM_OVERLAP;
};


struct output_stat {
    uint64_t output_fw;
    uint64_t output_drop;
    uint64_t output_cache;
    uint64_t output_unsupport;
};

struct att_stat{
    uint64_t land;
    uint64_t teardrop;
    uint64_t pingdeath;
    uint64_t pingspeed;
    uint64_t udpspeed;
    uint64_t synspeed;
    uint64_t syncount;
    uint64_t portscan_drop;
};


typedef struct
{
    struct recv_count rc;
    struct rx_stat    rxstat;
    struct ether_stat l2stat;
    struct vlan_stat  vlanstat;
    struct ipv4_stat  ipv4stat;
    struct icmp_stat  icmpstat;
    struct frag_stat  fragstat;
    struct udp_stat   udpstat;
    struct tcp_stat   tcpstat;
    struct acl_stat   aclstat;
    struct flow_stat  flowstat;
    struct tcpstream_track_stat tcpstreamtrackstat;
    struct tcpstream_reasm_stat tcpstreamreasmstat;
    struct output_stat outputstat;
    struct tx_stat    txstat;
    struct att_stat   attstat;
}pkt_stat;


#define PKT_STAT_MEM_NAME "pkt-statistic"


extern pkt_stat *pktstat[];


#define STAT_RECV_PC_ADD        do { pktstat[LOCAL_CPU_ID]->rc.recv_packet_count++; pktstat[LOCAL_CPU_ID]->rc.recv_packet_count_sum++; } while (0)
#define STAT_RECV_PB_ADD(bytes) do { pktstat[LOCAL_CPU_ID]->rc.recv_packet_bytes += bytes; pktstat[LOCAL_CPU_ID]->rc.recv_packet_bytes_sum += bytes; } while (0)

#define STAT_RECV_GRP_ERR       do { pktstat[LOCAL_CPU_ID]->rxstat.grp_err++; } while(0)
#define STAT_RECV_FROMHWPORT_ERR      do { pktstat[LOCAL_CPU_ID]->rxstat.rx_fromhwport_err++; } while(0)
#define STAT_RECV_FROMLINUX_ERR      do { pktstat[LOCAL_CPU_ID]->rxstat.rx_fromlinux_err++; } while(0)
#define STAT_RECV_ADDR_ERR do { pktstat[LOCAL_CPU_ID]->rxstat.addr_err++; } while(0)
#define STAT_RECV_FROMLINUX_OK       do { pktstat[LOCAL_CPU_ID]->rxstat.rx_fromlinux_ok++;} while(0)
#define STAT_RECV_FROMHWPORT_OK       do { pktstat[LOCAL_CPU_ID]->rxstat.rx_fromhwport_ok++;} while(0)


#define STAT_L2_HEADER_ERR do { pktstat[LOCAL_CPU_ID]->l2stat.headerlen_err++;} while(0)
#define STAT_L2_UNSUPPORT  do { pktstat[LOCAL_CPU_ID]->l2stat.unsupport++;} while(0)
#define STAT_L2_RECV_OK    do { pktstat[LOCAL_CPU_ID]->l2stat.rx_ok++;} while(0)
#define STAT_L2_ARP_SE2LINUX_OK    do { pktstat[LOCAL_CPU_ID]->l2stat.arp_se2linux_ok++;} while(0)
#define STAT_L2_ARP_SE2LINUX_FAIL    do { pktstat[LOCAL_CPU_ID]->l2stat.arp_se2linux_fail++;} while(0)

#define STAT_VLAN_HEADER_ERR     do { pktstat[LOCAL_CPU_ID]->vlanstat.headerlen_err++;} while(0)
#define STAT_VLAN_LAYER_EXCEED   do { pktstat[LOCAL_CPU_ID]->vlanstat.vlanlayer_exceed++;} while(0)
#define STAT_VLAN_UNSUPPORT      do { pktstat[LOCAL_CPU_ID]->vlanstat.unsupport++;} while(0)
#define STAT_VLAN_RECV_OK        do { pktstat[LOCAL_CPU_ID]->vlanstat.rx_ok++;} while(0)
#define STAT_VLAN_ARP_SE2LINUX_FAIL do { pktstat[LOCAL_CPU_ID]->vlanstat.arp_se2linux_fail++;} while(0)
#define STAT_VLAN_ARP_SE2LINUX_OK    do { pktstat[LOCAL_CPU_ID]->vlanstat.arp_se2linux_ok++;} while(0)


#define STAT_IPV4_HEADER_ERR     do { pktstat[LOCAL_CPU_ID]->ipv4stat.headerlen_err++;} while(0)
#define STAT_IPV4_VERSION_ERR    do { pktstat[LOCAL_CPU_ID]->ipv4stat.version_err++;} while(0)
#define STAT_IPV4_LEN_ERR        do { pktstat[LOCAL_CPU_ID]->ipv4stat.pktlen_err++;} while(0)
#define STAT_IPV4_UNSUPPORT      do { pktstat[LOCAL_CPU_ID]->ipv4stat.unsupport++;} while(0)
#define STAT_IPV4_RECV_OK        do { pktstat[LOCAL_CPU_ID]->ipv4stat.rx_ok++;} while(0)
#define STAT_IPV4_ICMP_SE2LINUX_OK     do { pktstat[LOCAL_CPU_ID]->ipv4stat.icmp_se2linux_ok++;} while(0)
#define STAT_IPV4_ICMP_SE2LINUX_FAIL   do { pktstat[LOCAL_CPU_ID]->ipv4stat.icmp_se2linux_fail++;} while(0)
#define STAT_IPV4_OSPF_SE2LINUX_OK     do { pktstat[LOCAL_CPU_ID]->ipv4stat.ospf_se2linux_ok++;} while(0)
#define STAT_IPV4_OSPF_SE2LINUX_FAIL   do { pktstat[LOCAL_CPU_ID]->ipv4stat.ospf_se2linux_fail++;} while(0)


#define STAT_ICMP_RECV_OK        do { pktstat[LOCAL_CPU_ID]->icmpstat.rx_ok++;} while(0)
#define STAT_ICMP_DROP        do { pktstat[LOCAL_CPU_ID]->icmpstat.drop++;} while(0)


#define STAT_FRAG_LEN_ERR        do { pktstat[LOCAL_CPU_ID]->fragstat.fraglen_err++; } while(0)
#define STAT_FRAG_FCB_NO         do { pktstat[LOCAL_CPU_ID]->fragstat.fcb_no++; } while(0)
#define STAT_FRAG_HW2SW_ERR      do { pktstat[LOCAL_CPU_ID]->fragstat.hw2sw_err++; } while(0)
#define STAT_FRAG_FCB_FULL       do { pktstat[LOCAL_CPU_ID]->fragstat.fcb_full++; } while(0)
#define STAT_FRAG_CACHE_FULL     do { pktstat[LOCAL_CPU_ID]->fragstat.cache_full++; } while(0)
#define STAT_FRAG_DEFRAG_ERR     do { pktstat[LOCAL_CPU_ID]->fragstat.defrag_err++; } while(0)
#define STAT_FRAG_SETUP_ERR     do { pktstat[LOCAL_CPU_ID]->fragstat.setup_err++; } while(0)
#define STAT_FRAG_OUT_OVERSIZE     do { pktstat[LOCAL_CPU_ID]->fragstat.out_oversize++; } while(0)

#define STAT_FRAG_REASM_OK       do { pktstat[LOCAL_CPU_ID]->fragstat.reasm_ok++; } while(0)
#define STAT_FRAG_CACHE_OK       do { pktstat[LOCAL_CPU_ID]->fragstat.cache_ok++; } while(0)


#define STAT_UDP_HEADER_ERR      do { pktstat[LOCAL_CPU_ID]->udpstat.headerlen_err++;} while(0)
#define STAT_UDP_LEN_ERR         do { pktstat[LOCAL_CPU_ID]->udpstat.pktlen_err++;} while(0)
#define STAT_UDP_RECV_OK         do { pktstat[LOCAL_CPU_ID]->udpstat.rx_ok++;} while(0)


#define STAT_TCP_HEADER_ERR      do { pktstat[LOCAL_CPU_ID]->tcpstat.headerlen_err++;} while(0)
#define STAT_TCP_LEN_ERR         do { pktstat[LOCAL_CPU_ID]->tcpstat.pktlen_err++;} while(0)
#define STAT_TCP_RECV_OK         do { pktstat[LOCAL_CPU_ID]->tcpstat.rx_ok++;} while(0)

#define STAT_ACL_DROP            do { pktstat[LOCAL_CPU_ID]->aclstat.drop++;} while(0)
#define STAT_ACL_FW              do { pktstat[LOCAL_CPU_ID]->aclstat.fw++;} while(0)

#define STAT_FLOW_NODE_NOMEM     do { pktstat[LOCAL_CPU_ID]->flowstat.node_nomem++;} while(0)
#define STAT_FLOW_PROC_OK        do { pktstat[LOCAL_CPU_ID]->flowstat.proc_ok++;} while(0)
#define STAT_FLOW_PROC_FAIL      do { pktstat[LOCAL_CPU_ID]->flowstat.proc_fail++;} while(0)
#define STAT_FLOW_PROC_DROP      do { pktstat[LOCAL_CPU_ID]->flowstat.proc_drop++;} while(0)
#define STAT_FLOW_TCP_NO_SYN_FIRST  do { pktstat[LOCAL_CPU_ID]->flowstat.tcp_no_syn_first++;} while(0)




#define STAT_TX_SEND_PORT_ERR    do { pktstat[LOCAL_CPU_ID]->txstat.port_err++;} while(0)
#define STAT_TX_HW_SEND_ERR      do { pktstat[LOCAL_CPU_ID]->txstat.hw_send_err++;} while(0)
#define STAT_TX_SW_DESC_ERR      do { pktstat[LOCAL_CPU_ID]->txstat.sw_desc_err++;} while(0)
#define STAT_TX_SW_SEND_ERR      do { pktstat[LOCAL_CPU_ID]->txstat.sw_send_err++;} while(0)
#define STAT_TX_SEND_OVER        do { pktstat[LOCAL_CPU_ID]->txstat.send_over++;} while(0)


#define STAT_ATTACK_LAND   do { pktstat[LOCAL_CPU_ID]->attstat.land++;} while(0)
#define STAT_ATTACK_TEARDROP  do { pktstat[LOCAL_CPU_ID]->attstat.teardrop++;} while(0)
#define STAT_ATTACK_PINGDEATH do { pktstat[LOCAL_CPU_ID]->attstat.pingdeath++;} while(0)
#define STAT_ATTACK_PINGFLOOD_DROP do { pktstat[LOCAL_CPU_ID]->attstat.pingspeed++;} while(0)
#define STAT_ATTACK_UDPFLOOD_DROP do { pktstat[LOCAL_CPU_ID]->attstat.udpspeed++;} while(0)
#define STAT_ATTACK_SYNFLOOD_DROP do { pktstat[LOCAL_CPU_ID]->attstat.synspeed++;} while(0)
#define STAT_ATTACK_SYNCOUNT do { pktstat[LOCAL_CPU_ID]->attstat.syncount++;} while(0)
#define STAT_ATTACK_PORTSCAN_DROP  do { pktstat[LOCAL_CPU_ID]->attstat.portscan_drop++;} while(0)


/* STREAM EVENTS */

#define    STREAM_SYN_ACK_COUNT    do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.SYN_ACK_COUNT++;} while(0)
#define    STREAM_SYN_COUNT        do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.SYN_COUNT++;} while(0)
#define    STREAM_RST_COUNT        do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.RST_COUNT++;} while(0)

#define    STREAM_SESSION_NO_MEM   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.SESSION_NO_MEM++;} while(0)
#define    STREAM_SESSION_PARAM_ERR do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.SESSION_PARAM_ERR++;} while(0)

#define    STREAM_SESSION_MIDSTREAM_OR_ONESIDE_DISABLE do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.MIDSTREAM_OR_ONESIDE_DISABLE++;} while(0)
#define    STREAM_SESSION_MIDSTREAM_DISABLE do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.MIDSTREAM_DISABLE++;} while(0)
#define    STREAM_SESSION_ONESIDE_DISABLE   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.ONESIDE_DISABLE++;} while(0)

#define    STERAM_3WHS_SYNACK_SEQ_MISMATCH  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_SYNACK_SEQ_MISMATCH++;} while(0)
#define    STREAM_3WHS_ACK_IN_WRONG_DIR  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_ACK_IN_WRONG_DIR++;} while(0)
#define    STREAM_3WHS_ASYNC_WRONG_SEQ   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_ASYNC_WRONG_SEQ++;} while(0)
#define    STREAM_3WHS_RIGHT_SEQ_WRONG_ACK_EVASION  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_RIGHT_SEQ_WRONG_ACK_EVASION++;} while(0)
#define    STREAM_3WHS_SYNACK_IN_WRONG_DIRECTION    do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_SYNACK_IN_WRONG_DIRECTION++;} while(0)
#define    STREAM_3WHS_SYNACK_RESEND_WITH_DIFFERENT_ACK  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_SYNACK_RESEND_WITH_DIFFERENT_ACK++;} while(0)
#define    STREAM_3WHS_SYNACK_RESEND_WITH_DIFF_SEQ
#define    STREAM_3WHS_SYNACK_TOSERVER_ON_SYN_RECV    do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_SYNACK_TOSERVER_SYN_RECV++;} while(0)
#define    STREAM_3WHS_SYNACK_WITH_WRONG_ACK        do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_SYNACK_WITH_WRONG_ACK++;} while(0)
#define    STREAM_3WHS_SYNACK_FLOOD
#define    STREAM_3WHS_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV++;} while(0)
#define    STREAM_3WHS_SYN_TOCLIENT_ON_SYN_RECV         do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_SYN_TOCLIENT_ON_SYN_RECV++;} while(0)
#define    STREAM_3WHS_WRONG_SEQ_WRONG_ACK           do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS3_WRONG_SEQ_WRONG_ACK++;} while(0)
#define    STREAM_4WHS_SYNACK_WITH_WRONG_ACK       do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS4_SYNACK_WITH_WRONG_ACK++;} while(0)
#define    STREAM_4WHS_SYNACK_WITH_WRONG_SYN       do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS4_SYNACK_WITH_WRONG_SYN++;} while(0)
#define    STREAM_4WHS_WRONG_SEQ                    do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS4_WRONG_SEQ++;} while(0)
#define    STREAM_4WHS_INVALID_ACK                  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.WHS4_INVALID_ACK++;} while(0)
#define    STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW     do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.CLOSEWAIT_ACK_OUT_OF_WINDOW++;} while(0)
#define    STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW     do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.CLOSEWAIT_FIN_OUT_OF_WINDOW++;} while(0)
#define    STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.CLOSEWAIT_PKT_BEFORE_LAST_ACK++;} while(0)
#define    STREAM_CLOSEWAIT_INVALID_ACK          do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.CLOSEWAIT_INVALID_ACK++;} while(0)
#define    STREAM_CLOSING_ACK_WRONG_SEQ       do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.CLOSING_ACK_WRONG_SEQ++;} while(0)
#define    STREAM_CLOSING_INVALID_ACK      do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.CLOSING_INVALID_ACK++;} while(0)
#define    STREAM_EST_PACKET_OUT_OF_WINDOW  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.EST_PACKET_OUT_OF_WINDOW++;} while(0)
#define    STREAM_EST_PKT_BEFORE_LAST_ACK  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.EST_PKT_BEFORE_LAST_ACK++;} while(0)
#define    STREAM_EST_SYNACK_RESEND       do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.EST_SYNACK_RESEND++;} while(0)
#define    STREAM_EST_SYNACK_RESEND_WITH_DIFFERENT_ACK  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.EST_SYNACK_RESEND_WITH_DIFFERENT_ACK++;} while(0)
#define    STREAM_EST_SYNACK_RESEND_WITH_DIFF_SEQ   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.EST_SYNACK_RESEND_WITH_DIFF_SEQ++;} while(0)
#define    STREAM_EST_SYNACK_TOSERVER   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.EST_SYNACK_TOSERVER ++;} while(0)
#define    STREAM_EST_SYN_RESEND   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.EST_SYN_RESEND++;} while(0)
#define    STREAM_EST_SYN_RESEND_DIFF_SEQ  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.EST_SYN_RESEND_DIFF_SEQ++;} while(0)
#define    STREAM_EST_SYN_TOCLIENT   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.EST_SYN_TOCLIENT++;} while(0)
#define    STREAM_EST_INVALID_ACK    do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.EST_INVALID_ACK++;} while(0)

#define    STREAM_FIN_INVALID_ACK     do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.FIN_INVALID_ACK++;} while(0)
#define    STREAM_FIN1_ACK_WRONG_SEQ  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.FIN1_ACK_WRONG_SEQ++;} while(0)
#define    STREAM_FIN1_FIN_WRONG_SEQ  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.FIN1_FIN_WRONG_SEQ++;} while(0)
#define    STREAM_FIN1_INVALID_ACK    do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.FIN1_INVALID_ACK++;} while(0)
#define    STREAM_FIN2_ACK_WRONG_SEQ   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.FIN2_ACK_WRONG_SEQ++;} while(0)
#define    STREAM_FIN2_FIN_WRONG_SEQ   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.FIN2_FIN_WRONG_SEQ++;} while(0)
#define    STREAM_FIN2_INVALID_ACK     do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.FIN2_INVALID_ACK ++;} while(0)

#define    STREAM_FIN_BUT_NO_SESSION    do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.FIN_BUT_NO_SESSION++;} while(0)
#define    STREAM_FIN_OUT_OF_WINDOW     do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.FIN_OUT_OF_WINDOW++;} while(0)
#define    STREAM_LASTACK_ACK_WRONG_SEQ  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.LASTACK_ACK_WRONG_SEQ++;} while(0)
#define    STREAM_LASTACK_INVALID_ACK   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.LASTACK_INVALID_ACK++;} while(0)

#define    STREAM_RST_BUT_NO_SESSION    do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.RST_BUT_NO_SESSION++;} while(0)
#define    STREAM_TIMEWAIT_ACK_WRONG_SEQ  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.TIMEWAIT_ACK_WRONG_SEQ++;} while(0)
#define    STREAM_TIMEWAIT_INVALID_ACK   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.TIMEWAIT_INVALID_ACK++;} while(0)
#define    STREAM_SHUTDOWN_SYN_RESEND   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.SHUTDOWN_SYN_RESEND++;} while(0)
#define    STREAM_PKT_INVALID_TIMESTAMP
#define    STREAM_PKT_INVALID_ACK     do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.PKT_INVALID_ACK++;} while(0)
#define    STREAM_PKT_BROKEN_ACK      do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.PKT_BROKEN_ACK++;} while(0)
#define    STREAM_RST_INVALID_ACK
#define    STREAM_PKT_RETRANSMISSION  do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.PKT_RETRANSMISSION++;} while(0)
#define    STREAM_PKT_BAD_WINDOW_UPDATE   do { pktstat[LOCAL_CPU_ID]->tcpstreamtrackstat.PKT_BAD_WINDOW_UPDATE++;} while(0)
#define    STREAM_REASSEMBLY_SEGMENT_BEFORE_BASE_SEQ
#define    STREAM_REASSEMBLY_NO_SEGMENT
#define    STREAM_REASSEMBLY_SEQ_GAP
#define    STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA



#define STREAMTCP_REASM_BEFORE_RA_BASE  do { pktstat[LOCAL_CPU_ID]->tcpstreamreasmstat.REASM_BEFORE_RA_BASE++;} while(0)
#define STREAMTCP_REASM_SEG_NO_MEM      do { pktstat[LOCAL_CPU_ID]->tcpstreamreasmstat.REASM_SEG_NO_MEM++;} while(0)
#define STREAMTCP_REASM_HW2SW_ERR       do { pktstat[LOCAL_CPU_ID]->tcpstreamreasmstat.REASM_HW2SW_ERR++;} while(0)
#define STREAMTCP_REASM_CACHE           do { pktstat[LOCAL_CPU_ID]->tcpstreamreasmstat.REASM_CACHE++;} while(0)
#define STREAMTCP_REASM_NO_NEED_REASM   do { pktstat[LOCAL_CPU_ID]->tcpstreamreasmstat.REASM_NO_NEED_REASM++;} while(0)
#define STREAMTCP_REASM_SETUP_FAIL      do { pktstat[LOCAL_CPU_ID]->tcpstreamreasmstat.REASM_SETUP_FAIL++;} while(0)
#define STREAMTCP_REASM_OK              do { pktstat[LOCAL_CPU_ID]->tcpstreamreasmstat.REASM_OK++;} while(0)
#define STREAMTCP_REASM_REASM_OVERLAP   do { pktstat[LOCAL_CPU_ID]->tcpstreamreasmstat.REASM_OVERLAP++;} while(0)


#define STAT_OUTPUT_DROP    do { pktstat[LOCAL_CPU_ID]->outputstat.output_drop++;} while(0)
#define STAT_OUTPUT_FW      do { pktstat[LOCAL_CPU_ID]->outputstat.output_fw++;} while(0)
#define STAT_OUTPUT_CACHE   do { pktstat[LOCAL_CPU_ID]->outputstat.output_cache++;} while(0)
#define STAT_OUTPUT_UNSUPPORT  do { pktstat[LOCAL_CPU_ID]->outputstat.output_unsupport++;} while(0)


extern int Decode_PktStat_Init();
extern int Decode_PktStat_Get();
extern void Decode_PktStat_Release();

#endif
