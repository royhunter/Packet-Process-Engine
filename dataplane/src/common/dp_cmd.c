#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
//#include <net/if.h>
#include <arpa/inet.h>

#include "dp_cmd.h"
#include "decode-statistic.h"
#include "decode-defrag.h"
#include "dp_acl.h"
#include <oct-rxtx.h>
#include <flow.h>
#include <stream-tcp.h>
#include "rwlock.h"
#include "shm.h"
#include <dp_attack.h>


static pthread_t dp_msg_process_thread;
static pthread_t dp_netstat_monitor_thread;
int dp_msg_queue_id = 0;
extern uint32_t syn_check;
extern uint32_t defrag_cache_max;
extern attack_rule attrule;
extern attack_monitor attinfo;
uint32_t unsupport_proto_action = 0;
extern int32_t fcb_running_num;
extern uint64_t new_fcb[];
extern uint64_t del_fcb[];
extern uint64_t new_pcb[];
extern uint64_t del_pcb[];
extern uint32_t portscan_able;
extern uint32_t portscan_action;
extern uint32_t flood_hold_time;
extern uint32_t portscan_exception_freq;
extern uint64_t packet_rx[4];
extern uint32_t synflood_ip_start;
extern uint32_t synflood_ip_end;
extern uint32_t synflood_percent;
extern uint32_t modbus_able;
extern uint32_t modbus_func;
extern uint32_t modbus_addr;
extern uint32_t modbus_min;
extern uint32_t modbus_max;

void oct_send_response(cvmx_wqe_t *work, uint16_t opcode, void *data, uint32_t size)
{
    void *resp = NULL;
    rpc_ether_hdr_t *hdr;
    rpc_msg_t *rpcmsg;

    resp = (void *)cvmx_phys_to_ptr(work->packet_ptr.s.addr);

    hdr = (rpc_ether_hdr_t *)resp;

    hdr->type = ETH_P;

    rpcmsg = (rpc_msg_t *)((uint8_t *)resp + sizeof(rpc_ether_hdr_t));
    rpcmsg->opcode = opcode;
    rpcmsg->info_len = size;
    memcpy((void *)rpcmsg->info_buf, data, size);

    work->packet_ptr.s.size = sizeof(rpc_ether_hdr_t) + sizeof(rpc_msg_t) + rpcmsg->info_len;

    cvmx_wqe_set_len(work, work->packet_ptr.s.size);
    cvmx_wqe_set_port(work, 0);
    cvmx_wqe_set_grp(work, TO_LINUX_GROUP);

    cvmx_pow_work_submit(work, work->word1.tag, work->word1.tag_type, cvmx_wqe_get_qos(work), TO_LINUX_GROUP);
}

uint16_t oct_rx_command_get(cvmx_wqe_t *work)
{
    uint8_t *data;
    rpc_msg_t *rpcmsg;

    if(cvmx_wqe_get_bufs(work))
    {
        data = cvmx_phys_to_ptr(work->packet_ptr.s.addr);
        if(NULL == data)
            return COMMAND_INVALID;
    }
    else
    {
        return COMMAND_INVALID;
    }

    rpcmsg = (rpc_msg_t *)data;

    //LOGDBG("opcode is 0x%x\n", rpcmsg->opcode);

    return rpcmsg->opcode;
}


void dp_send_response(int opcode, uint32_t len)
{
    MSG_QUE_BODY msgbody;

    msgbody.mtype = (long)opcode;
    msgbody.msg[0] = (uint64_t)len;

    if(MSGQUE_Send(dp_msg_queue_id, &msgbody) >= 0)
    {
        LOGDBG(SEC_DPCMD_DBG_BIT, "dp_send_response ok\n");
    }
    else
    {
        LOGDBG(SEC_DPCMD_DBG_BIT, "dp_send_response failed\n");
    }
}




void dp_show_build_time()
{
    uint32_t len;
    char *out = (char *)&srv_dp_sync->msgbuf;

    sprintf(out, "%s, %s\n", __DATE__, __TIME__);
    len = strlen(out);

    dp_send_response(COMMAND_SHOW_BUILD_TIME_ACK, len);
}

void dp_clear_pkt_stat()
{
    uint32_t len;
    int i;
    char *out = (char *)&srv_dp_sync->msgbuf;

    for( i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        memset((void *)pktstat[i], 0, sizeof(pkt_stat));
    }

    sprintf(out, "ok.\n");
    len = strlen(out);

    dp_send_response(COMMAND_CLEAR_PKT_STAT_ACK, len);
}


void dp_clear_tcpstream_stat()
{
    uint32_t len;
    int i;
    char *out = (char *)&srv_dp_sync->msgbuf;

    for( i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        memset((void *)(&pktstat[i]->tcpstreamtrackstat), 0, sizeof(struct tcpstream_track_stat));
        memset((void *)(&pktstat[i]->tcpstreamreasmstat), 0, sizeof(struct tcpstream_reasm_stat));
    }

    sprintf(out, "ok.\n");
    len = strlen(out);

    dp_send_response(COMMAND_CLEAR_TCPSTREAM_STAT_ACK, len);
}

void dp_show_tcpstream_stat()
{
    uint32_t len = 0;
    int i;
    uint32_t totallen = 0;
    uint8_t *ptr;
    char *out = (char *)&srv_dp_sync->msgbuf;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "tcpstream statistic:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "tcpstream track: %s\n", stream_tcp_track_enable ? "enable" : "disable");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "tcpstream reasm: %s\n", stream_tcp_reasm_enable ? "enable" : "disable");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------------------------\n");
    ptr += len;
    totallen += len;

    uint64_t x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.SYN_ACK_COUNT;
    }

    len = sprintf((void *)ptr, "SYN_ACK_COUNT: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.SYN_COUNT;
    }

    len = sprintf((void *)ptr, "SYN_COUNT: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.RST_COUNT;
    }

    len = sprintf((void *)ptr, "RST_COUNT: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.RST_BUT_NO_SESSION;
    }

    len = sprintf((void *)ptr, "RST_BUT_NO_SESSION: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.FIN_BUT_NO_SESSION;
    }

    len = sprintf((void *)ptr, "FIN_BUT_NO_SESSION: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.SESSION_NO_MEM;
    }

    len = sprintf((void *)ptr, "SESSION_NO_MEM: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.FIN_INVALID_ACK;
    }

    len = sprintf((void *)ptr, "FIN_INVALID_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.FIN_OUT_OF_WINDOW;
    }

    len = sprintf((void *)ptr, "FIN_OUT_OF_WINDOW: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.SESSION_PARAM_ERR;
    }

    len = sprintf((void *)ptr, "SESSION_PARAM_ERR: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_SYNACK_TOSERVER_SYN_RECV;
    }

    len = sprintf((void *)ptr, "WHS3_SYNACK_TOSERVER_SYN_RECV: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_SYNACK_SEQ_MISMATCH;
    }

    len = sprintf((void *)ptr, "WHS3_SYNACK_SEQ_MISMATCH: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_SYNACK_RESEND_WITH_DIFFERENT_ACK;
    }

    len = sprintf((void *)ptr, "WHS3_SYNACK_RESEND_WITH_DIFFERENT_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_SYN_TOCLIENT_ON_SYN_RECV;
    }

    len = sprintf((void *)ptr, "WHS3_SYN_TOCLIENT_ON_SYN_RECV: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV;
    }

    len = sprintf((void *)ptr, "WHS3_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_SYNACK_IN_WRONG_DIRECTION;
    }

    len = sprintf((void *)ptr, "WHS3_SYNACK_IN_WRONG_DIRECTION: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_ACK_IN_WRONG_DIR;
    }

    len = sprintf((void *)ptr, "WHS3_ACK_IN_WRONG_DIR: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_RIGHT_SEQ_WRONG_ACK_EVASION;
    }

    len = sprintf((void *)ptr, "WHS3_RIGHT_SEQ_WRONG_ACK_EVASION: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_WRONG_SEQ_WRONG_ACK;
    }

    len = sprintf((void *)ptr, "WHS3_WRONG_SEQ_WRONG_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_ASYNC_WRONG_SEQ;
    }

    len = sprintf((void *)ptr, "WHS3_ASYNC_WRONG_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS3_SYNACK_WITH_WRONG_ACK;
    }

    len = sprintf((void *)ptr, "WHS3_SYNACK_WITH_WRONG_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS4_WRONG_SEQ;
    }

    len = sprintf((void *)ptr, "WHS4_WRONG_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS4_INVALID_ACK;
    }

    len = sprintf((void *)ptr, "WHS4_INVALID_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS4_SYNACK_WITH_WRONG_ACK;
    }

    len = sprintf((void *)ptr, "WHS4_SYNACK_WITH_WRONG_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.WHS4_SYNACK_WITH_WRONG_SYN;
    }

    len = sprintf((void *)ptr, "WHS4_SYNACK_WITH_WRONG_SYN: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.EST_INVALID_ACK;
    }

    len = sprintf((void *)ptr, "EST_INVALID_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.EST_PKT_BEFORE_LAST_ACK;
    }

    len = sprintf((void *)ptr, "EST_PKT_BEFORE_LAST_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.EST_PACKET_OUT_OF_WINDOW;
    }

    len = sprintf((void *)ptr, "EST_PACKET_OUT_OF_WINDOW: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.EST_SYNACK_RESEND;
    }

    len = sprintf((void *)ptr, "EST_SYNACK_RESEND: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.EST_SYNACK_TOSERVER;
    }

    len = sprintf((void *)ptr, "EST_SYNACK_TOSERVER: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.EST_SYNACK_RESEND_WITH_DIFFERENT_ACK;
    }

    len = sprintf((void *)ptr, "EST_SYNACK_RESEND_WITH_DIFFERENT_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.EST_SYNACK_RESEND_WITH_DIFF_SEQ;
    }

    len = sprintf((void *)ptr, "EST_SYNACK_RESEND_WITH_DIFF_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.EST_SYN_TOCLIENT;
    }

    len = sprintf((void *)ptr, "EST_SYN_TOCLIENT: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.EST_SYN_RESEND_DIFF_SEQ;
    }

    len = sprintf((void *)ptr, "EST_SYN_RESEND_DIFF_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.EST_SYN_RESEND;
    }

    len = sprintf((void *)ptr, "EST_SYN_RESEND: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.PKT_RETRANSMISSION;
    }

    len = sprintf((void *)ptr, "PKT_RETRANSMISSION: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.FIN2_FIN_WRONG_SEQ;
    }

    len = sprintf((void *)ptr, "FIN2_FIN_WRONG_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.FIN2_INVALID_ACK;
    }

    len = sprintf((void *)ptr, "FIN2_INVALID_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.FIN2_ACK_WRONG_SEQ;
    }

    len = sprintf((void *)ptr, "FIN2_ACK_WRONG_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.FIN1_FIN_WRONG_SEQ;
    }

    len = sprintf((void *)ptr, "FIN1_FIN_WRONG_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.FIN1_INVALID_ACK;
    }

    len = sprintf((void *)ptr, "FIN1_INVALID_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.FIN1_ACK_WRONG_SEQ;
    }

    len = sprintf((void *)ptr, "FIN1_ACK_WRONG_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.SHUTDOWN_SYN_RESEND;
    }

    len = sprintf((void *)ptr, "SHUTDOWN_SYN_RESEND: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.CLOSEWAIT_FIN_OUT_OF_WINDOW;
    }

    len = sprintf((void *)ptr, "CLOSEWAIT_FIN_OUT_OF_WINDOW: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.CLOSING_ACK_WRONG_SEQ;
    }

    len = sprintf((void *)ptr, "CLOSING_ACK_WRONG_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.CLOSEWAIT_INVALID_ACK;
    }

    len = sprintf((void *)ptr, "CLOSEWAIT_INVALID_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.CLOSING_INVALID_ACK;
    }

    len = sprintf((void *)ptr, "CLOSING_INVALID_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.CLOSEWAIT_PKT_BEFORE_LAST_ACK;
    }

    len = sprintf((void *)ptr, "CLOSEWAIT_PKT_BEFORE_LAST_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.CLOSEWAIT_ACK_OUT_OF_WINDOW;
    }

    len = sprintf((void *)ptr, "CLOSEWAIT_ACK_OUT_OF_WINDOW: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.LASTACK_ACK_WRONG_SEQ;
    }

    len = sprintf((void *)ptr, "LASTACK_ACK_WRONG_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.LASTACK_INVALID_ACK;
    }

    len = sprintf((void *)ptr, "LASTACK_INVALID_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.TIMEWAIT_ACK_WRONG_SEQ;
    }

    len = sprintf((void *)ptr, "TIMEWAIT_ACK_WRONG_SEQ: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.TIMEWAIT_INVALID_ACK;
    }

    len = sprintf((void *)ptr, "TIMEWAIT_INVALID_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.PKT_INVALID_ACK;
    }

    len = sprintf((void *)ptr, "PKT_INVALID_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.PKT_BAD_WINDOW_UPDATE;
    }

    len = sprintf((void *)ptr, "PKT_BAD_WINDOW_UPDATE: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamtrackstat.PKT_BROKEN_ACK;
    }

    len = sprintf((void *)ptr, "PKT_BROKEN_ACK: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamreasmstat.REASM_BEFORE_RA_BASE;
    }

    len = sprintf((void *)ptr, "REASM_BEFORE_RA_BASE: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamreasmstat.REASM_SEG_NO_MEM;
    }

    len = sprintf((void *)ptr, "REASM_SEG_NO_MEM: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamreasmstat.REASM_HW2SW_ERR;
    }

    len = sprintf((void *)ptr, "REASM_HW2SW_ERR: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamreasmstat.REASM_CACHE;
    }

    len = sprintf((void *)ptr, "REASM_CACHE: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamreasmstat.REASM_NO_NEED_REASM;
    }

    len = sprintf((void *)ptr, "REASM_NO_NEED_REASM: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamreasmstat.REASM_SETUP_FAIL;
    }

    len = sprintf((void *)ptr, "REASM_SETUP_FAIL: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamreasmstat.REASM_OK;
    }

    len = sprintf((void *)ptr, "REASM_OK: %ld\n", x);
    ptr += len;
    totallen += len;


    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstreamreasmstat.REASM_OVERLAP;
    }

    len = sprintf((void *)ptr, "REASM_OVERLAP: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;


    dp_send_response(COMMAND_SHOW_TCPSTREAM_STAT_ACK, totallen);

}

void dp_show_pkt_stat()
{
    uint32_t len = 0;
    int i;
    uint32_t totallen = 0;
    uint8_t *ptr;
    char *out = (char *)&srv_dp_sync->msgbuf;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "packet statistic:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------------------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "recv_count:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    uint64_t x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rc.recv_packet_count;
    }

    len = sprintf((void *)ptr, "recv_packet_count: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rc.recv_packet_bytes;
    }

    len = sprintf((void *)ptr, "recv_packet_bytes: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rc.recv_packet_count_sum;
    }

    len = sprintf((void *)ptr, "recv_packet_count_sum: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rc.recv_packet_bytes_sum;
    }

    len = sprintf((void *)ptr, "recv_packet_bytes_sum: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "rx_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rxstat.grp_err;
    }

    len = sprintf((void *)ptr, "grp_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rxstat.rx_fromhwport_err;
    }

    len = sprintf((void *)ptr, "rx_fromhwport_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rxstat.rx_fromlinux_err;
    }

    len = sprintf((void *)ptr, "rx_fromlinux_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rxstat.rx_fromhwport_ok;
    }

    len = sprintf((void *)ptr, "rx_fromhwport_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rxstat.rx_fromlinux_ok;
    }

    len = sprintf((void *)ptr, "rx_fromlinux_ok: %ld\n", x);
    ptr += len;
    totallen += len;


    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rxstat.addr_err;
    }

    len = sprintf((void *)ptr, "addr_err: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "ether_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->l2stat.headerlen_err;
    }

    len = sprintf((void *)ptr, "headerlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->l2stat.unsupport;
    }

    len = sprintf((void *)ptr, "unsupport: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->l2stat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->l2stat.arp_se2linux_ok;
    }

    len = sprintf((void *)ptr, "arp_se2linux_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->l2stat.arp_se2linux_fail;
    }

    len = sprintf((void *)ptr, "arp_se2linux_fail: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "vlan_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->vlanstat.headerlen_err;
    }

    len = sprintf((void *)ptr, "headerlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->vlanstat.vlanlayer_exceed;
    }

    len = sprintf((void *)ptr, "vlanlayer_exceed: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->vlanstat.unsupport;
    }

    len = sprintf((void *)ptr, "unsupport: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->vlanstat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->vlanstat.arp_se2linux_fail;
    }

    len = sprintf((void *)ptr, "arp_se2linux_fail: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->vlanstat.arp_se2linux_ok;
    }

    len = sprintf((void *)ptr, "arp_se2linux_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;



    len = sprintf((void *)ptr, "ipv4_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.headerlen_err;
    }

    len = sprintf((void *)ptr, "headerlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.version_err;
    }

    len = sprintf((void *)ptr, "version_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.pktlen_err;
    }

    len = sprintf((void *)ptr, "pktlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.unsupport;
    }

    len = sprintf((void *)ptr, "unsupport: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.icmp_se2linux_ok;
    }

    len = sprintf((void *)ptr, "icmp_se2linux_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.icmp_se2linux_fail;
    }

    len = sprintf((void *)ptr, "icmp_se2linux_fail: %ld\n", x);
    ptr += len;
    totallen += len;

        x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.ospf_se2linux_ok;
    }

    len = sprintf((void *)ptr, "ospf_se2linux_ok: %ld\n", x);
    ptr += len;
    totallen += len;

        x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.ospf_se2linux_fail;
    }

    len = sprintf((void *)ptr, "ospf_se2linux_fail: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr, "ip_frag_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->fragstat.fraglen_err;
    }

    len = sprintf((void *)ptr, "fraglen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->fragstat.fcb_no;
    }


    len = sprintf((void *)ptr, "fcb_no: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->fragstat.hw2sw_err;
    }

    len = sprintf((void *)ptr, "hw2sw_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->fragstat.fcb_full;
    }

    len = sprintf((void *)ptr, "fcb_full: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->fragstat.cache_full;
    }

    len = sprintf((void *)ptr, "cache_full: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->fragstat.defrag_err;
    }

    len = sprintf((void *)ptr, "defrag_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->fragstat.setup_err;
    }

    len = sprintf((void *)ptr, "setup_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->fragstat.out_oversize;
    }

    len = sprintf((void *)ptr, "out_oversize: %ld\n", x);
    ptr += len;
    totallen += len;


    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->fragstat.cache_ok;
    }

    len = sprintf((void *)ptr, "cache_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->fragstat.reasm_ok;
    }

    len = sprintf((void *)ptr, "reasm_ok: %ld\n", x);
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "icmp_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->icmpstat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->icmpstat.drop;
    }

    len = sprintf((void *)ptr, "drop: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr, "tcp_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstat.headerlen_err;
    }

    len = sprintf((void *)ptr, "headerlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstat.pktlen_err;
    }

    len = sprintf((void *)ptr, "pktlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "udp_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->udpstat.headerlen_err;
    }

    len = sprintf((void *)ptr, "headerlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->udpstat.pktlen_err;
    }

    len = sprintf((void *)ptr, "pktlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->udpstat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "acl_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->aclstat.drop;
    }

    len = sprintf((void *)ptr, "drop: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->aclstat.fw;
    }

    len = sprintf((void *)ptr, "fw: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "flow_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->flowstat.node_nomem;
    }

    len = sprintf((void *)ptr, "node_nomem: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->flowstat.proc_ok;
    }

    len = sprintf((void *)ptr, "proc_ok: %ld\n", x);
    ptr += len;
    totallen += len;


    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->flowstat.proc_fail;
    }

    len = sprintf((void *)ptr, "proc_fail: %ld\n", x);
    ptr += len;
    totallen += len;


    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->flowstat.proc_drop;
    }

    len = sprintf((void *)ptr, "proc_drop: %ld\n", x);
    ptr += len;
    totallen += len;


    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->flowstat.tcp_no_syn_first;
    }

    len = sprintf((void *)ptr, "tcp_no_syn_first: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "output:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->outputstat.output_fw;
    }

    len = sprintf((void *)ptr, "output_fw: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->outputstat.output_drop;
    }

    len = sprintf((void *)ptr, "output_drop: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->outputstat.output_cache;
    }

    len = sprintf((void *)ptr, "output_cache: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->outputstat.output_unsupport;
    }

    len = sprintf((void *)ptr, "output_unsupport: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "tx_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->txstat.port_err;
    }

    len = sprintf((void *)ptr, "port_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->txstat.hw_send_err;
    }

    len = sprintf((void *)ptr, "hw_send_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->txstat.sw_desc_err;
    }

    len = sprintf((void *)ptr, "sw_desc_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->txstat.sw_send_err;
    }

    len = sprintf((void *)ptr, "sw_send_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->txstat.send_over;
    }

    len = sprintf((void *)ptr, "send_over: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "attack stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->attstat.land;
    }

    len = sprintf((void *)ptr, "land_drop: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->attstat.teardrop;
    }

    len = sprintf((void *)ptr, "teardrop: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->attstat.pingdeath;
    }

    len = sprintf((void *)ptr, "pingdeath: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->attstat.pingspeed;
    }

    len = sprintf((void *)ptr, "ping flood drop: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->attstat.udpspeed;
    }

    len = sprintf((void *)ptr, "udp flood drop: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->attstat.synspeed;
    }

    len = sprintf((void *)ptr, "syn flood drop: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->attstat.syncount;
    }

    len = sprintf((void *)ptr, "syncount: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->attstat.portscan_drop;
    }

    len = sprintf((void *)ptr, "portscan_drop: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SHOW_PKT_STAT_ACK, totallen);

}


void dp_show_mem_pool()
{
    uint32_t len = 0;
    int i;
    uint32_t totallen = 0;
    uint8_t *ptr;
    char *out = (char *)&srv_dp_sync->msgbuf;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "mem pool stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "small pool(%d bytes):\n", MEM_POOL_SMALL_BUFFER_SIZE);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "total slice num %d.\n", MEM_POOL_SMALL_BUFFER_NUM);
    ptr += len;
    totallen += len;

    for(i = 0; i < MEM_POOL_INTERNAL_NUM; i++)
    {
        len = sprintf((void *)ptr, "pool %d:  free num %d(%d)\n", i, mem_pool[MEM_POOL_ID_SMALL_BUFFER]->mpc.msc[i].freenum, MEM_POOL_SMALL_BUFFER_NUM/MEM_POOL_INTERNAL_NUM);
        ptr += len;
        totallen += len;
    }

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "large pool(%d bytes):\n", MEM_POOL_LARGE_BUFFER_SIZE);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "total slice num %d.\n", MEM_POOL_LARGE_BUFFER_NUM);
    ptr += len;
    totallen += len;

    for(i = 0; i < MEM_POOL_INTERNAL_NUM; i++)
    {
        len = sprintf((void *)ptr, "pool %d:  free num %d(%d)\n", i, mem_pool[MEM_POOL_ID_LARGE_BUFFER]->mpc.msc[i].freenum, MEM_POOL_LARGE_BUFFER_NUM/MEM_POOL_INTERNAL_NUM);
        ptr += len;
        totallen += len;
    }

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "stream session pool(%d bytes):\n", MEM_POOL_STREAM_TCP_SESSION_SIZE);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "total slice num %d.\n", MEM_POOL_STREAM_TCP_SESSION_NUM);
    ptr += len;
    totallen += len;

    for(i = 0; i < MEM_POOL_INTERNAL_NUM; i++)
    {
        len = sprintf((void *)ptr, "pool %d:  free num %d(%d)\n", i, mem_pool[MEM_POOL_ID_STREAMTCP_SESSION_BUFFER]->mpc.msc[i].freenum, MEM_POOL_STREAM_TCP_SESSION_NUM/MEM_POOL_INTERNAL_NUM);
        ptr += len;
        totallen += len;
    }

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "stream segment pool(%d bytes):\n", MEM_POOL_STREAM_TCP_SEGMENT_SIZE);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "total slice num %d.\n", MEM_POOL_STREAM_TCP_SEGMENT_NUM);
    ptr += len;
    totallen += len;

    for(i = 0; i < MEM_POOL_INTERNAL_NUM; i++)
    {
        len = sprintf((void *)ptr, "pool %d:  free num %d(%d)\n", i, mem_pool[MEM_POOL_ID_STREAMTCP_SEGMENT_BUFFER]->mpc.msc[i].freenum, MEM_POOL_STREAM_TCP_SEGMENT_NUM/MEM_POOL_INTERNAL_NUM);
        ptr += len;
        totallen += len;
    }

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "portscan item pool(%d bytes):\n", MEM_POOL_PORTSCAN_BUFFER_SIZE);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "total slice num %d.\n", MEM_POOL_PORTSCAN_BUFFER_NUM);
    ptr += len;
    totallen += len;

    for(i = 0; i < MEM_POOL_INTERNAL_NUM; i++)
    {
        len = sprintf((void *)ptr, "pool %d:  free num %d(%d)\n", i, mem_pool[MEM_POOL_ID_PORTSCAN_BUFFER]->mpc.msc[i].freenum, MEM_POOL_PORTSCAN_BUFFER_NUM/MEM_POOL_INTERNAL_NUM);
        ptr += len;
        totallen += len;
    }

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;




#if 0
    len = sprintf((void *)ptr, "sos mem pool stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "Global pool info:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "start: %p    totalsize: %d\n", sos_mem_pool->start, sos_mem_pool->total_size);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "cur_start: %p    cur_size: %d\n", sos_mem_pool->current_start, sos_mem_pool->current_size);
    ptr += len;
    totallen += len;
#endif

    dp_send_response(COMMAND_SHOW_MEM_POOL_ACK, totallen);

}

static unit_tree_t *get_back_acltree()
{
    unit_tree_t *acltree_back = NULL;
    unsigned long acltree1 = (unsigned long )(void *)&g_acltree_1;

    if( g_acltree_running == acltree1 )
    {
        acltree_back = &g_acltree_2;
    }
    else
    {
        acltree_back = &g_acltree_1;
    }

    return acltree_back;
}

static void set_running_acltree(unit_tree_t *acltree)
{
    write_lock(&acltree_running_rwlock);
    g_acltree_running = (unsigned long)(void *)acltree;
    write_unlock(&acltree_running_rwlock);
}

void dp_acl_rule_commit(uint64_t msgtype)
{
    uint32_t len, totallen = 0;
    uint32_t ret;
    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;
    unit_tree_t *acltree_back;

    ptr = (uint8_t *)out;

    pthread_mutex_lock(&rule_list->rulelist_mutex);

    if(rule_list->build_status == RULE_BUILD_COMMIT)
    {
        len = sprintf((void *)ptr, "commit ok\n");
        ptr += len;
        totallen += len;
    }
    else
    {
    #if 0
        if(rule_list->rule_entry_free == RULE_ENTRY_MAX)  // rule empty, no need to load
        {
            len = sprintf((void *)ptr, "no rule exist\n");
            ptr += len;
            totallen += len;
        }
        else
        {
    #endif
            acltree_back = get_back_acltree();

            ret = DP_Acl_Load_Rule(rule_list, &(acltree_back->TreeSet), &(acltree_back->TreeNode));
            if(SEC_OK != ret)
            {
                len = sprintf((void *)ptr, "commit failed\n");
                ptr += len;
                totallen += len;
            }
            else
            {
                set_running_acltree(acltree_back);
                acltree_back = get_back_acltree();
                DP_Acl_Rule_Clean(&acltree_back->TreeSet, &acltree_back->TreeNode);

                LOGDBG(SEC_DPCMD_DBG_BIT, "wrst case tree depth: %d\n",gWstDepth);
                if(gChildCount)
                    LOGDBG(SEC_DPCMD_DBG_BIT, "average tree depth: %f\n",(float)gAvgDepth/gChildCount);
                LOGDBG(SEC_DPCMD_DBG_BIT, "number of tree nodes: %d\n",gNumTreeNode);
                LOGDBG(SEC_DPCMD_DBG_BIT, "number of leaf nodes: %d\n",gNumLeafNode);
                LOGDBG(SEC_DPCMD_DBG_BIT, "finished\n");

                len = sprintf((void *)ptr, "commit ok\n");
                ptr += len;
                totallen += len;
            }
        //}

        rule_list->build_status = RULE_BUILD_COMMIT;
    }

    pthread_mutex_unlock(&rule_list->rulelist_mutex);

    if(msgtype == COMMAND_ACL_RULE_COMMIT)
    {
        dp_send_response(COMMAND_ACL_RULE_COMMIT_ACK, totallen);
    }

}


void dp_acl_def_act_set()
{
    uint32_t len, totallen = 0;

    dp_acl_action_default = rule_list->rule_def_act;

    rule_list->build_status = RULE_BUILD_UNCOMMIT;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_ACL_DEF_ACT_SET_ACK, totallen);
}

void dp_tcpstream_track_set()
{
    uint32_t len, totallen = 0;

    stream_tcp_track_enable = srv_dp_sync->dp_tcpstream_track;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_TCPSTREAM_TRACK_ACK, totallen);
}

void dp_tcpstream_reasm_set()
{
    uint32_t len, totallen = 0;

    stream_tcp_reasm_enable = srv_dp_sync->dp_tcpstream_reasm;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_TCPSTREAM_REASM_ACK, totallen);
}

void dp_syncheck_set()
{
    uint32_t len, totallen = 0;

    syn_check = srv_dp_sync->dp_syncheck_able;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_SYNCHECK_ACK, totallen);

}

void dp_portscan_able_set()
{
    uint32_t len, totallen = 0;

    portscan_able = srv_dp_sync->dp_portscan_able;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_PORTSCAN_ABLE_ACK, totallen);

}


void dp_modbus_able_set()
{
    uint32_t len, totallen = 0;

    modbus_able = srv_dp_sync->dp_modbus_able;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_MODBUS_ABLE_ACK, totallen);

}


void dp_modbus_value_set()
{
    uint32_t len, totallen = 0;

    modbus_func = srv_dp_sync->dp_modbus_func;
    modbus_addr = srv_dp_sync->dp_modbus_addr;
    modbus_min = srv_dp_sync->dp_modbus_min;
    modbus_max = srv_dp_sync->dp_modbus_max;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_MODBUS_VALUE_ACK, totallen);

}

void dp_portscan_action_set()
{
    uint32_t len, totallen = 0;

    portscan_action = srv_dp_sync->dp_portscan_action;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_PORTSCAN_ACTION_ACK, totallen);
}

void dp_attack_defend_time_set()
{
    uint32_t len, totallen = 0;

    flood_hold_time = srv_dp_sync->dp_attack_defend_time;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_ATTACK_DEFEND_TIME_ACK, totallen);
}

void dp_portscan_freq_set()
{
    uint32_t len, totallen = 0;

    portscan_exception_freq = srv_dp_sync->dp_portscan_freq;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_PORTSCAN_FREQ_ACK, totallen);

}


void dp_synflood_start_set()
{
    uint32_t len, totallen = 0;

    synflood_ip_start = srv_dp_sync->dp_synflood_start;
    synflood_ip_end = srv_dp_sync->dp_synflood_end;
    synflood_percent = srv_dp_sync->dp_synflood_percent;
    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_SYNFLOOD_FIRST_ACK, totallen);

}


void dp_directfw_able_set()
{
    uint32_t len, totallen = 0;

    oct_directfw_set();

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;
    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_DIRECTFW_ABLE_ACK, totallen);
}


void dp_defrag_max_set()
{
    uint32_t len, totallen = 0;

    defrag_cache_max = srv_dp_sync->dp_defragmax;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_DEFRAGMAX_ACK, totallen);
}

void dp_unsupport_proto_action_set()
{
    uint32_t len, totallen = 0;

    unsupport_proto_action = srv_dp_sync->dp_unsupportproto_action;

    char *out = (char *)&srv_dp_sync->msgbuf;
    uint8_t *ptr;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "ok.\n");
    ptr += len;
    totallen += len;

    dp_send_response(COMMAND_SET_UNSUPPORT_PROTO_ACTION_ACK, totallen);
}


void dp_clear_flow_stat()
{
    uint32_t len;
    int i;
    char *out = (char *)&srv_dp_sync->msgbuf;

    for( i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        new_flow[i] = 0;
        del_flow[i] = 0;
    }

    sprintf(out, "ok.\n");
    len = strlen(out);

    dp_send_response(COMMAND_CLEAR_FW_FLOW_STAT_ACK, len);
}

void dp_show_flow_stat()
{
    uint32_t len;
    int i;
    uint32_t totallen = 0;
    uint64_t x = 0, y = 0;
    uint8_t *ptr;
    char *out = (char *)&srv_dp_sync->msgbuf;

    ptr = (uint8_t *)out;

    for( i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += new_flow[i];
        y += del_flow[i];
    }

    len = sprintf((void *)ptr, "new flow is: ""%" PRId64 "\n""del flow is: ""%" PRId64 "\n", x, y);
    ptr += len;
    totallen += len;

    x = 0;
    y = 0;
    for( i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += new_fcb[i];
        y += del_fcb[i];
    }

    len = sprintf((void *)ptr, "new fcb is: ""%" PRId64 "\n""del fcb is: ""%" PRId64 "\n", x, y);
    ptr += len;
    totallen += len;

    x = 0;
    y = 0;
    for( i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += new_pcb[i];
        y += del_pcb[i];
    }

    len = sprintf((void *)ptr, "new pcb is: ""%" PRId64 "\n""del pcb is: ""%" PRId64 "\n", x, y);
    ptr += len;
    totallen += len;


    dp_send_response(COMMAND_SHOW_FW_FLOW_STAT_ACK, totallen);
}

void dp_show_attack_stat()
{
    uint32_t len = 0;
    int i;
    uint32_t totallen = 0;
    uint8_t *ptr;
    char *out = (char *)&srv_dp_sync->msgbuf;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "attack rule:\n");
    ptr += len;
    totallen += len;

    for(i = 0; i < OCT_PHY_PORT_MAX; i++)
    {
        len = sprintf((void *)ptr, "----------------\n");
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"interface %d:\n", i);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"packet detect:\n");
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"drop_pack: %d\n", attrule.pkt_detect_rule.pd[i].drop_pack);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"land: %d\n", attrule.pkt_detect_rule.pd[i].land);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"teardrop: %d\n", attrule.pkt_detect_rule.pd[i].teardrop);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"pingdeath: %d\n", attrule.pkt_detect_rule.pd[i].pingdeath);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"pingdeath_value: %d\n", attrule.pkt_detect_rule.pd[i].pingdeath_value);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"\n");
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"traffic detect:\n");
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"drop_pack: %d\n", attrule.tfc_detect_rule.td[i].drop_pack);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"flood_ping: %d\n", attrule.tfc_detect_rule.td[i].flood_ping);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"ping_speed: %d\n", attrule.tfc_detect_rule.td[i].ping_speed);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"flood_udp: %d\n", attrule.tfc_detect_rule.td[i].flood_udp);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"udp_speed: %d\n", attrule.tfc_detect_rule.td[i].udp_speed);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"flood_syn: %d\n", attrule.tfc_detect_rule.td[i].flood_syn);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"syn_speed: %d\n", attrule.tfc_detect_rule.td[i].syn_speed);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"syn_count: %d\n", attrule.tfc_detect_rule.td[i].syn_count);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"\n");
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"attack monitor info:\n");
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"pingpps: %ld\n", attinfo.ai[i].pingpps);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"ping_accum: %ld\n", attinfo.ai[i].ping_accum);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"udppps: %ld\n", attinfo.ai[i].udppps);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"udp_accum: %ld\n", attinfo.ai[i].udp_accum);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"synpps: %ld\n", attinfo.ai[i].synpps);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"syn_accum: %ld\n", attinfo.ai[i].syn_accum);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"syncount: %ld\n", attinfo.ai[i].syncount);
        ptr += len;
        totallen += len;

        len = sprintf((void *)ptr,"syncount_accum: %ld\n", attinfo.ai[i].syncount_accum);
        ptr += len;
        totallen += len;
    }

    len = sprintf((void *)ptr,"----------------------------\n");
    ptr += len;
    totallen += len;


    dp_send_response(COMMAND_SHOW_MEM_POOL_ACK, totallen);
}


void dp_fw_config_show()
{
    uint32_t len = 0;
    uint32_t totallen = 0;
    uint8_t *ptr;
    char *out = (char *)&srv_dp_sync->msgbuf;

    ptr = (uint8_t *)out;

    len = sprintf((void *)ptr, "firewall config:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr,"----------------------------\n");
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr,"defrag fcb max: %d\n", DEFRAG_FCB_MAX);
    ptr += len;
    totallen += len;
    len = sprintf((void *)ptr,"defrag fcb running num: %d\n", fcb_running_num);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr,"syncheck: %s\n", syn_check? "enable":"disable");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr,"directfw: %s sleep_time: %d\n", oct_directfw? "enable":"disable", oct_directfw_sleeptime);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr,"defragmax: %d\n", defrag_cache_max);
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr,"acl default action: %s\n", dp_acl_action_default?"drop":"fw");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr,"unsupport_proto_action: %s\n", unsupport_proto_action?"fw":"drop");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr,"portscan attack detect stat: %s\n", portscan_able?"enable":"disable");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr,"portscan attack detect action: %s\n", portscan_action?"fw":"drop");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr,"flood hold time: %d\n", flood_hold_time);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr,"portscan_exception_freq: %d\n", portscan_exception_freq);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr,"%ld %ld %ld %ld\n", packet_rx[0], packet_rx[1], packet_rx[2], packet_rx[3]);
    ptr += len;
    totallen += len;



    len = sprintf((void *)ptr,"----------------------------\n");
    ptr += len;
    totallen += len;


    dp_send_response(COMMAND_SHOW_MEM_POOL_ACK, totallen);
}


static void *DP_Msg_Process_Fn(void *arg)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);

    MSG_QUE_BODY msgbody;

    printf("dp msg proc thread running\n");

    if(pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0)
    {
        printf("set thread affinity failed\n");
    }

    printf("set thread affinity OK\n");

    dp_msg_queue_id = MSGQUE_Init(SHM_MSGQUE_KEY);
    if(dp_msg_queue_id < 0)
    {
        abort();
    }

    cvmx_linux_enable_xkphys_access(0);

    while(1)
    {
        memset((void *)&msgbody, 0, sizeof(MSG_QUE_BODY));
        msgbody.mtype = COMMAND_DP_END_POINT;
        if(MSGQUE_Recv(dp_msg_queue_id, &msgbody) >= 0)
        {
            switch(msgbody.msg[0])
            {
                case COMMAND_SHOW_BUILD_TIME:
                {
                    dp_show_build_time();
                    break;
                }
                case COMMAND_SHOW_PKT_STAT:
                {
                    dp_show_pkt_stat();
                    break;
                }
                case COMMAND_SHOW_TCPSTREAM_STAT:
                {
                    dp_show_tcpstream_stat();
                    break;
                }
                case COMMAND_SHOW_MEM_POOL:
                {
                    dp_show_mem_pool();
                    break;
                }
                case COMMAND_CLEAR_PKT_STAT:
                {
                    dp_clear_pkt_stat();
                    break;
                }
                case COMMAND_CLEAR_TCPSTREAM_STAT:
                {
                    dp_clear_tcpstream_stat();
                    break;
                }
                case COMMAND_SHOW_FW_FLOW_STAT:
                {
                    dp_show_flow_stat();
                    break;
                }
                case COMMAND_SHOW_ATTACK_STAT:
                {
                    dp_show_attack_stat();
                    break;
                }
                case COMMAND_CLEAR_FW_FLOW_STAT:
                {
                    dp_clear_flow_stat();
                    break;
                }
                case COMMAND_ACL_RULE_COMMIT:
                case COMMAND_ACL_RULE_COMMIT_NOSYNC:
                {
                    dp_acl_rule_commit(msgbody.msg[0]);
                    break;
                }
                case COMMAND_ACL_DEF_ACT_SET:
                {
                    dp_acl_def_act_set();
                    break;
                }
                case COMMAND_SET_TCPSTREAM_TRACK:
                {
                    dp_tcpstream_track_set();
                    break;
                }
                case COMMAND_SET_TCPSTREAM_REASM:
                {
                    dp_tcpstream_reasm_set();
                    break;
                }
                case COMMAND_SET_SYNCHECK:
                {
                    dp_syncheck_set();
                    break;
                }
                case COMMAND_SET_DEFRAGMAX:
                {
                    dp_defrag_max_set();
                    break;
                }
                case COMMAND_SET_UNSUPPORT_PROTO_ACTION:
                {
                    dp_unsupport_proto_action_set();
                    break;
                }
                case COMMAND_SET_DIRECTFW_ABLE:
                {
                    dp_directfw_able_set();
                    break;
                }
                case COMMAND_SHOW_FW_CONFIG:
                {
                    dp_fw_config_show();
                    break;
                }
                case COMMAND_SET_PORTSCAN_ABLE:
                {
                    dp_portscan_able_set();
                    break;
                }
                case COMMAND_SET_MODBUS_ABLE:
                {
                    dp_modbus_able_set();
                    break;
                }
                case COMMAND_SET_MODBUS_VALUE:
                {
                    dp_modbus_value_set();
                    break;
                }
                case COMMAND_SET_PORTSCAN_ACTION:
                {
                    dp_portscan_action_set();
                    break;
                }
                case COMMAND_SET_ATTACK_DEFEND_TIME:
                {
                    dp_attack_defend_time_set();
                    break;
                }
                case COMMAND_SET_PORTSCAN_FREQ:
                {
                    dp_portscan_freq_set();
                    break;
                }
                case COMMAND_SET_SYNFLOOD_FIRST:
                {
                    dp_synflood_start_set();
                    break;

                }
                default:
                {
                    LOGDBG(SEC_DPCMD_DBG_BIT, "unkonw command %ld\n", msgbody.mtype);
                    break;
                }
            }
        }
        else
        {
            continue;
        }
    }

    return NULL;
}



void DP_Msg_Process_Thread_Init()
{
    pthread_create(&dp_msg_process_thread, NULL, DP_Msg_Process_Fn, NULL);
}

void parseBinaryNetlinkMessage(struct nlmsghdr *nh)
{
    int len = nh->nlmsg_len - sizeof(*nh);
    struct ifinfomsg *ifi;

    if (sizeof(*ifi) > (size_t) len) {
        printf("Got a short RTM_NEWLINK message\n");
        return;
    }

    ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
    if ((ifi->ifi_flags & IFF_LOOPBACK) != 0) {
        return;
    }

    struct rtattr *rta = (struct rtattr *)((char *) ifi + NLMSG_ALIGN(sizeof(*ifi)));
    len = NLMSG_PAYLOAD(nh, sizeof(*ifi));

    while(RTA_OK(rta, len)) {
        switch(rta->rta_type) {
            case IFLA_IFNAME:
            {
                char ifname[IFNAMSIZ];
                char *action;
                snprintf(ifname, sizeof(ifname), "%s",(char *) RTA_DATA(rta));
                //action = (ifi->ifi_flags & IFF_LOWER_UP) ? "up" : "down";
                action = (ifi->ifi_flags & IFF_RUNNING) ? "up" : "down";
                printf("%s link %s\n", ifname, action);
                if(ifi->ifi_flags & IFF_RUNNING)
                {
                    if(!strcmp(ifname, "eth0"))
                    {
                        system("ifconfig pow0 up");
                    }
                    else if(!strcmp(ifname, "eth1"))
                    {
                        system("ifconfig pow1 up");
                    }
                    else if(!strcmp(ifname, "eth2"))
                    {
                        system("ifconfig pow2 up");
                    }
                    else if(!strcmp(ifname, "eth3"))
                    {
                        system("ifconfig pow3 up");
                    }
                }
                else
                {
                    if(!strcmp(ifname, "eth0"))
                    {
                        system("ifconfig pow0 down");
                    }
                    else if(!strcmp(ifname, "eth1"))
                    {
                        system("ifconfig pow1 down");
                    }
                    else if(!strcmp(ifname, "eth2"))
                    {
                        system("ifconfig pow2 down");
                    }
                    else if(!strcmp(ifname, "eth3"))
                    {
                        system("ifconfig pow3 down");
                    }
                }
            }
        }

        rta = RTA_NEXT(rta, len);
    }
}


static void *DP_NetStat_Monitor(void *arg)
{
    struct sockaddr_nl addr;
    int sock, len;
    char buffer[4096];
    struct nlmsghdr *nlh;


    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);

    printf("DP_NetStat_Monitor thread running\n");

    if(pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0)
    {
        printf("set thread affinity failed\n");
    }

    printf("set thread affinity OK\n");


    if ((sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) {
        perror("couldn't open NETLINK_ROUTE socket");
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("couldn't bind");
        return NULL;
    }

    system("./netstat_monitor.sh");


    while (1 && (len = recv(sock, buffer, 4096, 0)) > 0) {
        nlh = (struct nlmsghdr *)buffer;
        while ((NLMSG_OK(nlh, (unsigned int)len)) && (nlh->nlmsg_type != NLMSG_DONE)) {
            if (nlh->nlmsg_type == RTM_NEWLINK){
                parseBinaryNetlinkMessage(nlh);
            }
            nlh = NLMSG_NEXT(nlh, len);
        }
    }
    close(sock);

    return NULL;
}


void DP_NetStat_Monitor_Init()
{
    pthread_create(&dp_netstat_monitor_thread, NULL, DP_NetStat_Monitor, NULL);
}

#if 0
void oct_rx_process_command(cvmx_wqe_t *wq)
{
    uint16_t opcode = oct_rx_command_get(wq);
    //void *data;
    if(opcode == COMMAND_INVALID)
    {
        oct_packet_free(wq, wqe_pool);
        return;
    }

    //data = cvmx_phys_to_ptr(wq->packet_ptr.s.addr);

    switch(opcode)
    {
        default:
        {
            LOGDBG(SEC_DPCMD_DBG_BIT, "unsupport command\n");
            oct_packet_free(wq, wqe_pool);
            break;
        }
    }
}
#endif

