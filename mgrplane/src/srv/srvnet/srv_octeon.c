#include "srv_octeon.h"
#include <message.h>
#include <trans.h>
#include <pow.h>
#include <rpc-common.h>
#include <shm.h>


extern int dp_msg_queue_id;




int octeon_rpccall(uint8_t * from, uint32_t length, uint32_t fd, void *param_p, cmd_type_t cmdack, uint16_t opcode)
{
    int ret;
    uint8_t recv_buf[MAX_RECV_LEN];
    uint32_t recv_len = MAX_RECV_LEN ;
    uint16_t info_len;
    uint8_t s_buf[MAX_BUF];
    rpc_msg_t rpcmsg;

    cmd_type_t cmd_ack = cmdack;
    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;
    char *ptr = rcp_param_p->params_list.info_buf + rcp_param_p->info_len;

    rpcmsg.opcode = opcode;
    rpcmsg.info_len = 0;

    ret = pow_rpc_syncall2dp(&comm_pow, (void *)&rpcmsg, sizeof(rpc_msg_t), recv_buf, &recv_len);
    if(ret < 0)
    {
        return -1;
    }

    info_len = ((rpc_msg_t *)&recv_buf)->info_len;
    if((info_len + sizeof(rpc_msg_t)) != recv_len)
        return -1;

    memcpy((void *)ptr, (void *)((rpc_msg_t *)&recv_buf)->info_buf, info_len);
    ptr[info_len] = 0;
    ptr += info_len;
    rcp_param_p->info_len += info_len;

    send_rcp_res(cmd_ack, from, s_buf, fd, param_p, 0);

    return 0;
}


int octeon_msgque_rpccall(uint8_t * from, uint32_t length, uint32_t fd, void *param_p, cmd_type_t cmdack, uint16_t opcode)
{
    int ret;
    MSG_QUE_BODY msgsnd;
    MSG_QUE_BODY msgrcv;
    uint8_t s_buf[MAX_BUF];
    uint16_t info_len;

    memset((void *)&msgsnd, 0, sizeof(MSG_QUE_BODY));
    memset((void *)&msgrcv, 0, sizeof(MSG_QUE_BODY));

    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;
    char *ptr = rcp_param_p->params_list.info_buf;
    memset((void *)&srv_dp_sync->msgbuf, 0, sizeof(srv_dp_sync->msgbuf));

    msgsnd.mtype = (long)COMMAND_DP_END_POINT;
    msgsnd.msg[0] = (uint64_t)opcode;

    ret = MSGQUE_Rpc_Syncall2dp(dp_msg_queue_id, &msgsnd, &msgrcv);
    if(ret < 0)
    {
        return -1;
    }

    info_len = (uint16_t)msgrcv.msg[0];

    memcpy((void *)ptr, (void *)(&srv_dp_sync->msgbuf), info_len);
    ptr[info_len] = 0;
    ptr += info_len;
    rcp_param_p->info_len += info_len;

    send_rcp_res(cmdack, from, s_buf, fd, param_p, 0);

    return 0;
}


int octeon_show_test_command(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    int len;
    uint8_t s_buf[MAX_BUF];
    cmd_type_t cmd_ack = TEST_COMMAND_ACK;
    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;
    char *ptr = rcp_param_p->params_list.info_buf + rcp_param_p->info_len;

    len = sprintf(ptr, "show test command.\n");
    ptr += len;
    rcp_param_p->info_len += len;


    send_rcp_res(cmd_ack, from, s_buf, fd, param_p, 0);
    LOG("show test command\n");
    return 0;
}


int octeon_set_dbg_print(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    int len;
    uint8_t s_buf[MAX_BUF];
    cmd_type_t cmd_ack = SET_DBG_PRINT_ACK;
    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;
    char *ptr = rcp_param_p->params_list.info_buf + rcp_param_p->info_len;

    RCP_BLOCK_DBG_PRINT *blocks = (RCP_BLOCK_DBG_PRINT *)(from + MESSAGE_HEADER_LENGTH);


    srv_dp_sync->dp_debugprint |= blocks->dbgprint;

    len = sprintf(ptr, "OK.\n");
    ptr += len;
    rcp_param_p->info_len += len;

    send_rcp_res(cmd_ack, from, s_buf, fd, param_p, 0);
    LOG("octeon_set_dbg_print\n");
    return 0;
}


int octeon_set_tcpstream_track(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("octeon_set_tcpstream_track\n");

    RCP_BLOCK_TCPSTREAM_TRACK_ABLE *blocks = (RCP_BLOCK_TCPSTREAM_TRACK_ABLE *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_tcpstream_track = blocks->able;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_TCPSTREAM_TRACK_ABLE_ACK, COMMAND_SET_TCPSTREAM_TRACK);

    return 0;
}

int octeon_set_directfw_able(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("octeon_set_directfw_able\n");

    RCP_BLOCK_DIRECTFW_ABLE *blocks = (RCP_BLOCK_DIRECTFW_ABLE *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_directfw_able = blocks->able;
    srv_dp_sync->dp_directfw_sleep_time = blocks->sleep_time;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_DIRECT_FW_ACK, COMMAND_SET_DIRECTFW_ABLE);

    return 0;
}


int octeon_set_tcpstream_reasm(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("octeon_set_tcpstream_track\n");

    RCP_BLOCK_TCPSTREAM_REASM_ABLE *blocks = (RCP_BLOCK_TCPSTREAM_REASM_ABLE *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_tcpstream_reasm = blocks->able;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_TCPSTREAM_REASM_ABLE_ACK, COMMAND_SET_TCPSTREAM_REASM);

    return 0;
}



int octeon_clear_dbg_print(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    int len;
    uint8_t s_buf[MAX_BUF];
    cmd_type_t cmd_ack = CLEAR_DBG_PRINT_ACK;
    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;
    char *ptr = rcp_param_p->params_list.info_buf + rcp_param_p->info_len;

    srv_dp_sync->dp_debugprint = 0;

    len = sprintf(ptr, "OK.\n");
    ptr += len;
    rcp_param_p->info_len += len;

    send_rcp_res(cmd_ack, from, s_buf, fd, param_p, 0);
    LOG("octeon_clear_dbg_print\n");
    return 0;
}

int octeon_clear_tcpstream_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("octeon_clear_dp_pkt_stat\n");
    return octeon_msgque_rpccall(from, length, fd, param_p, CLEAR_TCPSTREAM_STAT_ACK, COMMAND_CLEAR_TCPSTREAM_STAT);
}

int octeon_show_dp_build_time(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{

    LOG("octeon_show_dp_build_time\n");
    return octeon_msgque_rpccall(from, length, fd, param_p, SHOW_DP_BUILD_TIME_ACK, COMMAND_SHOW_BUILD_TIME);

}

int octeon_show_dp_pkt_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("octeon_show_dp_pkt_stat\n");
    return octeon_msgque_rpccall(from, length, fd, param_p, SHOW_DP_PKT_STAT_ACK, COMMAND_SHOW_PKT_STAT);
}

int octeon_show_tcpstream_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("octeon_show_tcpstream_stat\n");
    return octeon_msgque_rpccall(from, length, fd, param_p, SHOW_TCPSTREAM_STAT_ACK, COMMAND_SHOW_TCPSTREAM_STAT);
}


int octeon_clear_dp_pkt_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("octeon_clear_dp_pkt_stat\n");
    return octeon_msgque_rpccall(from, length, fd, param_p, CLEAR_DP_PKT_STAT_ACK, COMMAND_CLEAR_PKT_STAT);
}


int octeon_show_mem_pool(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{

    LOG("octeon_show_mem_pool\n");
    return octeon_msgque_rpccall(from, length, fd, param_p, SHOW_MEM_POOL_ACK, COMMAND_SHOW_MEM_POOL);
}


