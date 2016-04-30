#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "cparser.h"
#include "cparser_token.h"


#include "message.h"
#include "cli_trans.h"
#include "shm.h"

cparser_result_t
cparser_cmd_show_dp_build_time (cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = SHOW_DP_BUILD_TIME;
    rcp_para.nparam = 0;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);


    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_show_pkt_stat (cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = SHOW_DP_PKT_STAT;
    rcp_para.nparam = 0;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_show_tcpstream_stat (cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = SHOW_TCPSTREAM_STAT;
    rcp_para.nparam = 0;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}


cparser_result_t
cparser_cmd_clear_pkt_stat (cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = CLEAR_DP_PKT_STAT;
    rcp_para.nparam = 0;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}



cparser_result_t
cparser_cmd_show_mem_pool (cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = SHOW_MEM_POOL;
    rcp_para.nparam = 0;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);


    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_set_debug_print_dbg(cparser_context_t *context, char **dbg)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_DBG_PRINT;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].DbgPrint.dbgprint = 0;

    if (!strcmp(*dbg, "rx")) {
        LOG("dbg is rx\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_RX_DBG_BIT;
    }else if (!strcmp(*dbg, "pktdump")) {
        LOG("dbg is pktdump\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_PACKET_DUMP;
    }else if (!strcmp(*dbg, "decode")) {
        LOG("dbg is decode\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_DECODE_DBG_BIT;
    }else if (!strcmp(*dbg, "ethernet")) {
        LOG("dbg is ethernet\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_ETHERNET_DBG_BIT;
    }else if (!strcmp(*dbg, "ipv4")) {
        LOG("dbg is ipv4\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_IPV4_DBG_BIT;
    }else if (!strcmp(*dbg, "tcp")) {
        LOG("dbg is tcp\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_TCP_DBG_BIT;
    }else if (!strcmp(*dbg, "udp")) {
        LOG("dbg is udp\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_UDP_DBG_BIT;
    }else if (!strcmp(*dbg, "flow")) {
        LOG("dbg is flow\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_FLOW_DBG_BIT;
    }else if (!strcmp(*dbg, "defrag")) {
        LOG("dbg is defrag\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_DEFRAG_DBG_BIT;
    }else if (!strcmp(*dbg, "acl")) {
        LOG("dbg is acl\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_ACL_DBG_BIT;
    }else if (!strcmp(*dbg, "l7")) {
        LOG("dbg is l7\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_L7_DBG_BIT;
    }
    else if (!strcmp(*dbg, "dpcmd")) {
        LOG("dbg is dpcmd\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_DPCMD_DBG_BIT;
    }
    else if (!strcmp(*dbg, "streamtcp_dbg")) {
        LOG("dbg is streamtcp_dbg\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_STREAMTCP_DBG_BIT;
    }
    else if (!strcmp(*dbg, "streamtcp_track")) {
        LOG("dbg is streamtcp_track\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_STREAMTCP_TRACK_DBG_BIT;
    }
    else if (!strcmp(*dbg, "streamtcp_reasm")) {
        LOG("dbg is streamtcp_reasm\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_STREAMTCP_REASM_DBG_BIT;
    }
    else if (!strcmp(*dbg, "attack_dbg"))
    {
        LOG("dbg is attack_dbg\n");
        rcp_para.params_list.params[0].DbgPrint.dbgprint = SEC_ATTACK_DBG_BIT;
    }

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_clear_debug_print(cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = CLEAR_DBG_PRINT;
    rcp_para.nparam = 0;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_clear_tcpstream_stat(cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = CLEAR_TCPSTREAM_STAT;
    rcp_para.nparam = 0;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_set_tcpstream_track_able(cparser_context_t *context, char **able)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_TCPSTREAM_TRACK_ABLE;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].TrackAble.able = 0;

    if (!strcmp(*able, "enable")) {
        LOG("enable\n");
        rcp_para.params_list.params[0].TrackAble.able = 1;
    }else if (!strcmp(*able, "disable")) {
        LOG("disable\n");
        rcp_para.params_list.params[0].TrackAble.able = 0;
    }

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}


cparser_result_t
cparser_cmd_set_tcpstream_reasm_able(cparser_context_t *context, char **able)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_TCPSTREAM_REASM_ABLE;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].ReasmAble.able = 0;

    if (!strcmp(*able, "enable")) {
        LOG("enable\n");
        rcp_para.params_list.params[0].ReasmAble.able = 1;
    }else if (!strcmp(*able, "disable")) {
        LOG("disable\n");
        rcp_para.params_list.params[0].ReasmAble.able = 0;
    }

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_set_defrag_fragment_max_num(cparser_context_t *context, uint32_t *num)
{
    assert(context);
    assert(num);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_DEFRAG_MAX;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].DefragMax.num = *num;

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);


    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_set_direct_fw_able_sleep_time_sleep(cparser_context_t *context, char **able, uint32_t *sleep)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_DIRECT_FW;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].DirfwAble.able = 0;

    if (!strcmp(*able, "enable")) {
        LOG("enable\n");
        rcp_para.params_list.params[0].DirfwAble.able = 1;
        rcp_para.params_list.params[0].DirfwAble.sleep_time = *sleep;
    }else if (!strcmp(*able, "disable")) {
        LOG("disable\n");
        rcp_para.params_list.params[0].TrackAble.able = 0;
    }

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}




