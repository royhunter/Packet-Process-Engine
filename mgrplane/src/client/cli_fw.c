#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "cparser.h"
#include "cparser_token.h"


#include "common.h"
#include "message.h"
#include "cli_trans.h"

cparser_result_t
cparser_cmd_show_firewall_config(cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = SHOW_FW_CONFIG;
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
cparser_cmd_show_attack_stat(cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = SHOW_ATTACK_STAT;
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
cparser_cmd_show_firewall_flow_stat (cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = SHOW_FW_FLOW_STAT;
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
cparser_cmd_clear_firewall_flow_stat (cparser_context_t *context)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));
    cmd = CLEAR_FW_FLOW_STAT;
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
cparser_cmd_set_firewall_syncheck_able(cparser_context_t *context, char **able)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_SYNCHECK_ABLE;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].SyncheckAble.able = 0;

    if (!strcmp(*able, "enable")) {
        LOG("enable\n");
        rcp_para.params_list.params[0].SyncheckAble.able = 1;
    }else if (!strcmp(*able, "disable")) {
        LOG("disable\n");
        rcp_para.params_list.params[0].SyncheckAble.able = 0;
    }

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;

}

cparser_result_t
cparser_cmd_set_portscan_able(cparser_context_t *context, char **able)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_PORTSCAN_ABLE;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].PortscanAble.able = 0;

    if (!strcmp(*able, "enable")) {
        LOG("enable\n");
        rcp_para.params_list.params[0].PortscanAble.able = 1;
    }else if (!strcmp(*able, "disable")) {
        LOG("disable\n");
        rcp_para.params_list.params[0].PortscanAble.able = 0;
    }

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}


cparser_result_t
cparser_cmd_set_firewall_unsupport_proto_action(cparser_context_t *context, char **action)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_UNSUPPORT_PROTO_ACTION;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    if (!strcmp(*action, "fw")) {
        LOG("fw\n");
        rcp_para.params_list.params[0].Unsupportaction.action = 1;
    }else if (!strcmp(*action, "drop")) {
        LOG("drop\n");
        rcp_para.params_list.params[0].Unsupportaction.action = 0;
    }

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;

}

cparser_result_t
cparser_cmd_set_portscan_action_action(cparser_context_t *context, char **action)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_PORTSCAN_ACTION;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    if (!strcmp(*action, "fw")) {
        LOG("fw\n");
        rcp_para.params_list.params[0].PortscanAction.action = 1;
    }else if (!strcmp(*action, "drop")) {
        LOG("drop\n");
        rcp_para.params_list.params[0].PortscanAction.action = 0;
    }

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;

}

cparser_result_t
cparser_cmd_set_attack_defend_time_seconds(cparser_context_t *context, uint32_t *seconds)
{
    assert(context);
    assert(seconds);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_ATTACK_DEFEND_TIME;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].DefendTime.seconds= *seconds;

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);


    return CPARSER_OK;
}



cparser_result_t
cparser_cmd_set_portscan_freq_pps(cparser_context_t *context, uint32_t *pps)
{
    assert(context);
    assert(pps);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_PORTSCAN_FREQ;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].PortscanFreq.pps= *pps;

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);


    return CPARSER_OK;
}


cparser_result_t
cparser_cmd_set_synflood_start_start_end_end_percent_percent(cparser_context_t *context, uint32_t *start, uint32_t *end, uint32_t *percent)
{
    assert(context);
    assert(start);
    assert(end);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_SYNFLOOD_START;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].SynfloodStart.start= *start;
    rcp_para.params_list.params[0].SynfloodStart.end= *end;
    rcp_para.params_list.params[0].SynfloodStart.percent = *percent;

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);


    return CPARSER_OK;

}

cparser_result_t
cparser_cmd_set_modbus_value_able(cparser_context_t *context, char **able)
{
    assert(context);

    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_MODBUS_ABLE;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].ModbusAble.able = 0;

    if (!strcmp(*able, "enable")) {
        LOG("enable\n");
        rcp_para.params_list.params[0].ModbusAble.able = 1;
    }else if (!strcmp(*able, "disable")) {
        LOG("disable\n");
        rcp_para.params_list.params[0].PortscanAble.able = 0;
    }

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);

    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_set_modbus_func_func_addr_addr_value_min_min_value_max_max(cparser_context_t *context,
                                                        uint32_t *func,
                                                        uint32_t *addr,
                                                        uint32_t *min,
                                                        uint32_t *max)
{
    assert(context);


    int sn;
    cmd_type_t cmd;
    struct rcp_msg_params_s rcp_para;
    memset(&rcp_para, 0, sizeof(struct rcp_msg_params_s));

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    cmd = SET_MODBUS_VALUE;
    rcp_para.nparam = 1;
    rcp_para.more_flag = 0;
    rcp_para.msg_id = g_msg_id;
    g_msg_id++;
    LOG("cmd=%d\n", cmd);

    rcp_para.params_list.params[0].ModubsValue.func = *func;
    rcp_para.params_list.params[0].ModubsValue.addr = *addr;
    rcp_para.params_list.params[0].ModubsValue.min = *min;
    rcp_para.params_list.params[0].ModubsValue.max = *max;

    cmd_msg_handles[cmd].pack(cmd, &rcp_para, send_buf, &sn);
    LOG("after pack the message\n");

    process_cli_show_cmd(recv_buf, send_buf, sn);


    return CPARSER_OK;

}


