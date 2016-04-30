#include "common.h"
#include "message.h"

#include <srv_octeon.h>
#include <srv_rule.h>
#include <srv_firewall.h>

static struct rcp_msg_params_s rcp_param;




int process_test_command(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_test_command \n");

    octeon_show_test_command(from, length, fd, (void *)&rcp_param);

    return 0;
}


int process_show_dp_build_time(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));
    LOG("process_show_dp_build_time \n");

    octeon_show_dp_build_time(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_show_dp_pkt_stat(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));
    LOG("process_show_dp_pkt_stat \n");

    octeon_show_dp_pkt_stat(from, length, fd, (void *)&rcp_param);

    return 0;
}


int process_show_tcpstream_stat(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));
    LOG("process_show_tcpstream_stat \n");

    octeon_show_tcpstream_stat(from, length, fd, (void *)&rcp_param);

    return 0;
}


int process_clear_dp_pkt_stat(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));
    LOG("process_clear_dp_pkt_stat \n");

    octeon_clear_dp_pkt_stat(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_show_mem_pool(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_show_mem_pool \n");

    octeon_show_mem_pool(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_show_acl_rule(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));
    LOG("process_show_acl_rule \n");

    Rule_show_acl_rule(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_add_acl_rule(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_add_acl_rule \n");

    Rule_add_acl_rule(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_del_acl_rule(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_del_acl_rule \n");

    Rule_del_acl_rule(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_del_acl_rule_id(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_del_acl_rule_id \n");

    Rule_del_acl_rule_id(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_del_acl_rule_all(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_del_acl_rule_all \n");

    Rule_del_acl_rule_all(from, length, fd, (void *)&rcp_param);

    return 0;
}


int process_commit_acl_rule(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_commit_acl_rule \n");

    Rule_commit_acl_rule(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_set_acl_def_act(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_commit_acl_rule \n");

    Rule_set_acl_def_act(from, length, fd, (void *)&rcp_param);

    return 0;
}


int process_show_acl_def_act(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_show_acl_def_act \n");

    Rule_show_acl_def_act(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_show_flow_stat(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_show_flow_stat \n");

    FW_show_flow_stat(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_show_attack_stat(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_show_attack_stat \n");

    FW_show_attack_stat(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_show_fw_config(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_show_fw_config \n");

    FW_show_fw_config(from, length, fd, (void *)&rcp_param);

    return 0;

}


int process_clear_flow_stat(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_clear_flow_stat \n");

    FW_clear_flow_stat(from, length, fd, (void *)&rcp_param);

    return 0;
}



int process_set_dbg_print(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_dbg_print \n");

    octeon_set_dbg_print(from, length, fd, (void *)&rcp_param);

    return 0;
}






int process_set_tcpstream_track(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_commit_acl_rule \n");

    octeon_set_tcpstream_track(from, length, fd, (void *)&rcp_param);

    return 0;

}

int process_set_directfw_able(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_directfw_able \n");

    octeon_set_directfw_able(from, length, fd, (void *)&rcp_param);

    return 0;

}

int process_set_tcpstream_reasm(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_tcpstream_reasm_stat \n");

    octeon_set_tcpstream_reasm(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_set_syncheck(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_syncheck \n");

    FW_set_syncheck(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_set_portscan(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_portscan \n");

    FW_set_portscan(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_set_modbus_able(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_modbus_able \n");

    FW_set_modbus(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_set_defrag_max(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_defrag_max \n");

    FW_set_defragmax(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_set_unsupport_action(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_unsupport_action \n");

    FW_set_unsupportaction(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_set_portscan_action(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_portscan_action \n");

    FW_set_portscanaction(from, length, fd, (void *)&rcp_param);

    return 0;
}


int process_set_attack_defend_time(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_attack_defend_time \n");

    FW_set_attack_defend_time(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_set_portscan_freq(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_portscan_freq \n");

    FW_set_portscan_freq(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_set_synflood_start(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_synflood_start \n");

    FW_set_synflood_start(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_set_modbus_value(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_set_modbus_value \n");

    FW_set_modbus_value(from, length, fd, (void *)&rcp_param);

    return 0;
}

int process_clear_dbg_print(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));

    LOG("process_clear_dbg_print \n");

    octeon_clear_dbg_print(from, length, fd, (void *)&rcp_param);

    return 0;
}


int process_clear_tcpstream_stat(uint8_t * from, uint32_t length, uint32_t fd)
{
    memset(&rcp_param, 0, sizeof(struct rcp_msg_params_s));
    LOG("process_clear_dp_pkt_stat \n");

    octeon_clear_tcpstream_stat(from, length, fd, (void *)&rcp_param);

    return 0;


}


int32_t init_cmd_process_handle(void)
{
    memset(cmd_process_handles, 0, sizeof(struct cmd_process_handle_s) * MAX_COMMAND_TYPE);

    register_cmd_process_handle(TEST_COMMAND, process_test_command);
    register_cmd_process_handle(SHOW_DP_BUILD_TIME, process_show_dp_build_time);
    register_cmd_process_handle(SHOW_DP_PKT_STAT, process_show_dp_pkt_stat);
    register_cmd_process_handle(SHOW_MEM_POOL, process_show_mem_pool);
    register_cmd_process_handle(SHOW_ACL_RULE, process_show_acl_rule);
    register_cmd_process_handle(ADD_ACL_RULE, process_add_acl_rule);
    register_cmd_process_handle(DEL_ACL_RULE, process_del_acl_rule);
    register_cmd_process_handle(DEL_ACL_RULE_ID, process_del_acl_rule_id);
    register_cmd_process_handle(DEL_ACL_RULE_ALL, process_del_acl_rule_all);
    register_cmd_process_handle(COMMIT_ACL_RULE, process_commit_acl_rule);
    register_cmd_process_handle(SET_ACL_DEF_ACT, process_set_acl_def_act);
    register_cmd_process_handle(SHOW_ACL_DEF_ACT, process_show_acl_def_act);
    register_cmd_process_handle(CLEAR_DP_PKT_STAT, process_clear_dp_pkt_stat);
    register_cmd_process_handle(SHOW_FW_FLOW_STAT, process_show_flow_stat);
    register_cmd_process_handle(CLEAR_FW_FLOW_STAT, process_clear_flow_stat);
    register_cmd_process_handle(SET_DBG_PRINT, process_set_dbg_print);
    register_cmd_process_handle(CLEAR_DBG_PRINT, process_clear_dbg_print);
    register_cmd_process_handle(SHOW_TCPSTREAM_STAT, process_show_tcpstream_stat);
    register_cmd_process_handle(CLEAR_TCPSTREAM_STAT, process_clear_tcpstream_stat);
    register_cmd_process_handle(SET_TCPSTREAM_TRACK_ABLE, process_set_tcpstream_track);
    register_cmd_process_handle(SET_TCPSTREAM_REASM_ABLE, process_set_tcpstream_reasm);
    register_cmd_process_handle(SET_SYNCHECK_ABLE, process_set_syncheck);
    register_cmd_process_handle(SET_DEFRAG_MAX, process_set_defrag_max);
    register_cmd_process_handle(SHOW_ATTACK_STAT, process_show_attack_stat);
    register_cmd_process_handle(SET_UNSUPPORT_PROTO_ACTION, process_set_unsupport_action);
    register_cmd_process_handle(SET_DIRECT_FW, process_set_directfw_able);
    register_cmd_process_handle(SHOW_FW_CONFIG, process_show_fw_config);
    register_cmd_process_handle(SET_PORTSCAN_ABLE, process_set_portscan);
    register_cmd_process_handle(SET_PORTSCAN_ACTION, process_set_portscan_action);
    register_cmd_process_handle(SET_ATTACK_DEFEND_TIME, process_set_attack_defend_time);
    register_cmd_process_handle(SET_PORTSCAN_FREQ, process_set_portscan_freq);
    register_cmd_process_handle(SET_SYNFLOOD_START, process_set_synflood_start);
    register_cmd_process_handle(SET_MODBUS_ABLE, process_set_modbus_able);
    register_cmd_process_handle(SET_MODBUS_VALUE, process_set_modbus_value);
    return 0;
}



