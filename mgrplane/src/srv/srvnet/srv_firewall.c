#include "srv_firewall.h"
#include "srv_octeon.h"
#include <shm.h>


int FW_show_flow_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_show_flow_stat\n");
    return octeon_msgque_rpccall(from, length, fd, param_p, SHOW_FW_FLOW_STAT_ACK, COMMAND_SHOW_FW_FLOW_STAT);
}

int FW_show_attack_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_show_attack_stat\n");
    return octeon_msgque_rpccall(from, length, fd, param_p, SHOW_ATTACK_STAT_ACK, COMMAND_SHOW_ATTACK_STAT);
}


int FW_show_fw_config(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_show_attack_stat\n");
    return octeon_msgque_rpccall(from, length, fd, param_p, SHOW_ATTACK_STAT_ACK, COMMAND_SHOW_FW_CONFIG);
}



int FW_clear_flow_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_clear_flow_stat\n");
    return octeon_msgque_rpccall(from, length, fd, param_p, CLEAR_FW_FLOW_STAT_ACK, COMMAND_CLEAR_FW_FLOW_STAT);
}


int FW_set_syncheck(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_set_syncheck\n");
    RCP_BLOCK_TCPSTREAM_SYNCHECK_ABLE *blocks = (RCP_BLOCK_TCPSTREAM_SYNCHECK_ABLE *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_syncheck_able = blocks->able;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_SYNCHECK_ABLE_ACK, COMMAND_SET_SYNCHECK);

    return 0;
}

int FW_set_portscan(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_set_portscan\n");
    RCP_BLOCK_PORTSCAN_ABLE *blocks = (RCP_BLOCK_PORTSCAN_ABLE *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_portscan_able = blocks->able;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_PORTSCAN_ABLE, COMMAND_SET_PORTSCAN_ABLE);

    return 0;
}

int FW_set_modbus(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_set_modbus\n");
    RCP_BLOCK_MODBUS_ABLE *blocks = (RCP_BLOCK_MODBUS_ABLE *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_modbus_able = blocks->able;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_MODBUS_ABLE, COMMAND_SET_MODBUS_ABLE);

    return 0;
}

int FW_set_defragmax(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_set_defragmax\n");
    RCP_BLOCK_DEFRAG_MAX *blocks = (RCP_BLOCK_DEFRAG_MAX *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_defragmax = blocks->num;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_DEFRAG_MAX_ACK, COMMAND_SET_DEFRAGMAX);

    return 0;
}

int FW_set_unsupportaction(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_set_unsupportaction\n");
    RCP_BLOCK_UNSUPPORT_PROTO_ACTION *blocks = (RCP_BLOCK_UNSUPPORT_PROTO_ACTION *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_unsupportproto_action = blocks->action;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_UNSUPPORT_PROTO_ACTION, COMMAND_SET_UNSUPPORT_PROTO_ACTION);

    return 0;
}

int FW_set_portscanaction(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_set_portscanaction\n");
    RCP_BLOCK_PORTSCAN_ACTION *blocks = (RCP_BLOCK_PORTSCAN_ACTION *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_portscan_action = blocks->action;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_PORTSCAN_ACTION, COMMAND_SET_PORTSCAN_ACTION);

    return 0;
}

int FW_set_attack_defend_time(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_set_attack_defend_time\n");
    RCP_BLOCK_DEFEND_TIME *blocks = (RCP_BLOCK_DEFEND_TIME *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_attack_defend_time = blocks->seconds;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_ATTACK_DEFEND_TIME, COMMAND_SET_ATTACK_DEFEND_TIME);

    return 0;
}

int FW_set_portscan_freq(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_set_portscan_freq\n");
    RCP_BLOCK_PORTSCAN_FREQ *blocks = (RCP_BLOCK_PORTSCAN_FREQ *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_portscan_freq = blocks->pps;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_PORTSCAN_FREQ, COMMAND_SET_PORTSCAN_FREQ);

    return 0;
}

int FW_set_synflood_start(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_set_synflood_start\n");
    RCP_BLOCK_SYNFLOOD_START *blocks = (RCP_BLOCK_SYNFLOOD_START *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_synflood_start = blocks->start;
    srv_dp_sync->dp_synflood_end = blocks->end;
    srv_dp_sync->dp_synflood_percent = blocks->percent;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_SYNFLOOD_START, COMMAND_SET_SYNFLOOD_FIRST);

    return 0;
}

int FW_set_modbus_value(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("FW_set_modbus_value\n");
    RCP_BLOCK_MODBUS_VALUE *blocks = (RCP_BLOCK_MODBUS_VALUE *)(from + MESSAGE_HEADER_LENGTH);

    srv_dp_sync->dp_modbus_func = blocks->func;
    srv_dp_sync->dp_modbus_addr = blocks->addr;
    srv_dp_sync->dp_modbus_min = blocks->min;
    srv_dp_sync->dp_modbus_max = blocks->max;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_MODBUS_VALUE, COMMAND_SET_MODBUS_VALUE);

    return 0;

}


