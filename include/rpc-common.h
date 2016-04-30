#ifndef __OPCODE_H__
#define __OPCODE_H__

#include <stdint.h>


#define ETH_P 0x3322


#define COMMAND_INVALID              0x0

#define COMMAND_DP_END_POINT         0xA000
#define COMMAND_SRV_END_POINT        0xB000

#define COMMAND_SHOW_BUILD_TIME      0xA001
#define COMMAND_SHOW_BUILD_TIME_ACK  0xB001

#define COMMAND_SHOW_PKT_STAT        0xA002
#define COMMAND_SHOW_PKT_STAT_ACK    0xB002

#define COMMAND_SHOW_MEM_POOL        0xA003
#define COMMAND_SHOW_MEM_POOL_ACK    0xB003

#define COMMAND_ACL_RULE_COMMIT      0xA004
#define COMMAND_ACL_RULE_COMMIT_ACK  0XB004

#define COMMAND_ACL_DEF_ACT_SET      0xA005
#define COMMAND_ACL_DEF_ACT_SET_ACK  0xB005

#define COMMAND_CLEAR_PKT_STAT       0xA006
#define COMMAND_CLEAR_PKT_STAT_ACK   0xB006

#define COMMAND_SHOW_FW_FLOW_STAT      0xA007
#define COMMAND_SHOW_FW_FLOW_STAT_ACK  0xB007

#define COMMAND_CLEAR_FW_FLOW_STAT     0xA008
#define COMMAND_CLEAR_FW_FLOW_STAT_ACK 0xB008

#define COMMAND_ACL_RULE_COMMIT_NOSYNC  0xA009
#define COMMAND_ACL_RULE_COMMIT_NOSYNC_ACK 0xB009

#define COMMAND_SHOW_TCPSTREAM_STAT       0xA00A
#define COMMAND_SHOW_TCPSTREAM_STAT_ACK   0xB00A

#define COMMAND_CLEAR_TCPSTREAM_STAT     0xA00B
#define COMMAND_CLEAR_TCPSTREAM_STAT_ACK 0xB00B

#define COMMAND_SET_TCPSTREAM_TRACK      0xA00C
#define COMMAND_SET_TCPSTREAM_TRACK_ACK  0xB00C

#define COMMAND_SET_TCPSTREAM_REASM      0xA00D
#define COMMAND_SET_TCPSTREAM_REASM_ACK  0xB00D

#define COMMAND_SET_SYNCHECK             0xA00E
#define COMMAND_SET_SYNCHECK_ACK         0xB00E

#define COMMAND_SET_DEFRAGMAX            0xA00F
#define COMMAND_SET_DEFRAGMAX_ACK        0xB00F

#define COMMAND_SHOW_ATTACK_STAT       0xA010
#define COMMAND_SHOW_ATTACK_STAT_ACK   0xB010

#define COMMAND_SET_UNSUPPORT_PROTO_ACTION 0xA011
#define COMMAND_SET_UNSUPPORT_PROTO_ACTION_ACK 0xB011

#define COMMAND_SET_DIRECTFW_ABLE          0xA012
#define COMMAND_SET_DIRECTFW_ABLE_ACK      0xB012

#define COMMAND_SHOW_FW_CONFIG    0xA013
#define COMMAND_SHOW_FW_CONFIG_ACK 0xB013

#define COMMAND_SET_PORTSCAN_ABLE         0xA014
#define COMMAND_SET_PORTSCAN_ABLE_ACK     0xB014

#define COMMAND_SET_PORTSCAN_ACTION     0xA015
#define COMMAND_SET_PORTSCAN_ACTION_ACK 0xB015

#define COMMAND_SET_ATTACK_DEFEND_TIME      0xA016
#define COMMAND_SET_ATTACK_DEFEND_TIME_ACK  0xB016

#define COMMAND_SET_PORTSCAN_FREQ       0xA017
#define COMMAND_SET_PORTSCAN_FREQ_ACK   0xB017

#define COMMAND_SET_SYNFLOOD_FIRST      0xA018
#define COMMAND_SET_SYNFLOOD_FIRST_ACK  0xB018

#define COMMAND_SET_MODBUS_ABLE         0xA019
#define COMMAND_SET_MODBUS_ABLE_ACK      0xB019

#define COMMAND_SET_MODBUS_VALUE     0xA01A
#define COMMAND_SET_MODBUS_VALUE_ACK  0xB01A


#define MAX_BUF_SIZE 1000


typedef struct tag_RCP_BLOCK_ACL_RULE_TUPLE{
    uint64_t time_start;
    uint64_t time_end;
    uint8_t smac[6];
    uint8_t dmac[6];
    uint16_t sport_start;
    uint16_t sport_end;
    uint32_t sip;
    uint32_t dip;
    uint32_t sip_mask;
    uint32_t dip_mask;
    uint16_t dport_start;
    uint16_t dport_end;
    uint8_t protocol_start;
    uint8_t protocol_end;
    uint16_t action;
    uint32_t logable;
}__attribute__ ((__packed__)) RCP_BLOCK_ACL_RULE_TUPLE;


/*
  *uniform data struct for packing/unpacking
  */
typedef struct {
    int16_t opcode;
    int16_t info_len; //used by show info message
    char info_buf[0]; //used by show info message
}rpc_msg_t;

typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
} rpc_ether_hdr_t;





#endif
