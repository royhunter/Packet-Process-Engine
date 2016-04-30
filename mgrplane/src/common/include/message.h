#ifndef __MESSAGE__H__
#define __MESSAGE__H__

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"
#include "rpc-common.h"
#include "acl_rule.h"

#define SERV_LOCAL 0x7f000001
#define SERV_CLI_PORT  10001



#define RCP_MAX_DATA_BLOCK_PER_MESSAGE 255
#define MAX_INFO_BUF_SIZE 2000
#define BUFSIZE  2048
#define MAX_BUF BUFSIZE


#define MSG_VALID_FLAG 0x88




typedef enum
{
    TEST_COMMAND = 0,     //0
    TEST_COMMAND_ACK,

    SHOW_DP_BUILD_TIME,   // 2
    SHOW_DP_BUILD_TIME_ACK,

    SHOW_DP_PKT_STAT,     // 4
    SHOW_DP_PKT_STAT_ACK,

    SHOW_MEM_POOL,        //6
    SHOW_MEM_POOL_ACK,

    SHOW_ACL_RULE,        //8
    SHOW_ACL_RULE_ACK,

    ADD_ACL_RULE,         //10
    ADD_ACL_RULE_ACK,

    DEL_ACL_RULE,         //12
    DEL_ACL_RULE_ACK,

    DEL_ACL_RULE_ID,      //14
    DEL_ACL_RULE_ID_ACK,

    DEL_ACL_RULE_ALL,     //16
    DEL_ACL_RULE_ALL_ACK,

    COMMIT_ACL_RULE,      //18
    COMMIT_ACL_RULE_ACK,

    SET_ACL_DEF_ACT,      //20
    SET_ACL_DEF_ACT_ACK,

    SHOW_ACL_DEF_ACT,     //22
    SHOW_ACL_DEF_ACT_ACK,

    CLEAR_DP_PKT_STAT,    //24
    CLEAR_DP_PKT_STAT_ACK,

    SHOW_FW_FLOW_STAT,    //26
    SHOW_FW_FLOW_STAT_ACK,

    CLEAR_FW_FLOW_STAT,   //28
    CLEAR_FW_FLOW_STAT_ACK,

    SET_DBG_PRINT,        // 30
    SET_DBG_PRINT_ACK,

    CLEAR_DBG_PRINT,      // 32
    CLEAR_DBG_PRINT_ACK,

    SHOW_TCPSTREAM_STAT,     // 34
    SHOW_TCPSTREAM_STAT_ACK,

    CLEAR_TCPSTREAM_STAT,    // 36
    CLEAR_TCPSTREAM_STAT_ACK,

    SET_TCPSTREAM_TRACK_ABLE,     // 38
    SET_TCPSTREAM_TRACK_ABLE_ACK,

    SET_TCPSTREAM_REASM_ABLE,     //40
    SET_TCPSTREAM_REASM_ABLE_ACK,

    SET_SYNCHECK_ABLE,        //42
    SET_SYNCHECK_ABLE_ACK,

    SET_DEFRAG_MAX,            //44
    SET_DEFRAG_MAX_ACK,

    SHOW_ATTACK_STAT,       //46
    SHOW_ATTACK_STAT_ACK,

    SET_UNSUPPORT_PROTO_ACTION,     //48
    SET_UNSUPPORT_PROTO_ACTION_ACK,

    SET_DIRECT_FW,        //50
    SET_DIRECT_FW_ACK,

    SHOW_FW_CONFIG,      //52
    SHOW_FW_CONFIG_ACK,

    SET_PORTSCAN_ABLE,  //54
    SET_PORTSCAN_ABLE_ACK,

    SET_PORTSCAN_ACTION,      //56
    SET_PORTSCAN_ACTION_ACK,

    SET_ATTACK_DEFEND_TIME,          // 58
    SET_ATTACK_DEFEND_TIME_ACK,

    SET_PORTSCAN_FREQ,               // 60
    SET_PORTSCAN_FREQ_ACK,

    SET_SYNFLOOD_START,            // 62
    SET_SYNFLOOD_START_ACK,

    SET_MODBUS_ABLE,              // 64
    SET_MODBUS_ABLE_ACK,

    SET_MODBUS_VALUE,
    SET_MODBUS_VALUE_ACK,

    MAX_COMMAND_TYPE,
}cmd_type_t;

typedef enum tag_RCP_NISAC_RESULT_CODE {
    RCP_RESULT_OK = 0x0,
    RCP_RESULT_RULE_FULL,
    RCP_RESULT_RULE_EXIST,
    RCP_RESULT_RULE_NOT_EXIST,
    RCP_RESULT_FAIL,
    RCP_RESULT_NO_MEM,
    RCP_RESULT_FILE_ERR,
    RCP_RESULT_INVALID_FLAG,
    RCP_RESULT_INVALID_MSG_TYPE,
    RCP_RESULT_INVALID_MSG_CODE,
    RCP_RESULT_INVALID_USER,
    RCP_RESULT_INVALID_PASSWORD,
    RCP_RESULT_QUERY_IN_PROGRESS,
    RCP_RESULT_SAVE_IN_PROGRESS,
    RCP_RESULT_REQUEST_FORBIDDEN,
    RCP_RESULT_CODE_MAX,
} RCP_NISAC_RESULT_CODE;





typedef enum _msg_block_type_e {
    BLOCK_TYPE_START = 0x00,
    BLOCK_IPV4_FIVE_TUPLE = 0x01,
    BLOCK_ACL_RULE_TUPLE = 0x02,
    BLOCK_RESULT_CODE = 0x3,
    BLOCK_ACL_RULE_ID = 0x4,
    BLOCK_ACL_DEF_ACT_ID = 0x5,
    BLOCK_DBG_PRINT_ID = 0x6,
    BLOCK_TCPSTREAM_TRACK = 0x7,
    BLOCK_TCPSTREAM_REASM = 0x8,
    BLOCK_SYNCHECK_ID = 0x9,
    BLOCK_DEFRAG_MAX_ID = 0xA,
    BLOCK_UNSUPPORTACTION_ID = 0xB,
    BLOCK_DIRECTFW_ABLE_ID = 0xC,
    BLOCK_PORTSCAN_ID = 0xD,
    BLOCK_PORTSCAN_ACTION_ID = 0xE,
    BLOCK_ATTACK_DEFEND_TIME_ID = 0xF,
    BLOCK_PORTSCAN_FREQ_ID = 0x10,
    BLOCK_SYNFLOOD_START_ID = 0x11,
    BLOCK_MODBUS_ABLE_ID = 0x12,
    BLOCK_MODBUS_VALUE_ID = 0x13,
}msg_block_type_e;




typedef struct tag_CLI_RESULT {
    uint32_t result_code;
} __attribute__ ((__packed__)) CLI_RESULT;




typedef struct tag_RCP_BLOCK_IPV4_FIVE_TUPLE {
    uint8_t protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
}__attribute__ ((__packed__)) RCP_BLOCK_IPV4_FIVE_TUPLE;




typedef struct tag_RCP_BLOCK_RESULT {
    uint32_t result_code;
} __attribute__ ((__packed__)) RCP_BLOCK_RESULT;


typedef struct tag_RCP_BLOCK_ACL_RULE_ID {
    uint32_t rule_id;
} __attribute__ ((__packed__)) RCP_BLOCK_ACL_RULE_ID;

typedef struct tag_RCP_BLOCK_ACL_DEF_ACTION {
    uint32_t action;
} __attribute__ ((__packed__)) RCP_BLOCK_ACL_DEF_ACTION;

typedef struct tag_RCP_BLOCK_DBG_PRINT {
    uint32_t dbgprint;
} __attribute__ ((__packed__)) RCP_BLOCK_DBG_PRINT;


typedef struct tag_RCP_BLOCK_TCPSTREAM_TRACK_ABLE {
    uint32_t able;
} __attribute__ ((__packed__))RCP_BLOCK_TCPSTREAM_TRACK_ABLE;

typedef struct tag_RCP_BLOCK_DIRECTFW_ABLE {
    uint32_t able;
    uint32_t sleep_time;
} __attribute__ ((__packed__))RCP_BLOCK_DIRECTFW_ABLE;


typedef struct tag_RCP_BLOCK_TCPSTREAM_REASM_ABLE {
    uint32_t able;
} __attribute__ ((__packed__))RCP_BLOCK_TCPSTREAM_REASM_ABLE;

typedef struct tag_RCP_BLOCK_TCPSTREAM_SYNCHECK_ABLE {
    uint32_t able;
} __attribute__ ((__packed__))RCP_BLOCK_TCPSTREAM_SYNCHECK_ABLE;

typedef struct tag_RCP_BLOCK_PORTSCAN_ABLE {
    uint32_t able;
} __attribute__ ((__packed__))RCP_BLOCK_PORTSCAN_ABLE;


typedef struct tag_RCP_BLOCK_MODBUS_ABLE {
    uint32_t able;
} __attribute__ ((__packed__))RCP_BLOCK_MODBUS_ABLE;



typedef struct tag_RCP_BLOCK_UNSUPPORT_PROTO_ACTION {
    uint32_t action;
} __attribute__ ((__packed__))RCP_BLOCK_UNSUPPORT_PROTO_ACTION;

typedef struct tag_RCP_BLOCK_PORTSCAN_ACTION {
    uint32_t action;
} __attribute__ ((__packed__))RCP_BLOCK_PORTSCAN_ACTION;


typedef struct tag_RCP_BLOCK_DEFRAG_MAX{
    uint32_t num;
}__attribute__ ((__packed__))RCP_BLOCK_DEFRAG_MAX;

typedef struct tag_RCP_BLOCK_PORTSCAN_FREQ{
    uint32_t pps;
}__attribute__ ((__packed__))RCP_BLOCK_PORTSCAN_FREQ;


typedef struct tag_RCP_BLOCK_DEFEND_TIME{
    uint32_t seconds;
}__attribute__ ((__packed__))RCP_BLOCK_DEFEND_TIME;

typedef struct tag_RCP_BLOCK_SYNFLOOD_START{
    uint32_t start;
    uint32_t end;
    uint32_t percent;
}__attribute__ ((__packed__))RCP_BLOCK_SYNFLOOD_START;

typedef struct tag_RCP_BLOCK_MODBUS_VALUE{
    uint32_t func;
    uint32_t addr;
    uint32_t min;
    uint32_t max;
}__attribute__ ((__packed__))RCP_BLOCK_MODBUS_VALUE;


typedef struct TAG_RCP_DATA_BLOCK { //mush be 4 bytes align
    union {
        RCP_BLOCK_ACL_RULE_TUPLE  AclRuleTuple;
        RCP_BLOCK_ACL_RULE_ID   AclRuleId;
        RCP_BLOCK_ACL_DEF_ACTION AclDefAct;
        RCP_BLOCK_DBG_PRINT DbgPrint;
        RCP_BLOCK_TCPSTREAM_TRACK_ABLE TrackAble;
        RCP_BLOCK_DIRECTFW_ABLE DirfwAble;
        RCP_BLOCK_TCPSTREAM_REASM_ABLE ReasmAble;
        RCP_BLOCK_TCPSTREAM_SYNCHECK_ABLE SyncheckAble;
        RCP_BLOCK_PORTSCAN_ABLE PortscanAble;
        RCP_BLOCK_UNSUPPORT_PROTO_ACTION Unsupportaction;
        RCP_BLOCK_PORTSCAN_ACTION PortscanAction;
        RCP_BLOCK_DEFRAG_MAX DefragMax;
        RCP_BLOCK_DEFEND_TIME DefendTime;
        RCP_BLOCK_PORTSCAN_FREQ PortscanFreq;
        RCP_BLOCK_SYNFLOOD_START SynfloodStart;
        RCP_BLOCK_MODBUS_ABLE ModbusAble;
        RCP_BLOCK_MODBUS_VALUE ModubsValue;
        RCP_BLOCK_RESULT ResultCode;
        CLI_RESULT CliResultCode;
    };
}RCP_DATA_BLOCK;


typedef enum _msg_type_e {
    MSG_TYPE_CLI_OCTEON = 0x1,
    MSG_TYPE_CLI_DEBUG = 0x2,
    MSG_TYPE_CLI_LOG = 0x3,
    MSG_TYPE_CLI_SNMP = 0x4,
} msg_type_e;


typedef enum _msg_code_e {
    MSG_CODE_START = 0,

    MSG_CODE_SHOW_TEST_COMMAND = 0x101,
    MSG_CODE_SHOW_TEST_COMMAND_ACK,

    MSG_CODE_SHOW_DP_BUILD_TIME,
    MSG_CODE_SHOW_DP_BUILD_TIME_ACK,

    MSG_CODE_SHOW_DP_PKT_STAT,
    MSG_CODE_SHOW_DP_PKT_STAT_ACK,

    MSG_CODE_SHOW_MEM_POOL,
    MSG_CODE_SHOW_MEM_POOL_ACK,

    MSG_CODE_SHOW_ACL_RULE,
    MSG_CODE_SHOW_ACL_RULE_ACK,

    MSG_CODE_ADD_ACL_RULE,       //0x10b
    MSG_CODE_ADD_ACL_RULE_ACK,

    MSG_CODE_DEL_ACL_RULE,
    MSG_CODE_DEL_ACL_RULE_ACK,

    MSG_CODE_DEL_ACL_RULE_ID,
    MSG_CODE_DEL_ACL_RULE_ID_ACK,

    MSG_CODE_DEL_ACL_RULE_ALL,
    MSG_CODE_DEL_ACL_RULE_ALL_ACK,

    MSG_CODE_COMMIT_ACL_RULE,
    MSG_CODE_COMMIT_ACL_RULE_ACK,

    MSG_CODE_SET_ACL_DEF_ACT,
    MSG_CODE_SET_ACL_DEF_ACT_ACK,

    MSG_CODE_SHOW_ACL_DEF_ACT,
    MSG_CODE_SHOW_ACL_DEF_ACT_ACK,

    MSG_CODE_CLEAR_DP_PKT_STAT,
    MSG_CODE_CLEAR_DP_PKT_STAT_ACK,

    MSG_CODE_SHOW_FW_FLOW_STAT,
    MSG_CODE_SHOW_FW_FLOW_STAT_ACK,

    MSG_CODE_CLEAR_FW_FLOW_STAT,
    MSG_CODE_CLEAR_FW_FLOW_STAT_ACK,

    MSG_CODE_SET_DBG_PRINT,
    MSG_CODE_SET_DBG_PRINT_ACK,

    MSG_CODE_CLEAR_DBG_PRINT,
    MSG_CODE_CLEAR_DBG_PRINT_ACK,

    MSG_CODE_SHOW_TCPSTREAM_STAT,
    MSG_CODE_SHOW_TCPSTREAM_STAT_ACK,

    MSG_CODE_CLEAR_TCPSTREAM_STAT,
    MSG_CODE_CLEAR_TCPSTREAM_STAT_ACK,

    MSG_CODE_SET_TCPSTREAM_TRACK,
    MSG_CODE_SET_TCPSTREAM_TRACK_ACK,

    MSG_CODE_SET_TCPSTREAM_REASM,
    MSG_CODE_SET_TCPSTREAM_REASM_ACK,

    MSG_CODE_SET_SYNCHECK_ABLE,
    MSG_CODE_SET_SYNCHECK_ABLE_ACK,

    MSG_CODE_SET_DEFRAG_MAX,
    MSG_CODE_SET_DEFRAG_MAX_ACK,

    MSG_CODE_SHOW_ATTACK_STAT,
    MSG_CODE_SHOW_ATTACK_STAT_ACK,

    MSG_CODE_SET_UNSUPPORT_PROTO_ACTION,
    MSG_CODE_SET_UNSUPPORT_PROTO_ACTION_ACK,

    MSG_CODE_SET_DIRECTFW_ABLE,
    MSG_CODE_SET_DIRECTFW_ABLE_ACK,

    MSG_CODE_SHOW_FW_CONFIG,
    MSG_CODE_SHOW_FW_CONFIG_ACK,

    MSG_CODE_SET_PORTSCAN_ABLE,
    MSG_CODE_SET_PORTSCAN_ABLE_ACK,

    MSG_CODE_SET_PORTSCAN_ACTION,
    MSG_CODE_SET_PORTSCAN_ACTION_ACK,

    MSG_CODE_SET_ATTACK_DEFEND_TIME,
    MSG_CODE_SET_ATTACK_DEFEND_TIME_ACK,

    MSG_CODE_SET_PORTSCAN_FREQ,
    MSG_CODE_SET_PORTSCAN_FREQ_ACK,

    MSG_CODE_SET_SYNFLOOD_START,
    MSG_CODE_SET_SYNFLOOD_START_ACK,

    MSG_CODE_SET_MODBUS_ABLE,
    MSG_CODE_SET_MODBUS_ABLE_ACK,

    MSG_CODE_SET_MODBUS_VALUE,
    MSG_CODE_SET_MODBUS_VALUE_ACK,
}msg_code_e;



struct rcp_msg_params_s {
    uint32_t msg_id;
    uint8_t more_flag;
    uint8_t nparam;         // used by data block message
    uint16_t info_len;      //used by show info message
    union {
        RCP_DATA_BLOCK params[RCP_MAX_DATA_BLOCK_PER_MESSAGE];  // used by data block message
        char info_buf[MAX_INFO_BUF_SIZE];   //used by show info message
    } params_list;
};

/*
  * structure for command type map to message header
  */
struct msg_header_info_s {
    cmd_type_t cmd;
    uint8_t flag;
    uint8_t msg_type;
    uint16_t msg_code;
    uint8_t msg_block_type;
};



/* Message header */
typedef struct tag_MESSAGE_HEAD {
    uint8_t flag;
    uint8_t msg_type;
    uint16_t msg_code;

    uint32_t msg_id;

    uint8_t more_flag;
    uint8_t blocktype;
    uint8_t data_block_num;
    uint8_t reserved;
    uint32_t length;
    uint8_t payload[0];
} MESSAGE_HEAD;

#define MESSAGE_HEADER_LENGTH sizeof(MESSAGE_HEAD)


/*
  * structure for packing/unpacking message for the comand
  */
typedef int (*msg_pack_handle_t) (cmd_type_t, void *, void *, int *);
struct msg_pack_handle_s {
    cmd_type_t cmd;
    int (*pack) (cmd_type_t, void *, void *, int *);
};


/* structure for processing  the command */
typedef int (*cmd_proc_handle_t) (uint8_t *, uint32_t, uint32_t);
struct cmd_process_handle_s {
    cmd_type_t cmd;
    int32_t (*handle) (uint8_t *, uint32_t, uint32_t);
};



extern struct msg_header_info_s cmd_msg_headers[];
extern struct msg_pack_handle_s cmd_msg_handles[];
extern struct cmd_process_handle_s cmd_process_handles[];

extern int param_to_pkt(cmd_type_t cmd, void *from, uint8_t *sbuf, int *sn_p, void *param_p);
extern int init_msg_pack_handle(void);
extern int32_t init_cmd_process_handle(void);
extern int mgmt_process_cmd(uint8_t * from, uint32_t length, uint32_t fd);

extern int register_cmd_process_handle(cmd_type_t cmd, cmd_proc_handle_t cmd_handle);
extern int init_msg_header(void);



#ifdef __cplusplus
}
#endif


#endif

