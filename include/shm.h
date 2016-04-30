#ifndef __SHM_H__
#define __SHM_H__

#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>




#define SHM_RULE_LIST_NAME "RULE_LIST_SPACE"

#define SHM_SRV_DP_SYNC_NAME "SRV_DP_SYNC_NAME"


#define SRV_DP_SYNC_MAGIC  0x86cf0000



#define SEC_RX_DBG_BIT       1 << 0
#define SEC_PACKET_DUMP      1 << 1
#define SEC_DECODE_DBG_BIT   1 << 2
#define SEC_ETHERNET_DBG_BIT 1 << 3
#define SEC_IPV4_DBG_BIT     1 << 4
#define SEC_TCP_DBG_BIT      1 << 5
#define SEC_UDP_DBG_BIT      1 << 6
#define SEC_DEFRAG_DBG_BIT   1 << 7
#define SEC_FLOW_DBG_BIT     1 << 8
#define SEC_ACL_DBG_BIT      1 << 9
#define SEC_L7_DBG_BIT       1 << 10
#define SEC_DPCMD_DBG_BIT    1 << 11
#define SEC_STREAMTCP_DBG_BIT 1 << 12
#define SEC_STREAMTCP_TRACK_DBG_BIT 1 << 13
#define SEC_STREAMTCP_REASM_DBG_BIT 1 << 14
#define SEC_OSPF_ON_DBG_BIT            1 << 15
#define SEC_OSPF_OFF_DBG_BIT           0 << 15
#define SEC_ATTACK_DBG_BIT    1 << 16




typedef struct
{
    uint32_t magic;
    uint32_t dp_sync_dp;
    uint32_t srv_initdone;
    uint32_t srv_notify_dp;
    uint32_t dp_ack;
    uint32_t dp_debugprint;
    uint32_t dp_tcpstream_track;
    uint32_t dp_tcpstream_reasm;
    uint32_t dp_syncheck_able;
    uint32_t dp_directfw_able;
    uint32_t dp_directfw_sleep_time;
    uint32_t dp_portscan_able;
    uint32_t dp_defragmax;
    uint32_t dp_unsupportproto_action;
    uint32_t dp_portscan_action;
    uint32_t dp_attack_defend_time;
    uint32_t dp_portscan_freq;
    uint32_t dp_synflood_start;
    uint32_t dp_synflood_end;
    uint32_t dp_synflood_percent;
    uint32_t dp_modbus_able;
    uint32_t dp_modbus_func;
    uint32_t dp_modbus_addr;
    uint32_t dp_modbus_min;
    uint32_t dp_modbus_max;
    char msgbuf[4096];
}SRV_DP_SYNC;



#define SHM_MSGQUE_KEY  0x23231414



typedef struct
{
	long mtype;
	uint64_t msg[2];
}MSG_QUE_BODY;


extern SRV_DP_SYNC *srv_dp_sync;

extern int MSGQUE_Init(int key);
extern int MSGQUE_Send(int msgid, MSG_QUE_BODY *msgbody);
extern int MSGQUE_Recv(int msgid, MSG_QUE_BODY *msgbody);
extern int MSGQUE_Rpc_Syncall2dp(int msgid,MSG_QUE_BODY *msgbody_snd, MSG_QUE_BODY *msgbody_rcv);


#endif
