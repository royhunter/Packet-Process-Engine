#ifndef __DP_ATTACK_H__
#define __DP_ATTACK_H__
#include "sec-common.h"
#include <mbuf.h>
#include <decode.h>
#include "oct-port.h"
#include "decode-statistic.h"

//#define ATTACK_DEBUG

#define PACKET_DELETE_TYPE 0
#define TRAFFIC_DELETE_TYPE 1

#define ATTACK_DISABLE 0
#define ATTACK_ENABLE  1

typedef enum {
	ALERT_DATA_PROTECTION_DOS_ID_LAND = 0,
		ALERT_DATA_PROTECTION_DOS_ID_TEARDROP,
		ALERT_DATA_PROTECTION_DOS_ID_PINGDEATH,
		ALERT_DATA_PROTECTION_DOS_ID_SYNFLOOD,
		ALERT_DATA_PROTECTION_DOS_ID_PINGFLOOD,
		ALERT_DATA_PROTECTION_DOS_ID_UDPFLOOD
}ALERT_DATA_PROTECTION_DOS_ID;

typedef struct packet_detect_s
{
    uint32_t drop_pack;        //0: drop     1:not drop
    uint32_t land;             //0: disable 1:enable
    uint32_t teardrop;         //0: disable 1:enable
    uint32_t pingdeath;        //0: disable 1:enable
    uint32_t pingdeath_value;  //max len of ping packet
}packet_detect;

typedef struct traffic_detect_s
{
    uint32_t drop_pack;    // 0: drop 1:not drop
    uint32_t flood_ping;   // 0: disable  1: enable
    uint32_t ping_speed;
    uint32_t last_ping_flood_time;
    uint32_t flood_udp;    // 0: disable  1: enable
    uint32_t udp_speed;
    uint32_t last_udp_flood_time;
    uint32_t flood_syn;    // 0: disable  1: enable
    uint32_t syn_speed;
    uint32_t last_syn_flood_time;
    uint32_t syn_count;
}traffic_detect;


typedef struct packet_detect_rule_s
{
    packet_detect pd[OCT_PHY_PORT_MAX];
}packet_detect_rule;


typedef struct traffic_detect_rule_s
{
    traffic_detect td[OCT_PHY_PORT_MAX];
}traffic_detect_rule;


typedef struct attack_rule_s
{
    packet_detect_rule pkt_detect_rule;
    traffic_detect_rule tfc_detect_rule;
}attack_rule;




typedef struct attack_info_s
{
    uint64_t pingpps;
    uint64_t ping_accum;
    uint64_t udppps;
    uint64_t udp_accum;
    uint64_t synpps;
    uint64_t syn_accum;
    uint64_t syncount;
    uint64_t syncount_accum;
    uint32_t ping_flood_hold;
    uint64_t ping_flood_hold_time;
    uint32_t syn_flood_hold;
    uint64_t syn_flood_hold_time;
    uint32_t udp_flood_hold;
    uint64_t udp_flood_hold_time;
}attack_info;




typedef struct attack_monitor_s
{
    attack_info ai[OCT_PHY_PORT_MAX];
}attack_monitor;


extern int DP_Attack_load_from_conf();
extern uint32_t DP_Attack_UdpPacketMonitor(mbuf_t *m);
extern void DP_Attack_SynCountFins(mbuf_t *m);
extern uint32_t DP_Land_Attack_Monitor(mbuf_t *m);
extern uint32_t DP_Pingdeath_Attack_Monitor(mbuf_t *m);
extern uint32_t DP_Attack_PingPacketMonitor(mbuf_t *m);
extern uint32_t DP_Attack_SynPacketMonitor(mbuf_t *m);
extern void DP_Teardrop_Attack_Monitor(mbuf_t *m);
extern void DP_Attack_SynCountMonitor(mbuf_t *mbuf);
extern void DP_Attack_Info_Update();
extern void DP_Attack_SynCountFins_Byport(uint32_t port);
extern void DP_Attack_load_thread_start();
#endif