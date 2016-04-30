#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <sec-common.h>
#include <shm.h>
#include "dp_attack.h"
#include <mbuf.h>
#include <sec-debug.h>
#include "dp_log.h"
#include <oct-time.h>


attack_rule attrule;
attack_monitor attinfo;


char *attack_conf_filename = "/data/protection.rul";
static pthread_t attack_load_thread_dp;
static pthread_cond_t attack_load_cond_dp = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t attack_load_mutex_dp= PTHREAD_MUTEX_INITIALIZER; //mutex for rule config file and load
uint32_t attack_load_notify_dp = 0;

extern uint32_t flow_log;

uint32_t flood_hold_time = 600;

uint32_t synflood_ip_start = 0;
uint32_t synflood_ip_end = 0;
uint32_t synflood_percent = 0;


void DP_Attack_Del_All()
{
    memset(&attrule, 0, sizeof(attack_rule));
}

int ReadInterfaceInfo(FILE *fp, int line, uint32_t *intfinfo)
{
    if ( 1 !=  fscanf(fp, "%u", intfinfo))
    {
        printf ("\n>> [err] ill-format interface attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}


int ReadTypeInfo(FILE *fp, int line, uint32_t *type)
{
    if ( 1 !=  fscanf(fp,"%u",type))
    {
        printf ("\n>> [err] ill-format type attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}


int ReadDroppackInfo(FILE *fp, int line, uint32_t *drop_pack)
{
    if ( 1 !=  fscanf(fp,"%u",drop_pack))
    {
        printf ("\n>> [err] ill-format drop_pack attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int ReadLandInfo(FILE *fp, int line, uint32_t *land)
{
    if ( 1 !=  fscanf(fp,"%u",land))
    {
        printf ("\n>> [err] ill-format land attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int ReadTeardropInfo(FILE *fp, int line, uint32_t *teardrop)
{
    if ( 1 !=  fscanf(fp,"%u",teardrop))
    {
        printf ("\n>> [err] ill-format teardrop attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int ReadPingdeathInfo(FILE *fp, int line, uint32_t *pingdeath)
{
    if ( 1 !=  fscanf(fp,"%u",pingdeath))
    {
        printf ("\n>> [err] ill-format pingdeath attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int ReadPingdeathvalueInfo(FILE *fp, int line, uint32_t *pingdeath_value)
{
    if ( 1 !=  fscanf(fp,"%d",pingdeath_value))
    {
        printf ("\n>> [err] ill-format pingdeath_value attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int Readflood_pingInfo(FILE *fp, int line, uint32_t *flood_ping)
{
    if ( 1 !=  fscanf(fp,"%u",flood_ping))
    {
        printf ("\n>> [err] ill-format flood_ping attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int Readping_speedInfo(FILE *fp, int line, uint32_t *ping_speed)
{
    if ( 1 !=  fscanf(fp,"%d",ping_speed))
    {
        printf ("\n>> [err] ill-format ping_speed attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int Readflood_udpInfo(FILE *fp, int line, uint32_t *flood_udp)
{
    if ( 1 !=  fscanf(fp,"%u",flood_udp))
    {
        printf ("\n>> [err] ill-format flood_udp attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int Readudp_speedInfo(FILE *fp, int line, uint32_t *udp_speed)
{
    if ( 1 !=  fscanf(fp,"%d",udp_speed))
    {
        printf ("\n>> [err] ill-format udp_speed attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int Readflood_synInfo(FILE *fp, int line, uint32_t *flood_syn)
{
    if ( 1 !=  fscanf(fp,"%u",flood_syn))
    {
        printf ("\n>> [err] ill-format flood_syn attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int Readsyn_speedInfo(FILE *fp, int line, uint32_t *syn_speed)
{
    if ( 1 !=  fscanf(fp,"%d",syn_speed))
    {
        printf ("\n>> [err] ill-format syn_speed attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}

int Readsyn_countInfo(FILE *fp, int line, uint32_t *syn_count)
{
    if ( 1 !=  fscanf(fp,"%d",syn_count))
    {
        printf ("\n>> [err] ill-format syn_count attack rule file, rule line: %d\n", line);
        return -1;
    }

    return 0;
}


attack_rule attackrule_tmp;

int DP_Attack_Load_Line(FILE *fp, int line)
{
    uint32_t intf = 0;
    uint32_t type = 0;
    char validfilter;               //validfilter means an '@'

    while(!feof(fp))
    {
        if(0 != fscanf(fp,"%c",&validfilter))
        {
            //printf (">> [err] ill-format @ rule-file\n");
            //return -1;
        }

        if (validfilter != '@')     //each rule should begin with an '@'
        {
            continue;
        }

        if(0 != ReadInterfaceInfo(fp, line, &intf))
        {
            return -1;
        }
    #ifdef ATTACK_DEBUG
        printf("interface is %d\n", intf);
    #endif

        if(intf >= OCT_PHY_PORT_MAX)
        {
            printf("error interface is %d\n", intf);
            return -1;
        }

        if(intf < OCT_PHY_PORT_MAX)
        {

            if(0 != ReadTypeInfo(fp, line, &type))
            {
                return -1;
            }
        #ifdef ATTACK_DEBUG
            printf("type is %d\n", type);
        #endif
            if(type == PACKET_DELETE_TYPE)
            {
                if(0 != ReadDroppackInfo(fp, line, &attackrule_tmp.pkt_detect_rule.pd[intf].drop_pack))
                {
                    return -1;
                }

                if(0 != ReadLandInfo(fp, line, &attackrule_tmp.pkt_detect_rule.pd[intf].land))
                {
                    return -1;
                }

                if(0 != ReadTeardropInfo(fp, line, &attackrule_tmp.pkt_detect_rule.pd[intf].teardrop))
                {
                    return -1;
                }

                if(0 != ReadPingdeathInfo(fp, line, &attackrule_tmp.pkt_detect_rule.pd[intf].pingdeath))
                {
                    return -1;
                }

                if(0 != ReadPingdeathvalueInfo(fp, line, &attackrule_tmp.pkt_detect_rule.pd[intf].pingdeath_value))
                {
                    return -1;
                }
            }
            else if(type == TRAFFIC_DELETE_TYPE)
            {
                if(0 != ReadDroppackInfo(fp, line, &attackrule_tmp.tfc_detect_rule.td[intf].drop_pack))
                {
                    return -1;
                }

                if(0 != Readflood_pingInfo(fp, line, &attackrule_tmp.tfc_detect_rule.td[intf].flood_ping))
                {
                    return -1;
                }

                if(0 != Readping_speedInfo(fp, line, &attackrule_tmp.tfc_detect_rule.td[intf].ping_speed))
                {
                    return -1;
                }

                if(0 != Readflood_udpInfo(fp, line, &attackrule_tmp.tfc_detect_rule.td[intf].flood_udp))
                {
                    return -1;
                }

                if(0 != Readudp_speedInfo(fp, line, &attackrule_tmp.tfc_detect_rule.td[intf].udp_speed))
                {
                    return -1;
                }

                if(0 != Readflood_synInfo(fp, line, &attackrule_tmp.tfc_detect_rule.td[intf].flood_syn))
                {
                    return -1;
                }

                if(0 != Readsyn_speedInfo(fp, line, &attackrule_tmp.tfc_detect_rule.td[intf].syn_speed))
                {
                    return -1;
                }

                if(0 != Readsyn_countInfo(fp, line, &attackrule_tmp.tfc_detect_rule.td[intf].syn_count))
                {
                    return -1;
                }

            }
            else
            {
                printf("dp attack load rule type error %d\n", type);

            }
        }

        return 0;
    }

    return 0;
}


int DP_Attack_load_from_conf()
{
    int line = 0;
    uint32_t ret;
    FILE *fp;

    if(access(attack_conf_filename, F_OK) != 0)
    {
        printf("attack_conf_filename NOT EXIST\n");
        return  -1;
    }

    fp = fopen(attack_conf_filename, "r");
    if (fp == NULL)
    {
        printf("Couldnt open attack_conf_filename\n");
        return  -1;
    }

#ifdef ATTACK_DEBUG
    printf("open rule config success\n");
#endif

    DP_Attack_Del_All();

#ifdef ATTACK_DEBUG
    printf("rule delete all\n");
#endif

    memset(&attackrule_tmp, 0, sizeof(attack_rule));

    while(!feof(fp))
    {
        ret = DP_Attack_Load_Line(fp, line);
        if(ret != 0)
        {
            //printf("config file line %d format err\n", line);
            fclose(fp);
            return 0;
        }
        line++;
    }

    fclose(fp);

    memcpy(&attrule, &attackrule_tmp, sizeof(attack_rule));

    return 0;

}

void Attack_config()
{

}

void Attack_Conf_Load_Notify()
{
    pthread_mutex_lock(&attack_load_mutex_dp);

    Attack_config();  //give a configfile and notify

    attack_load_notify_dp = 1;

    pthread_cond_signal(&attack_load_cond_dp);

    pthread_mutex_unlock(&attack_load_mutex_dp);
}


void DP_Attack_Conf_Recover()
{
    pthread_mutex_lock(&attack_load_mutex_dp);

    if(DP_Attack_load_from_conf() < 0)
    {
        pthread_mutex_unlock(&attack_load_mutex_dp);
        return;
    }

    pthread_mutex_unlock(&attack_load_mutex_dp);

    return;
}

static void *DP_Attack_Load_Fn(void *arg)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);

    printf("DP_Rule_Load_Fn thread running\n");

    if(pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0)
    {
        printf("set thread affinity failed\n");
    }

    printf("set thread affinity OK\n");

    cvmx_linux_enable_xkphys_access(0);

    while(1)
    {
        pthread_mutex_lock(&attack_load_mutex_dp);

        while (!attack_load_notify_dp)
        {
            pthread_cond_wait(&attack_load_cond_dp, &attack_load_mutex_dp);
        }

        DP_Attack_load_from_conf();

        attack_load_notify_dp = 0;

        pthread_mutex_unlock(&attack_load_mutex_dp);
    }

    return NULL;
}

void DP_Attack_load_thread_start()
{
    pthread_create(&attack_load_thread_dp, NULL, DP_Attack_Load_Fn, NULL);
}




void DP_Attack_Init()
{
    memset(&attrule, 0, sizeof(attack_rule));

    memset(&attinfo, 0, sizeof(attack_info));

    DP_Attack_load_thread_start();

    DP_Attack_Conf_Recover();

}

uint32_t DP_Land_Attack_Monitor(mbuf_t *m)
{
    uint32_t input = m->input_port;
    if(ATTACK_ENABLE == attrule.pkt_detect_rule.pd[input].land )
    {
        if(m->ipv4.dip == m->ipv4.sip)
        {
            /*TODO: ALARM*/
            if(ATTACK_ENABLE == attrule.pkt_detect_rule.pd[input].drop_pack)
            {
            #ifdef ATTACK_DEBUG
                printf("is land attack\n");
            #endif
                STAT_ATTACK_LAND;
                return DECODE_DROP;
            }
        }
    }

    return DECODE_OK;
}


void DP_Teardrop_Attack_Monitor(mbuf_t *m)
{
    uint32_t input = m->input_port;
    if(ATTACK_ENABLE == attrule.pkt_detect_rule.pd[input].teardrop)
    {
        /*TODO: ALARM*/
        #ifdef ATTACK_DEBUG
            printf("is teardrop attack\n");
        #endif
        STAT_ATTACK_TEARDROP;
    }
}


uint32_t DP_Pingdeath_Attack_Monitor(mbuf_t *m)
{
    uint32_t input = m->input_port;
    if(ATTACK_ENABLE == attrule.pkt_detect_rule.pd[input].pingdeath)
    {
        if(m->pkt_totallen > attrule.pkt_detect_rule.pd[input].pingdeath_value)
        {
            /*TODO: ALARM*/
            if(ATTACK_ENABLE == attrule.pkt_detect_rule.pd[input].drop_pack)
            {
            #ifdef ATTACK_DEBUG
                printf("is pingdeath attack m->pkt_totallen is %d\n", m->pkt_totallen);
            #endif
                STAT_ATTACK_PINGDEATH;
                return DECODE_DROP;
            }
        }
    }

    return DECODE_OK;
}


uint32_t DP_Attack_PingPacketMonitor(mbuf_t *m)//ping flood
{
    uint32_t input = m->input_port;



    if(PKTBUF_IS_SW(m))
    {
        mbuf_t *next;
        mbuf_t *head = m->fragments;
        cvmx_atomic_add64((int64_t *)&attinfo.ai[input].ping_accum, 1);
        while(head)
        {
            next = head->next;
            head = next;
            cvmx_atomic_add64((int64_t *)&attinfo.ai[input].ping_accum, 1);
        }
    }
    else
    {
        cvmx_atomic_add64((int64_t *)&attinfo.ai[input].ping_accum, 1);
    }

    if(ATTACK_ENABLE == attrule.tfc_detect_rule.td[input].flood_ping)
    {
        if(attinfo.ai[input].ping_flood_hold)
        {
            if(ATTACK_ENABLE == attrule.tfc_detect_rule.td[input].drop_pack)
            {
                /*TODO: ALARM*/
            #ifdef ATTACK_DEBUG
                printf("ping flood drop hold\n");
            #endif
                STAT_ATTACK_PINGFLOOD_DROP;
                return DECODE_DROP;
            }
        }

        if(attinfo.ai[input].pingpps > attrule.tfc_detect_rule.td[input].ping_speed)
        {
            if(ATTACK_ENABLE == attrule.tfc_detect_rule.td[input].drop_pack)
            {
                /*TODO: ALARM*/
            #ifdef ATTACK_DEBUG
                printf("is pingspeed attack\n");
            #endif
                attinfo.ai[input].ping_flood_hold = 1;
                attinfo.ai[input].ping_flood_hold_time = OCT_TIME_SECONDS_SINCE1970 + flood_hold_time;
                STAT_ATTACK_PINGFLOOD_DROP;
                return DECODE_DROP;
            }
        }
    }

    return DECODE_OK;
}


uint32_t DP_Attack_UdpPacketMonitor(mbuf_t *m)//udp flood
{
    uint32_t input = m->input_port;

    if(PKTBUF_IS_SW(m))
    {
        mbuf_t *next;
        mbuf_t *head = m->fragments;
        cvmx_atomic_add64((int64_t *)&attinfo.ai[input].udp_accum, 1);
        while(head)
        {
            next = head->next;
            head = next;
            cvmx_atomic_add64((int64_t *)&attinfo.ai[input].udp_accum, 1);
        }
    }
    else
    {
        cvmx_atomic_add64((int64_t *)&attinfo.ai[input].udp_accum, 1);
    }

    if(ATTACK_ENABLE == attrule.tfc_detect_rule.td[input].flood_udp)
    {
        if(attinfo.ai[input].udp_flood_hold)
        {
            if(ATTACK_ENABLE == attrule.tfc_detect_rule.td[input].drop_pack)
            {
                #ifdef ATTACK_DEBUG
                    printf("is udp flood drop hold\n");
                #endif
                STAT_ATTACK_UDPFLOOD_DROP;
                return DECODE_DROP;
            }
        }

        if(attinfo.ai[input].udppps > attrule.tfc_detect_rule.td[input].udp_speed)
        {
            if(ATTACK_ENABLE == attrule.tfc_detect_rule.td[input].drop_pack)
            {
                /*TODO: ALARM*/
            #ifdef ATTACK_DEBUG
                printf("is udpspeed attack\n");
            #endif
                attinfo.ai[input].udp_flood_hold = 1;
                attinfo.ai[input].udp_flood_hold_time = OCT_TIME_SECONDS_SINCE1970 + flood_hold_time;
                STAT_ATTACK_UDPFLOOD_DROP;
                return DECODE_DROP;
            }
        }
    }

    return DECODE_OK;
}


uint32_t DP_Attack_SynPacketMonitor(mbuf_t *m)//syn flood
{
    uint32_t input = m->input_port;

    cvmx_atomic_add64((int64_t *)&attinfo.ai[input].syn_accum, 1);

    if(ATTACK_ENABLE == attrule.tfc_detect_rule.td[input].flood_syn)
    {
        if(attinfo.ai[input].syn_flood_hold)
        {
            if(ATTACK_ENABLE == attrule.tfc_detect_rule.td[input].drop_pack)
            {
                #ifdef ATTACK_DEBUG
                    printf("is syn flood drop hold\n");
                #endif
                STAT_ATTACK_SYNFLOOD_DROP;
                return DECODE_DROP;
            }
        }

        if(attinfo.ai[input].synpps > attrule.tfc_detect_rule.td[input].syn_speed)
        {
            if(ATTACK_ENABLE == attrule.tfc_detect_rule.td[input].drop_pack)
            {
                /*TODO: ALARM*/
            #ifdef ATTACK_DEBUG
                printf("is synspeed attack\n");
            #endif
                attinfo.ai[input].syn_flood_hold = 1;
                attinfo.ai[input].syn_flood_hold_time = OCT_TIME_SECONDS_SINCE1970 + flood_hold_time;
                STAT_ATTACK_SYNFLOOD_DROP;
                return DECODE_DROP;
            }
        }
    }

    if(attinfo.ai[input].syncount > attrule.tfc_detect_rule.td[input].syn_count)
    {
        if(ATTACK_ENABLE == attrule.tfc_detect_rule.td[input].drop_pack)
        {
            /*TODO: ALARM*/
        #ifdef ATTACK_DEBUG
            printf("is syncount attack\n");
        #endif

            STAT_ATTACK_SYNCOUNT;
            return DECODE_DROP;
        }
    }

    return DECODE_OK;
}


void DP_Attack_SynCountMonitor(mbuf_t *mbuf)
{
    uint32_t input = mbuf->input_port;
    cvmx_atomic_add64((int64_t *)&attinfo.ai[input].syncount_accum, 1);
}



void DP_Attack_SynCountFins(mbuf_t *m)
{
    uint32_t input = m->input_port;

    cvmx_atomic_add64((int64_t *)&attinfo.ai[input].syncount_accum, -1);
}

void DP_Attack_SynCountFins_Byport(uint32_t port)
{
    cvmx_atomic_add64((int64_t *)&attinfo.ai[port].syncount_accum, -1);
}


void DP_Attack_Info_Update()
{
    int i = 0;
    for(i = 0; i < OCT_PHY_PORT_MAX; i++)
    {
        attinfo.ai[i].pingpps = attinfo.ai[i].ping_accum;
        attinfo.ai[i].ping_accum = 0;
        if(seconds_since1970 >= attinfo.ai[i].ping_flood_hold_time)
        {
            attinfo.ai[i].ping_flood_hold = 0;
            attinfo.ai[i].ping_flood_hold_time = 0;
        }

        attinfo.ai[i].udppps = attinfo.ai[i].udp_accum;
        attinfo.ai[i].udp_accum = 0;

        if(OCT_TIME_SECONDS_SINCE1970 >= attinfo.ai[i].udp_flood_hold_time)
        {
            attinfo.ai[i].udp_flood_hold = 0;
            attinfo.ai[i].udp_flood_hold_time = 0;
        }
        //printf("port %d :udp pps is %ld\n",i,attinfo.ai[i].udppps);
        //printf("OCT_TIME_SECONDS_SINCE1970 is %ld, udp_flood_hold_time is %ld\n", OCT_TIME_SECONDS_SINCE1970, attinfo.ai[i].udp_flood_hold_time);

        attinfo.ai[i].synpps = attinfo.ai[i].syn_accum;
        attinfo.ai[i].syn_accum = 0;

        if(OCT_TIME_SECONDS_SINCE1970 >= attinfo.ai[i].syn_flood_hold_time)
        {
            attinfo.ai[i].syn_flood_hold = 0;
            attinfo.ai[i].syn_flood_hold_time = 0;
        }

        attinfo.ai[i].syncount = attinfo.ai[i].syncount_accum;
        attinfo.ai[i].syncount_accum = 0;
    }
}
