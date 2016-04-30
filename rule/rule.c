#include "rule.h"
#include "acl_rule.h"
#include "shm.h"
extern int dp_msg_queue_id;


static inline int Rule_compare(RCP_BLOCK_ACL_RULE_TUPLE *rule1, RCP_BLOCK_ACL_RULE_TUPLE *rule2)
{
    return memcmp((void *)rule1, (void *)rule2, sizeof(RCP_BLOCK_ACL_RULE_TUPLE));
}


static inline int find_first_free()
{
    int i;
    for(i = 0; i < RULE_ENTRY_MAX; i++)
    {
        if(rule_list->rule_entry[i].entry_status == RULE_ENTRY_STATUS_FREE)
            return i;
    }

    return -1;
}



int ReadIPInfo(FILE *fp, int line ,uint32_t *ip_info, uint32_t *mask_info)
{
    unsigned int trange[4];
    unsigned int mask;
    char validslash;
    uint32_t ip = 0;

    if (4 != fscanf(fp, "%d.%d.%d.%d", &trange[0],&trange[1],&trange[2],&trange[3]))
    {
        printf (">> [err] ill-format IP rule-file, rule line: %d\n", line);
        return -1;
    }

    if (1 != fscanf(fp, "%c", &validslash))
    {
        printf ("\n>> [err] ill-format IP slash rule-file, rule line: %d\n", line);
        return -1;
    }

    if(validslash != '/')
    {
        printf ("\n>> [err] ill-format IP slash rule-file, rule line: %d\n", line);
        return -1;
    }

    if (1 != fscanf(fp,"%d", &mask))
    {
        printf ("\n>> [err] ill-format mask rule-file, rule line: %d\n", line);
        return -1;
    }

    ip = ((uint32_t)trange[0]) << 24;
    ip |= ((uint32_t)trange[1]) << 16;
    ip |= ((uint32_t)trange[2]) << 8;
    ip |= ((uint32_t)trange[3]);

    if( 0 == ip && 0 != mask)
    {
        printf("sip mask invalid, rule line: %d\n", line);
        return -1;

    }
    if( 0 != ip && mask > 32)
    {
        printf("sip mask invalid, rule line: %d\n", line);
        return -1;
    }

    *ip_info = ip;
    *mask_info = mask;

    return 0;
}

int ReadPortInfo(FILE *fp, int line, uint16_t *from, uint16_t *to)
{
    unsigned int tfrom;
    unsigned int tto;
    if ( 2 !=  fscanf(fp,"%d : %d",&tfrom, &tto))
    {
        printf ("\n>> [err] ill-format port range rule-file, rule line: %d\n", line);
        return -1;
    }
    *from = tfrom;
    *to = tto;

    return 0;
}

int ReadProtoInfo(FILE *fp, int line, uint8_t *from, uint8_t *to)
{
    unsigned int tfrom;
    unsigned int tto;
    if ( 2 !=  fscanf(fp,"%d : %d",&tfrom, &tto)) {
        printf ("\n>> [err] ill-format protocol range rule-file, rule line: %d\n", line);
        return -1;
    }
    *from = tfrom;
    *to = tto;

    return 0;
}


int ReadMACInfo(FILE *fp, int line, uint8_t *macinfo)
{
    unsigned int mac[6];
    if ( 6 !=  fscanf(fp,"%2x:%2x:%2x:%2x:%2x:%2x",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]))
    {
        printf ("\n>> [err] ill-format macinfo rule-file, rule line: %d\n", line);
        return -1;
    }

    macinfo[0] = mac[0];
    macinfo[1] = mac[1];
    macinfo[2] = mac[2];
    macinfo[3] = mac[3];
    macinfo[4] = mac[4];
    macinfo[5] = mac[5];

    return 0;
}


int ReadTimeInfo(FILE *fp, int line, uint64_t *timeinfo)
{
    uint64_t time;
    if (1 != fscanf(fp, "%ld", &time))
    {
        printf ("\n>> [err] ill-format time rule-file, rule line: %d\n", line);
        return -1;
    }

    *timeinfo = time;

    return 0;
}


int ReadActionInfo(FILE *fp, int line, uint16_t *actioninfo)
{
    int action;
    if (1 != fscanf(fp, "%d", &action))
    {
        printf ("\n>> [err] ill-format action rule-file, rule line: %d\n", line);
        return -1;
    }

    *actioninfo = action;

    return 0;
}


int ReadLogInfo(FILE *fp, int line, uint32_t *logable)
{
    int able;
    if (1 != fscanf(fp, "%d", &able))
    {
        printf ("\n>> [err] ill-format logable rule-file, rule line: %d\n", line);
        return -1;
    }

    *logable = able;

    return 0;
}


int Rule_del_all()
{
    int i;

    pthread_mutex_lock(&rule_list->rulelist_mutex);

    for (i = 0; i < RULE_ENTRY_MAX; i++)
    {
        rule_list->rule_entry[i].entry_status = RULE_ENTRY_STATUS_FREE;
    }
    rule_list->rule_entry_free = RULE_ENTRY_MAX;
    rule_list->build_status = RULE_BUILD_UNCOMMIT;

    pthread_mutex_unlock(&rule_list->rulelist_mutex);

    return RULE_OK;
}

int Rule_Load_Line(FILE *fp, int line)
{
    RCP_BLOCK_ACL_RULE_TUPLE rule;
    char validfilter;               //validfilter means an '@'
    uint32_t rule_id;

    memset((void *)&rule, 0, sizeof(RCP_BLOCK_ACL_RULE_TUPLE));

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


        if(0 != ReadMACInfo(fp, line, rule.smac))
        {
            return -1;
        }

    #ifdef RULE_DEBUG
        printf("smac is %02x:%02x:%02x:%02x:%02x:%02x\n",
                rule.smac[0],
                rule.smac[1],
                rule.smac[2],
                rule.smac[3],
                rule.smac[4],
                rule.smac[5] );
    #endif

        if(0 != ReadMACInfo(fp, line, rule.dmac))
        {
            return -1;
        }

    #ifdef RULE_DEBUG
        printf("dmac is %02x:%02x:%02x:%02x:%02x:%02x\n",
                rule.dmac[0],
                rule.dmac[1],
                rule.dmac[2],
                rule.dmac[3],
                rule.dmac[4],
                rule.dmac[5] );
    #endif

        if(0 != ReadIPInfo(fp, line, &rule.sip, &rule.sip_mask))
        {
            return -1;
        }
    #ifdef RULE_DEBUG
        printf("sip is %d.%d.%d.%d/%d\n", (int)((rule.sip >> 24)&0xff), (int)((rule.sip >> 16)&0xff), (int)((rule.sip >> 8)&0xff), (int)((rule.sip)&0xff), (int)rule.sip_mask & 0xff );
    #endif
        if(0 != ReadIPInfo(fp, line, &rule.dip, &rule.dip_mask))
        {
            return -1;
        }
    #ifdef RULE_DEBUG
        printf("dip is %d.%d.%d.%d/%d\n", (int)((rule.dip >> 24)&0xff), (int)((rule.dip >> 16)&0xff), (int)((rule.dip >> 8)&0xff), (int)((rule.dip)&0xff), (int)rule.dip_mask & 0xff );
    #endif
        if(0 != ReadPortInfo(fp, line, &rule.sport_start, &rule.sport_end))
        {
            return -1;
        }
    #ifdef RULE_DEBUG
        printf("sport start is %d, end is %d\n", rule.sport_start, rule.sport_end);
    #endif
        if( rule.sport_start > rule.sport_end)
        {
            printf("sport invalid\n");
            return -1;
        }

        if(0 != ReadPortInfo(fp, line, &rule.dport_start, &rule.dport_end))
        {
            return -1;
        }
    #ifdef RULE_DEBUG
        printf("dport start is %d, end is %d\n", rule.dport_start, rule.dport_end);
    #endif
        if( rule.dport_start > rule.dport_end)
        {
            printf("sport invalid\n");
            return -1;
        }

        if(0 != ReadProtoInfo(fp, line, &rule.protocol_start, &rule.protocol_end))
        {
            return -1;
        }
    #ifdef RULE_DEBUG
        printf("protocol start is %d, end is %d\n", rule.protocol_start, rule.protocol_end);
    #endif
        if( rule.protocol_start > rule.protocol_end )
        {
            printf("dport invalid\n");
            return -1;
        }

        if(0 != ReadTimeInfo(fp, line, &rule.time_start))
        {
            return -1;
        }
    #ifdef RULE_DEBUG
        printf("time_start is %ld\n", rule.time_start);
    #endif
        if(0 != ReadTimeInfo(fp, line, &rule.time_end))
        {
            return -1;
        }
    #ifdef RULE_DEBUG
        printf("time_end is %ld\n", rule.time_end);
    #endif
        if(0 != ReadActionInfo(fp, line, &rule.action))
        {
            return -1;
        }
    #ifdef RULE_DEBUG
        printf("action is %d\n", rule.action);
    #endif
        if(rule.action != 0 && rule.action != 1)
        {
            printf("action is error %d\n", rule.action);
            return -1;
        }


        if(0 != ReadLogInfo(fp, line, &rule.logable))
        {
            return -1;
        }
    #ifdef RULE_DEBUG
        printf("logable is %d\n", rule.logable);
    #endif
        if(rule.logable != 0 && rule.logable != 1)
        {
            printf("logable is error %d\n", rule.logable);
            return -1;
        }


        Rule_add(&rule, &rule_id);

        return 0;
    }

    return 0;
}


int Rule_add(RCP_BLOCK_ACL_RULE_TUPLE *rule, uint32_t *ruleid)
{
    int index;

    pthread_mutex_lock(&rule_list->rulelist_mutex);

    if(rule_list->rule_entry_free == 0)
    {
        printf("Rule Full\n");
        pthread_mutex_unlock(&rule_list->rulelist_mutex);
        return RULE_FULL;
    }

    if( RULE_EXIST == Rule_duplicate_check(rule))
    {
        printf("Rule already exist\n");
        pthread_mutex_unlock(&rule_list->rulelist_mutex);
        return RULE_EXIST;
    }

    index = find_first_free();
    if(-1 == index)
    {
        printf("Rule Full\n");
        pthread_mutex_unlock(&rule_list->rulelist_mutex);
        return RULE_FULL;
    }

    memcpy( (void *)&rule_list->rule_entry[index].rule_tuple, rule, sizeof(RCP_BLOCK_ACL_RULE_TUPLE));

    rule_list->rule_entry_free--;
    rule_list->rule_entry[index].entry_status = RULE_ENTRY_STATUS_USED;
    rule_list->build_status = RULE_BUILD_UNCOMMIT;

    pthread_mutex_unlock(&rule_list->rulelist_mutex);
    *ruleid = index;
    return RULE_OK;
}

int Rule_del_by_id(uint32_t id)
{
    pthread_mutex_lock(&rule_list->rulelist_mutex);

    if(RULE_ENTRY_MAX == rule_list->rule_entry_free)
    {
        pthread_mutex_unlock(&rule_list->rulelist_mutex);
        return RULE_NOT_EXIST;
    }

    if(RULE_ENTRY_STATUS_FREE == rule_list->rule_entry[id].entry_status)
    {
        pthread_mutex_unlock(&rule_list->rulelist_mutex);
        return RULE_NOT_EXIST;
    }
    else
    {
        rule_list->rule_entry[id].entry_status = RULE_ENTRY_STATUS_FREE;
        rule_list->rule_entry_free++;
        rule_list->build_status = RULE_BUILD_UNCOMMIT;

        pthread_mutex_unlock(&rule_list->rulelist_mutex);
        return RULE_OK;
    }

}

int Rule_duplicate_check(RCP_BLOCK_ACL_RULE_TUPLE *rule)
{
    int i = 0;
    for (i = 0; i < RULE_ENTRY_MAX; i++)
    {
        if(rule_list->rule_entry[i].entry_status == RULE_ENTRY_STATUS_FREE)
            continue;

        if(0 == Rule_compare(rule, &rule_list->rule_entry[i].rule_tuple))
        {
            return RULE_EXIST;
        }
    }

    return RULE_OK;
}



void Rule_Notify_Dp_Build_Sync()
{
    MSG_QUE_BODY msgsnd;
    MSG_QUE_BODY msgrcv;

    memset((void *)&msgsnd, 0, sizeof(MSG_QUE_BODY));
    memset((void *)&msgrcv, 0, sizeof(MSG_QUE_BODY));

    memset((void *)&srv_dp_sync->msgbuf, 0, sizeof(srv_dp_sync->msgbuf));

    msgsnd.mtype = COMMAND_DP_END_POINT;
    msgsnd.msg[0] = COMMAND_ACL_RULE_COMMIT;
    msgrcv.mtype = COMMAND_ACL_RULE_COMMIT_ACK;

    MSGQUE_Rpc_Syncall2dp(dp_msg_queue_id, &msgsnd, &msgrcv);

    printf("%s\n", srv_dp_sync->msgbuf);

}



void Rule_Notify_Dp_Build()
{
    MSG_QUE_BODY msgsnd;

    memset((void *)&msgsnd, 0, sizeof(MSG_QUE_BODY));

    msgsnd.mtype = COMMAND_DP_END_POINT;
    msgsnd.msg[0] = COMMAND_ACL_RULE_COMMIT_NOSYNC;

    MSGQUE_Send(dp_msg_queue_id, &msgsnd);
}


