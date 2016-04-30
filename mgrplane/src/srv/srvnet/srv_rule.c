#include "srv_rule.h"
#include "srv_octeon.h"
#include <message.h>
#include <trans.h>
#include <pow.h>
#include <rpc-common.h>
#include <shm.h>
#include <time.h>
#include <pthread.h>


//#define RULE_LODE_DBG
extern int dp_msg_queue_id;

rule_list_t *rule_list;
static pthread_mutex_t rule_list_mutex = PTHREAD_MUTEX_INITIALIZER;// just for cli operation and rule load thread



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


int Rule_list_init()
{
    /*TODO:alloc rule_list a share mem*/
    int fd;

    fd = shm_open(SHM_RULE_LIST_NAME, O_RDWR | O_CREAT | O_TRUNC, 0);

    if (fd < 0) {
        printf("Failed to setup CVMX_SHARED(shm_open)");
        return -1;
    }

    //if (shm_unlink(SHM_RULE_LIST_NAME) < 0)
    //      printf("Failed to shm_unlink shm_name");

    ftruncate(fd, sizeof(rule_list_t));


    void *ptr = mmap(NULL, sizeof(rule_list_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == NULL)
    {
        printf("Failed to setup rule list (mmap copy)");
        return -1;
    }
    rule_list = (rule_list_t *)ptr;

    memset((void *)rule_list, 0, sizeof(rule_list_t));

    rule_list->rule_def_act = ACL_RULE_ACTION_DROP;
    rule_list->rule_entry_free = RULE_ENTRY_MAX;
    rule_list->build_status = RULE_BUILD_COMMIT;

    return 0;
}


int Rule_add(RCP_BLOCK_ACL_RULE_TUPLE *rule)
{
    int index;

    if(rule_list->rule_entry_free == 0)
    {
        LOG("Rule Full\n");
        return RULE_FULL;
    }

    if( RULE_EXIST == Rule_duplicate_check(rule))
    {
        LOG("Rule already exist\n");
        return RULE_EXIST;
    }

    index = find_first_free();
    if(-1 == index)
    {
        LOG("Rule Full\n");
        return RULE_FULL;
    }

    memcpy( (void *)&rule_list->rule_entry[index].rule_tuple, rule, sizeof(RCP_BLOCK_ACL_RULE_TUPLE));

    rule_list->rule_entry_free--;
    rule_list->rule_entry[index].entry_status = RULE_ENTRY_STATUS_USED;
    rule_list->build_status = RULE_BUILD_UNCOMMIT;

    return RULE_OK;
}

int Rule_del(RCP_BLOCK_ACL_RULE_TUPLE *rule)
{
    int i;
    int ret;

    if(rule_list->rule_entry_free == RULE_ENTRY_MAX)
    {
        return RULE_NOT_EXIST;
    }

    for( i = 0; i < RULE_ENTRY_MAX; i++ )
    {
        if(rule_list->rule_entry[i].entry_status == RULE_ENTRY_STATUS_FREE)
        {
            continue;
        }

        ret = Rule_compare(&rule_list->rule_entry[i].rule_tuple, rule);
        if(0 == ret)
        {
            rule_list->rule_entry[i].entry_status = RULE_ENTRY_STATUS_FREE;
            rule_list->rule_entry_free++;
            rule_list->build_status = RULE_BUILD_UNCOMMIT;
            return RULE_OK;
        }
        else
        {
            continue;
        }
    }

    return RULE_NOT_EXIST;
}

int Rule_del_by_id(RCP_BLOCK_ACL_RULE_ID *id)
{
    if(RULE_ENTRY_MAX == rule_list->rule_entry_free)
    {
        return RULE_NOT_EXIST;
    }

    if(RULE_ENTRY_STATUS_FREE == rule_list->rule_entry[id->rule_id].entry_status)
    {
        return RULE_NOT_EXIST;
    }
    else
    {
        rule_list->rule_entry[id->rule_id].entry_status = RULE_ENTRY_STATUS_FREE;
        rule_list->rule_entry_free++;
        rule_list->build_status = RULE_BUILD_UNCOMMIT;
        return RULE_OK;
    }

}


int Rule_del_all()
{
    int i;
    for (i = 0; i < RULE_ENTRY_MAX; i++)
    {
        rule_list->rule_entry[i].entry_status = RULE_ENTRY_STATUS_FREE;
    }
    rule_list->rule_entry_free = RULE_ENTRY_MAX;
    rule_list->build_status = RULE_BUILD_UNCOMMIT;

    return RULE_OK;
}



void Rule_Save_File(FILE *fp)
{
    int i;
    struct tm *p;
    char time_s[32] = {0};
    char time_e[32] = {0};


    fprintf(fp, "Rule Status: %s\n", rule_list->build_status? "Commit":"UnCommit");

    for( i = 0; i < RULE_ENTRY_MAX; i++ )
    {
        if(rule_list->rule_entry[i].entry_status == RULE_ENTRY_STATUS_FREE)
        {
            continue;
        }

        memset(time_s, 0, sizeof(time_s));
        memset(time_e, 0, sizeof(time_e));
        if(rule_list->rule_entry[i].rule_tuple.time_start == 0 && rule_list->rule_entry[i].rule_tuple.time_end == 0)
        {
            strcpy(time_s, "any");
            strcpy(time_e, "any");
        }
        else
        {
            p = gmtime((const time_t *)&rule_list->rule_entry[i].rule_tuple.time_start);
            strftime(time_s, sizeof(time_s), "%Y-%m-%d %H:%M:%S", p);

            p = gmtime((const time_t *)&rule_list->rule_entry[i].rule_tuple.time_end);
            strftime(time_e, sizeof(time_e), "%Y-%m-%d %H:%M:%S", p);
        }

        fprintf(fp,
            "%d: smac: %2x:%2x:%2x:%2x:%2x:%2x,  dmac: %2x:%2x:%2x:%2x:%2x:%2x, sip:%d.%d.%d.%d/%d, dip:%d.%d.%d.%d/%d, sport_start:%d, sport_end:%d, dport_start:%d, dport_end:%d, proto_start:%d, proto_end:%d, time_start:%s, time_end:%s, action:%s, log:%s\n",
            i,
            rule_list->rule_entry[i].rule_tuple.smac[0],
            rule_list->rule_entry[i].rule_tuple.smac[1],
            rule_list->rule_entry[i].rule_tuple.smac[2],
            rule_list->rule_entry[i].rule_tuple.smac[3],
            rule_list->rule_entry[i].rule_tuple.smac[4],
            rule_list->rule_entry[i].rule_tuple.smac[5],
            rule_list->rule_entry[i].rule_tuple.dmac[0],
            rule_list->rule_entry[i].rule_tuple.dmac[1],
            rule_list->rule_entry[i].rule_tuple.dmac[2],
            rule_list->rule_entry[i].rule_tuple.dmac[3],
            rule_list->rule_entry[i].rule_tuple.dmac[4],
            rule_list->rule_entry[i].rule_tuple.dmac[5],
            rule_list->rule_entry[i].rule_tuple.sip >> 24 & 0xff,
            rule_list->rule_entry[i].rule_tuple.sip >> 16 & 0xff,
            rule_list->rule_entry[i].rule_tuple.sip >> 8 & 0xff,
            rule_list->rule_entry[i].rule_tuple.sip & 0xff,
            rule_list->rule_entry[i].rule_tuple.sip_mask,
            rule_list->rule_entry[i].rule_tuple.dip >> 24 & 0xff,
            rule_list->rule_entry[i].rule_tuple.dip >> 16 & 0xff,
            rule_list->rule_entry[i].rule_tuple.dip >> 8 & 0xff,
            rule_list->rule_entry[i].rule_tuple.dip & 0xff,
            rule_list->rule_entry[i].rule_tuple.dip_mask,
            rule_list->rule_entry[i].rule_tuple.sport_start,
            rule_list->rule_entry[i].rule_tuple.sport_end,
            rule_list->rule_entry[i].rule_tuple.dport_start,
            rule_list->rule_entry[i].rule_tuple.dport_end,
            rule_list->rule_entry[i].rule_tuple.protocol_start,
            rule_list->rule_entry[i].rule_tuple.protocol_end,
            time_s,
            time_e,
            rule_list->rule_entry[i].rule_tuple.action? "drop":"fw",
            rule_list->rule_entry[i].rule_tuple.logable? "enable":"disable");
    }
}




int Rule_show_acl_rule(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("Rule_show_acl_rule\n");
    char tmp_rule_file[80];
    FILE *fp = NULL;
    uint32_t result_code;
    uint8_t s_buf[MAX_BUF];
    cmd_type_t cmd_ack = SHOW_ACL_RULE_ACK;

    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;

    sprintf(tmp_rule_file, "/tmp/tmp_rule");

    fp = fopen(tmp_rule_file, "w+");

    if ( NULL != fp )
    {
        fprintf(fp, "ACL Rule:\n");
        Rule_Save_File(fp);
        fclose(fp);
        result_code = RCP_RESULT_OK;
    }
    else
    {
        result_code = RCP_RESULT_FILE_ERR;
    }

    rcp_param_p->nparam = 1;
    rcp_param_p->params_list.params[0].CliResultCode.result_code = result_code;

    send_rcp_res(cmd_ack, from, s_buf, fd, param_p, 0);

    return 0;
}



int Rule_add_acl_rule(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    int ret;
    LOG("Rule_add_acl_rule\n");
    uint8_t s_buf[MAX_BUF];
    cmd_type_t cmd_ack = ADD_ACL_RULE_ACK;

    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;

    RCP_BLOCK_ACL_RULE_TUPLE *blocks = (RCP_BLOCK_ACL_RULE_TUPLE *)(from + MESSAGE_HEADER_LENGTH);

    /*ADD RULE INFO INTO LOCAL MANAGER*/
    pthread_mutex_lock(&rule_list_mutex);
    ret = Rule_add(blocks);
    pthread_mutex_unlock(&rule_list_mutex);
    if(RULE_OK == ret)
    {
        rcp_param_p->params_list.params[0].CliResultCode.result_code = RCP_RESULT_OK;
    }
    else if(RULE_FULL == ret)
    {
        rcp_param_p->params_list.params[0].CliResultCode.result_code = RCP_RESULT_RULE_FULL;
    }
    else if(RULE_EXIST == ret)
    {
        rcp_param_p->params_list.params[0].CliResultCode.result_code = RCP_RESULT_RULE_EXIST;
    }

    rcp_param_p->nparam = 1;


    send_rcp_res(cmd_ack, from, s_buf, fd, param_p, 0);

    return 0;
}


int Rule_del_acl_rule(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    int ret;
    LOG("Rule_del_acl_rule\n");

    uint8_t s_buf[MAX_BUF];
    cmd_type_t cmd_ack = DEL_ACL_RULE_ACK;

    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;

    RCP_BLOCK_ACL_RULE_TUPLE *blocks = (RCP_BLOCK_ACL_RULE_TUPLE *)(from + MESSAGE_HEADER_LENGTH);
    pthread_mutex_lock(&rule_list_mutex);
    ret = Rule_del(blocks);
    pthread_mutex_unlock(&rule_list_mutex);
    if( RULE_OK == ret )
    {
        rcp_param_p->params_list.params[0].CliResultCode.result_code = RCP_RESULT_OK;
    }
    else if( RULE_NOT_EXIST == ret )
    {
        rcp_param_p->params_list.params[0].CliResultCode.result_code = RCP_RESULT_RULE_NOT_EXIST;
    }

    rcp_param_p->nparam = 1;

    send_rcp_res(cmd_ack, from, s_buf, fd, param_p, 0);

    return 0;
}


int Rule_del_acl_rule_id(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    int ret;
    LOG("Rule_del_acl_rule_id\n");

    uint8_t s_buf[MAX_BUF];
    cmd_type_t cmd_ack = DEL_ACL_RULE_ID_ACK;

    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;

    RCP_BLOCK_ACL_RULE_ID *blocks = (RCP_BLOCK_ACL_RULE_ID *)(from + MESSAGE_HEADER_LENGTH);
    pthread_mutex_lock(&rule_list_mutex);
    ret = Rule_del_by_id(blocks);
    pthread_mutex_unlock(&rule_list_mutex);
    if( RULE_OK == ret )
    {
        rcp_param_p->params_list.params[0].CliResultCode.result_code = RCP_RESULT_OK;
    }
    else if( RULE_NOT_EXIST == ret )
    {
        rcp_param_p->params_list.params[0].CliResultCode.result_code = RCP_RESULT_RULE_NOT_EXIST;
    }

    rcp_param_p->nparam = 1;

    send_rcp_res(cmd_ack, from, s_buf, fd, param_p, 0);

    return 0;
}



int Rule_del_acl_rule_all(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("Rule_del_acl_rule_all\n");

    uint8_t s_buf[MAX_BUF];
    cmd_type_t cmd_ack = DEL_ACL_RULE_ALL_ACK;

    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;

    pthread_mutex_lock(&rule_list_mutex);
    Rule_del_all();
    pthread_mutex_unlock(&rule_list_mutex);

    rcp_param_p->params_list.params[0].CliResultCode.result_code = RCP_RESULT_OK;

    rcp_param_p->nparam = 1;

    send_rcp_res(cmd_ack, from, s_buf, fd, param_p, 0);

    return 0;
}


int Rule_commit_acl_rule(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("Rule_commit_acl_rule\n");
    pthread_mutex_lock(&rule_list_mutex);
    octeon_msgque_rpccall(from, length, fd, param_p, COMMIT_ACL_RULE_ACK, COMMAND_ACL_RULE_COMMIT);
    pthread_mutex_unlock(&rule_list_mutex);
    return 0;
}

int Rule_set_acl_def_act(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("Rule_set_acl_def_act\n");

    RCP_BLOCK_ACL_DEF_ACTION *blocks = (RCP_BLOCK_ACL_DEF_ACTION *)(from + MESSAGE_HEADER_LENGTH);
    pthread_mutex_lock(&rule_list_mutex);
    rule_list->rule_def_act = blocks->action;
    octeon_msgque_rpccall(from, length, fd, param_p, SET_ACL_DEF_ACT_ACK, COMMAND_ACL_DEF_ACT_SET);
    pthread_mutex_unlock(&rule_list_mutex);
    return 0;
}

int Rule_show_acl_def_act(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("Rule_show_acl_def_act\n");

    int len;
    uint8_t s_buf[MAX_BUF];
    cmd_type_t cmd_ack = SHOW_ACL_DEF_ACT_ACK;
    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;
    char *ptr = rcp_param_p->params_list.info_buf + rcp_param_p->info_len;

    len = sprintf(ptr, "%s.\n", rule_list->rule_def_act? "drop" : "fw");
    ptr += len;
    rcp_param_p->info_len += len;

    send_rcp_res(cmd_ack, from, s_buf, fd, param_p, 0);

    return 0;
}



static pthread_t rule_load_thread;
static pthread_cond_t rule_load_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t rule_load_mutex = PTHREAD_MUTEX_INITIALIZER;
uint32_t rule_load_notify = 0;

char *rule_conf_filename = "/root/rule_config";


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
    if ( 6 !=  fscanf(fp,"%u:%u:%u:%u:%u:%u",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]))
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


void Rule_Notify_Dp_Build()
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

    printf("notify result is %s\n", srv_dp_sync->msgbuf);
}
int Rule_Load_Line(FILE *fp, int line)
{
    RCP_BLOCK_ACL_RULE_TUPLE rule;
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


        if(0 != ReadMACInfo(fp, line, rule.smac))
        {
            return -1;
        }
        LOG("smac is %2u:%2u:%2u:%2u:%2u:%2u\n",
                rule.smac[0],
                rule.smac[1],
                rule.smac[2],
                rule.smac[3],
                rule.smac[4],
                rule.smac[5] );

        if(0 != ReadMACInfo(fp, line, rule.dmac))
        {
            return -1;
        }
        LOG("dmac is %2u:%2u:%2u:%2u:%2u:%2u\n",
                rule.dmac[0],
                rule.dmac[1],
                rule.dmac[2],
                rule.dmac[3],
                rule.dmac[4],
                rule.dmac[5] );

        if(0 != ReadIPInfo(fp, line, &rule.sip, &rule.sip_mask))
        {
            return -1;
        }

        LOG("sip is %d.%d.%d.%d/%d\n", (int)((rule.sip >> 24)&0xff), (int)((rule.sip >> 16)&0xff), (int)((rule.sip >> 8)&0xff), (int)((rule.sip)&0xff), (int)rule.sip_mask & 0xff );

        if(0 != ReadIPInfo(fp, line, &rule.dip, &rule.dip_mask))
        {
            return -1;
        }

        LOG("dip is %d.%d.%d.%d/%d\n", (int)((rule.dip >> 24)&0xff), (int)((rule.dip >> 16)&0xff), (int)((rule.dip >> 8)&0xff), (int)((rule.dip)&0xff), (int)rule.dip_mask & 0xff );

        if(0 != ReadPortInfo(fp, line, &rule.sport_start, &rule.sport_end))
        {
            return -1;
        }

        LOG("sport start is %d, end is %d\n", rule.sport_start, rule.sport_end);

        if( rule.sport_start > rule.sport_end || rule.sport_end > 0xffff )
        {
            printf("sport invalid\n");
            return -1;
        }

        if(0 != ReadPortInfo(fp, line, &rule.dport_start, &rule.dport_end))
        {
            return -1;
        }

        LOG("dport start is %d, end is %d\n", rule.dport_start, rule.dport_end);

        if( rule.dport_start > rule.dport_end || rule.dport_end > 0xffff )
        {
            printf("sport invalid\n");
            return -1;
        }

        if(0 != ReadProtoInfo(fp, line, &rule.protocol_start, &rule.protocol_end))
        {
            return -1;
        }

        LOG("protocol start is %d, end is %d\n", rule.protocol_start, rule.protocol_end);

        if( rule.protocol_start > rule.protocol_end || rule.protocol_end > 0xff )
        {
            printf("dport invalid\n");
            return -1;
        }

        if(0 != ReadTimeInfo(fp, line, &rule.time_start))
        {
            return -1;
        }

        LOG("time_start is %ld\n", rule.time_start);

        if(0 != ReadTimeInfo(fp, line, &rule.time_end))
        {
            return -1;
        }

        LOG("time_end is %ld\n", rule.time_end);

        if(0 != ReadActionInfo(fp, line, &rule.action))
        {
            return -1;
        }

        LOG("action is %d\n", rule.action);

        if(rule.action != 0 && rule.action != 1)
        {
            LOG("action is error %d\n", rule.action);
            return -1;
        }

        Rule_add(&rule);

        return 0;
    }

    return 0;
}


int Rule_load_from_conf()
{
    int line = 0;
    uint32_t ret;
    FILE *fp;

    fp = fopen(rule_conf_filename, "r");
    if (fp == NULL)
    {
        printf("Couldnt open rule config file\n");
        return  -1;
    }

    printf("open rule config success\n");

    pthread_mutex_lock(&rule_list_mutex);

    Rule_del_all();
    LOG("rule delete all\n");

    while(!feof(fp))
    {
        ret = Rule_Load_Line(fp, line);
        if(ret != 0)
        {
            //printf("config file line %d format err\n", line);
            fclose(fp);
            pthread_mutex_unlock(&rule_list_mutex);
            return 0;
        }
        line++;
    }

    fclose(fp);
    pthread_mutex_unlock(&rule_list_mutex);

    return 0;

}

static void *Rule_Load_Fn(void *arg)
{
    while(1)
    {
        pthread_mutex_lock(&rule_load_mutex);

        while (!rule_load_notify)
        {
            pthread_cond_wait(&rule_load_cond, &rule_load_mutex);
        }

        Rule_load_from_conf();

        LOG("success load rule num is %d\n", RULE_ENTRY_MAX - rule_list->rule_entry_free);

        Rule_Notify_Dp_Build();

        rule_load_notify = 0;

        pthread_mutex_unlock(&rule_load_mutex);
    }

    return NULL;
}


void Rule_config()
{}

void Rule_Load_Notify()
{
    pthread_mutex_lock(&rule_load_mutex);

    Rule_config();  //give a configfile and notify

    rule_load_notify = 1;

    pthread_cond_signal(&rule_load_cond);

    pthread_mutex_unlock(&rule_load_mutex);
}



void Rule_load_thread_start()
{
    pthread_create(&rule_load_thread, NULL, Rule_Load_Fn, NULL);
}



void Rule_Conf_Recover()
{
    pthread_mutex_lock(&rule_load_mutex);

    Rule_load_from_conf();

    printf("success load rule num is %d\n", RULE_ENTRY_MAX - rule_list->rule_entry_free);

    Rule_Notify_Dp_Build();

    pthread_mutex_unlock(&rule_load_mutex);
}



