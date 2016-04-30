#ifndef __ACL_RULE_H__
#define __ACL_RULE_H__

#include <rpc-common.h>
#include <pthread.h>


#define RULE_ENTRY_MAX 10000

#define RULE_ENTRY_STATUS_FREE 0
#define RULE_ENTRY_STATUS_USED 1


#define RULE_BUILD_UNCOMMIT  0
#define RULE_BUILD_COMMIT    1


#define ACL_RULE_ACTION_FW 0
#define ACL_RULE_ACTION_DROP 1


#define RULE_OK         0
#define RULE_FULL       1
#define RULE_EXIST      2
#define RULE_NOT_EXIST  3

typedef struct{
    int8_t entry_status;
    RCP_BLOCK_ACL_RULE_TUPLE rule_tuple;
}rule_entry_t;



typedef struct
{
    uint32_t rule_def_act;
    int rule_entry_free;
    int build_status;
    pthread_mutex_t rulelist_mutex;
    rule_entry_t rule_entry[RULE_ENTRY_MAX];
}rule_list_t;

extern rule_list_t *rule_list;

#endif