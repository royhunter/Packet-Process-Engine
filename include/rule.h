#ifndef __RULE_H__
#define __RULE_H__

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "rpc-common.h"


//#define RULE_DEBUG




extern int Rule_del_all();
extern int Rule_Load_Line(FILE *fp, int line);
extern void Rule_Notify_Dp_Build_Sync();
extern int Rule_add(RCP_BLOCK_ACL_RULE_TUPLE *rule, uint32_t *ruleid);
extern int Rule_duplicate_check(RCP_BLOCK_ACL_RULE_TUPLE *rule);
extern int Rule_del_by_id(uint32_t id);
extern void Rule_Notify_Dp_Build();




#endif
