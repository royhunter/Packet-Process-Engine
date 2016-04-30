#ifndef __SRV_RULE_H__
#define __SRV_RULE_H__

#include <common.h>
#include <message.h>
#include <acl_rule.h>


#define RULE_OK         0
#define RULE_FULL       1
#define RULE_EXIST      2
#define RULE_NOT_EXIST  3

extern int Rule_list_init();
extern int Rule_add_acl_rule(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int Rule_del_acl_rule(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int Rule_commit_acl_rule(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int Rule_show_acl_rule(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int Rule_del_acl_rule_all(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int Rule_del_acl_rule_id(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int Rule_set_acl_def_act(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int Rule_show_acl_def_act(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);

extern void Rule_load_thread_start();

extern void Rule_Conf_Recover();


#endif
