#ifndef __SRV_FIREWALL_H__
#define __SRV_FIREWALL_H__

#include <common.h>



extern int FW_show_flow_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_clear_flow_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_set_syncheck(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_set_defragmax(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_show_attack_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_set_unsupportaction(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_show_fw_config(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_set_portscan(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_set_portscanaction(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_set_attack_defend_time(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_set_portscan_freq(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_set_synflood_start(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_set_modbus(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_set_modbus_value(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
#endif
