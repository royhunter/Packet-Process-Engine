#ifndef __SRV_OCTEON_H__
#define __SRV_OCTEON_H__

#include <common.h>
#include <message.h>
extern int octeon_rpccall(uint8_t * from, uint32_t length, uint32_t fd, void *param_p, cmd_type_t cmdack, uint16_t opcode);
extern int octeon_show_test_command(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_show_dp_build_time(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_show_dp_pkt_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_show_mem_pool(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_clear_dp_pkt_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_msgque_rpccall(uint8_t * from, uint32_t length, uint32_t fd, void *param_p, cmd_type_t cmdack, uint16_t opcode);
extern int octeon_set_dbg_print(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_clear_dbg_print(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_show_tcpstream_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_clear_tcpstream_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_set_tcpstream_track(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_set_tcpstream_reasm(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int octeon_set_directfw_able(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
#endif
