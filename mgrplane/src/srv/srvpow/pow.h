#ifndef __POW_H__
#define __POW_H__

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>




#define MAX_RECV_LEN 2048




typedef struct comm_info {
    struct {
        int32_t ifindex;
        uint8_t mac[6];
        uint32_t fd;
    } pow;
}comm_info_t;


extern comm_info_t comm_pow;

extern int32_t pow_send_fn( comm_info_t *info, void *data, uint32_t size );
extern int32_t pow_recv_fn ( comm_info_t *info, void *data, uint32_t *size );
extern int32_t pow_open_fn( comm_info_t *info);
extern int32_t pow_close_fn( comm_info_t *info );
extern int pow_init(void);
extern int pow_rpc_syncall2dp(comm_info_t *node, void *send_buf, uint32_t send_len , void *res_buf, uint32_t *res_len);

#endif
