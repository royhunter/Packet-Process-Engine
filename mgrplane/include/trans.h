#ifndef __TRANS__H__
#define __TRANS__H__


#include "common.h"
#include "message.h"


#define SOCK_MAX    1027

typedef enum SOCK_TYPE 
{ 
    TCP_SERVER = 0, 
    TCP_CLIENT = 1, 
    UDP_CLIENT = 2, 
    UDP_SERVER = 3
}SOCK_TYPE_T;

typedef enum SOCK_STATUS {
    INVALID = -1,
    INITIALIZED = 0,
    CONNETED = 1,
    OPERATIONAL = 2,
} SOCK_STATUS_T;




typedef struct tag_SOCK_MAP {
    SOCK_STATUS_T status;
    int conn_num;

    int32_t account_type;
    int32_t account_id;     /*0:admin 1:main 2~5:user1~user4 6:debug*/
    int8_t login_tool[10];

    struct sockaddr_in addr;
    SOCK_TYPE_T sock_type;
} SOCK_MAP;




extern SOCK_MAP sock_map[SOCK_MAX];

extern int server_init(void);
extern void server_run(void);
extern int send_rcp_res(cmd_type_t cmd_ack, uint8_t * from, uint8_t *sbuf, uint32_t fd, void *param_p, char more_flag);


#endif
