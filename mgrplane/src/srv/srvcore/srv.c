#include "trans.h"
#include "common.h"
#include <srv_rule.h>
#include <shm.h>

SRV_DP_SYNC *srv_dp_sync;


int dp_msg_queue_id;
int srv_dp_sync_init()
{
    /*TODO:alloc rule_list a share mem*/
    int fd;

    dp_msg_queue_id = MSGQUE_Init(SHM_MSGQUE_KEY);
    if(dp_msg_queue_id < 0)
    {
        return -1;
    }

    fd = shm_open(SHM_SRV_DP_SYNC_NAME, O_RDWR | O_CREAT | O_TRUNC, 0);

    if (fd < 0) {
        printf("Failed to setup CVMX_SHARED(shm_open)");
        return -1;
    }

    //if (shm_unlink(SHM_RULE_LIST_NAME) < 0)
    //      printf("Failed to shm_unlink shm_name");

    ftruncate(fd, sizeof(SRV_DP_SYNC));


    void *ptr = mmap(NULL, sizeof(SRV_DP_SYNC), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == NULL)
    {
        printf("Failed to setup rule list (mmap copy)");
        return -1;
    }
    srv_dp_sync = (SRV_DP_SYNC *)ptr;

    memset((void *)srv_dp_sync, 0, sizeof(SRV_DP_SYNC));

    srv_dp_sync->magic = SRV_DP_SYNC_MAGIC;

    return 0;
}

void srv_sync_dp()
{
    srv_dp_sync->srv_initdone = 1;
    printf("\nsrv init done, waiting for dp...\n");

    srv_dp_sync->srv_notify_dp = 1;

    while(!srv_dp_sync->dp_ack);

    printf("dp already, srv begin run...\n");
}





int main(int argc, char *argv[])
{
    int ch;

    while ((ch = getopt(argc, argv, "pdc:x")) != -1) {
        switch (ch) {
        case 'd':
            debugprint = 1;
            break;
        }
    }

    if (!debugprint) {
        daemon(0, 1);
    }

    server_init();

    if(Rule_list_init() < 0)
    {
        exit(-1);
    }

    if(srv_dp_sync_init() < 0)
    {
        exit(-1);
    }

    srv_sync_dp();

    //Rule_Conf_Recover();

    //printf("start rule load thread...\n");
    //Rule_load_thread_start();

    printf("server init done.\n");

    printf("now server running....\n");
    server_run();

    return 0;
}



