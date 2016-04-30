#include "pow.h"






int pow_rpc_syncall2dp(comm_info_t *node, void *send_buf, uint32_t send_len , void *res_buf, uint32_t *res_len)
{

    if(pow_send_fn( node, (void *)send_buf, send_len ) < 0)
    {
        printf("pow_send err\n");
        return -1;
    }


    if(pow_recv_fn(node, res_buf, res_len) < 0)
    {
        printf("pow_recv err\n");
        return -1;
    }
    else
    {
        return 0;
    }
}
