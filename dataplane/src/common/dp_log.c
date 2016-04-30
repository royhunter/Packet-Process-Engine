#include "dp_log.h"



typedef  int (*fw_alert)(void*);


fw_alert fw_log_fun = NULL;



void reg_fw_alert(fw_alert fun)
{
        fw_log_fun = fun;
}



void DP_Log_Func(mbuf_t *m)
{
    if(NULL == m)
    {
        return;
    }

    if(fw_log_fun)
    {
        fw_log_fun((void*)m);
    }
}




