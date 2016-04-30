#ifndef __OCT_SCHED_H__
#define __OCT_SCHED_H__

#include <sec-common.h>
#include <oct-common.h>
#include "oct-arch.h"


typedef struct OCT_SCHED_tag_t
{
    uint32_t  watchdog_disabled;
    uint32_t  watchdog_retry;
    struct
    {
        uint32_t watchdog_enabled;
        uint32_t watchdog_ok;
    }data[CPU_HW_RUNNING_MAX];
}oct_sched_t;



#define OCT_SCHED_TABLE_NAME "oct_sched_table"




#define WD_WATCHDOG_TIMEOUT         4
#define WD_WATCHDOG_OK              0
#define WD_WATCHDOG_CHECK_INTERVAL  1



#define watchdog_ok()       sched_tbl->data[LOCAL_CPU_ID].watchdog_ok = 0;
#define register_watchdog() sched_tbl->data[LOCAL_CPU_ID].watchdog_enabled = 1;


extern oct_sched_t *sched_tbl;
extern int oct_sched_init(void);
extern int oct_sched_Get(void);

extern void wd_watchdog_init(void);
extern void oct_seched_Release(void);


#endif
