#ifndef __DP_PORTSCAN_H__
#define __DP_PORTSCAN_H__


#include <sec-common.h>
#include <jhash.h>
#include <mbuf.h>
#include <sec-debug.h>
#include "decode-defrag.h"
#include "decode-ipv4.h"
#include "decode-statistic.h"
#include "oct-rxtx.h"
#include "dp_attack.h"

#include <oct-common.h>
#include <oct-init.h>
#include <hlist.h>

#define PORTSCAN_OK    0
#define PORTSCAN_NOMEM 1
#define PORTSCAN_DETECTED 2
#define PORTSCAN_HOLD   3


typedef struct {
    struct hlist_node   list;
    uint64_t            cycle;
    uint64_t            last_cycle;
    cvmx_spinlock_t     lock;
    uint32_t            sip;
    uint32_t            exception;
    uint32_t            last_exception;
    uint16_t            last_dport;             /*dport*/
    uint64_t            portscan_hold_time;
}pcb_t;




typedef struct
{
    struct hlist_head hash;
    cvmx_spinlock_t bkt_lock;
}portscan_bucket_t;

typedef struct {
    uint32_t bucket_num;
    uint32_t bucket_size;

    uint32_t item_size;
    uint32_t item_num;

    void *bucket_base_ptr;

    uint32_t (*match)(pcb_t * , mbuf_t *);
    uint32_t (*hashfn)(mbuf_t *);
}portscan_table_info_t;

#define PORTSCAN_BUCKET_NUM   65536
#define PORTSCAN_BUCKET_MASK  (PORTSCAN_BUCKET_NUM - 1)



#define PORTSCAN_BUCKET_SIZE  sizeof(portscan_bucket_t)


#define PORTSCAN_ITEM_NUM     100000
#define PORTSCAN_ITEM_SIZE    sizeof(pcb_t)

#define PORTSCAN_HASH_TABLE_NAME   "PORTSCAN_Hash_Table"

#define PORTSCAN_TABLE_INITLOCK(pb) cvmx_spinlock_init(&pb->bkt_lock)
#define PORTSCAN_TABLE_TRYLOCK(pb)  cvmx_spinlock_trylock(&pb->bkt_lock)
#define PORTSCAN_TABLE_LOCK(pb)     cvmx_spinlock_lock(&pb->bkt_lock)
#define PORTSCAN_TABLE_UNLOCK(pb)   cvmx_spinlock_unlock(&pb->bkt_lock)


#define PORTSCAN_INITLOCK(pcb)      cvmx_spinlock_init(&pcb->lock)
#define PORTSCAN_TRYLOCK(pcb)       cvmx_spinlock_trylock(&pcb->lock)
#define PORTSCAN_LOCK(pcb)          cvmx_spinlock_lock(&pcb->lock)
#define PORTSCAN_UNLOCK(pcb)        cvmx_spinlock_unlock(&pcb->lock)

#define PORTSCAN_UPDATE_TIMESTAMP(p)  (p->cycle = cvmx_get_cycle())


static inline void portscan_item_size_judge(void)
{
    BUILD_BUG_ON((sizeof(pcb_t) + sizeof(Mem_Slice_Ctrl_B)) > MEM_POOL_PORTSCAN_BUFFER_SIZE);

    return;
}

extern uint32_t portscan_action;
extern uint32_t PortScan_Module_init();
extern uint32_t PortScan_Detect(mbuf_t *mb);

#endif
