#include <dp_portscan.h>
#include <oct-time.h>




extern uint32_t flood_hold_time;
portscan_table_info_t *portscan_table;
uint32_t portscan_exception_freq = 50;
uint32_t portscan_able = 1;
uint32_t portscan_action = 0;   /*0: drop  1: fw*/
uint64_t new_pcb[CPU_HW_RUNNING_MAX] = {0, 0, 0, 0};
uint64_t del_pcb[CPU_HW_RUNNING_MAX] = {0, 0, 0, 0};


static inline pcb_t *pcb_alloc()
{
    void *buf = mem_pool_alloc(MEM_POOL_ID_PORTSCAN_BUFFER, 0);
    if(NULL == buf)
        return NULL;

    return (pcb_t *)(buf);
}

static inline void pcb_free(pcb_t *pcb)
{
    mem_pool_free((void *)pcb);
    return;
}


uint32_t portscan_match(pcb_t *pcb, mbuf_t *mb)
{
    return (pcb->sip == mb->ipv4.sip);
}


uint32_t portscan_hashfn(mbuf_t *mb)
{
    return jhash_1word(mb->ipv4.sip, 0) & PORTSCAN_BUCKET_MASK;
}

void PortScan_timeout(Oct_Timer_Threat *o, void *param)
{
    int i;
    uint64_t current_cycle;

    portscan_bucket_t *base;
    portscan_bucket_t *pb;
    pcb_t *pcb;
    pcb_t *tpcb;
    struct hlist_node *n;
    struct hlist_node *t;
    struct hlist_head timeout;

    base = (portscan_bucket_t *)portscan_table->bucket_base_ptr;

    current_cycle = cvmx_get_cycle();

    for(i = 0; i < PORTSCAN_BUCKET_NUM; i++)
    {
        INIT_HLIST_HEAD(&timeout);
        pb = &base[i];

        if(PORTSCAN_TABLE_TRYLOCK(pb) != 0)
            continue;

        hlist_for_each_entry_safe(pcb, t, n, &base[i].hash, list)
        {
            if(((current_cycle > pcb->cycle) && ((current_cycle - pcb->cycle) > FRAG_MAX_TIMEOUT)))
            {
                hlist_del(&pcb->list);

                LOGDBG(SEC_ATTACK_DBG_BIT, "delete one pcb %p\n", pcb);

                del_pcb[LOCAL_CPU_ID]++;
                hlist_add_head(&pcb->list, &timeout);
            }
        }

        PORTSCAN_TABLE_UNLOCK(pb);

        hlist_for_each_entry_safe(tpcb, t, n, &timeout, list)
        {
            hlist_del(&tpcb->list);

            pcb_free(tpcb);
        }

    }

    return;
}


pcb_t *PortScanFind(portscan_bucket_t *fbucket, mbuf_t *mbuf, uint32_t hash)
{
    pcb_t *pcb;
    struct hlist_node *n;

    LOGDBG(SEC_ATTACK_DBG_BIT, "============>enter PortScanFind\n");

    hlist_for_each_entry(pcb, n, &fbucket->hash, list)
    {
        if(portscan_table->match(pcb, mbuf))
        {
            LOGDBG(SEC_ATTACK_DBG_BIT, "frag match is ok\n");

            FCB_UPDATE_TIMESTAMP(pcb);
            return pcb;
        }
    }

    LOGDBG(SEC_ATTACK_DBG_BIT, "frag match is fail\n");

    return NULL;

}




static inline pcb_t *pcb_create(mbuf_t *mb)
{
    pcb_t *pcb = pcb_alloc();
    if(NULL == pcb)
    {
        //STAT_PORTSCAN_PCB_NO;
        return NULL;
    }

    memset((void *)pcb, 0, sizeof(pcb_t));

    pcb->sip = mb->ipv4.sip;

    return pcb;
}

uint32_t PortScan_Detec_process(mbuf_t * mbuf,pcb_t * pcb)
{
    uint16_t current_dport = mbuf->dport;
    LOGDBG(SEC_ATTACK_DBG_BIT, "pcb->portscan_hold_tim is %ld\n", pcb->portscan_hold_time);
    if(pcb->portscan_hold_time)
    {
        if(mbuf->timestamp < pcb->portscan_hold_time)
        {
            return PORTSCAN_HOLD;
        }
        else
        {
            pcb->portscan_hold_time = 0;
        }
    }

    if(pcb->last_dport == 0)/*first create*/
    {
        pcb->last_dport = current_dport;
        pcb->last_cycle = cvmx_get_cycle();
        LOGDBG(SEC_ATTACK_DBG_BIT, "last_dport is %d, last_cycle is %ld\n", pcb->last_dport, pcb->last_cycle);
    }
    else
    {
        if((cvmx_get_cycle() - pcb->last_cycle) < oct_cpu_rate )  // <1s
        {
            LOGDBG(SEC_ATTACK_DBG_BIT, "<1s\n");
            if(pcb->last_dport != current_dport)
            {
                pcb->last_dport = current_dport;
                pcb->exception++;
                if(pcb->last_exception >= portscan_exception_freq)
                {
                    pcb->portscan_hold_time = OCT_TIME_SECONDS_SINCE1970 + flood_hold_time;
                    return PORTSCAN_DETECTED;
                }
            }
        }
        else if( ((cvmx_get_cycle() - pcb->last_cycle) > oct_cpu_rate)
            && ((cvmx_get_cycle() - pcb->last_cycle) < 2 * oct_cpu_rate)) // >1s && <2s
        {
            LOGDBG(SEC_ATTACK_DBG_BIT, ">1s && <2s\n");
            pcb->last_cycle = pcb->last_cycle + oct_cpu_rate;
            pcb->last_exception = pcb->exception;
            pcb->exception = 0;
            if(pcb->last_dport != current_dport)
            {
                pcb->last_dport = current_dport;
                pcb->exception++;
                if(pcb->last_exception >= portscan_exception_freq)
                {
                    pcb->portscan_hold_time = OCT_TIME_SECONDS_SINCE1970 + flood_hold_time;
                    return PORTSCAN_DETECTED;
                }
            }
        }
        else // >2s
        {
            LOGDBG(SEC_ATTACK_DBG_BIT, ">2s\n");
            pcb->last_cycle = cvmx_get_cycle();
            pcb->last_exception = 0;
            pcb->exception = 0;
            if(pcb->last_dport != current_dport)
            {
                pcb->last_dport = current_dport;
                pcb->exception++;
            }
        }
    }

    return PORTSCAN_OK;
}

uint32_t PortScan_Detect_Begin(mbuf_t *mbuf, pcb_t *pcb)
{
    uint32_t ret;

    PORTSCAN_LOCK(pcb);

    ret = PortScan_Detec_process(mbuf, pcb);

    PORTSCAN_UNLOCK(pcb);

    return ret;
}

static inline void pcb_insert(portscan_bucket_t *pb, pcb_t *pcb)
{
    hlist_add_head(&pcb->list, &pb->hash);
}


uint32_t PortScan_Detect(mbuf_t *mb)
{
    uint32_t hash;
    portscan_bucket_t *base;
    portscan_bucket_t *fb;
    pcb_t *pcb;

    if(portscan_able != 1)
    {
        return DECODE_OK;
    }

    hash = portscan_table->hashfn(mb);

    LOGDBG(SEC_ATTACK_DBG_BIT, "port scan hash is %d\n", hash);

    base = (portscan_bucket_t *)portscan_table->bucket_base_ptr;
    fb = &base[hash];

    PORTSCAN_TABLE_LOCK(fb);

    pcb = PortScanFind(fb, mb, hash);

    if(NULL == pcb) /*not find , create a new one and add it into table*/
    {
        pcb = pcb_create(mb);
        if(NULL == pcb)
        {
            PORTSCAN_TABLE_UNLOCK(fb);
            return PORTSCAN_NOMEM;
        }

        FCB_UPDATE_TIMESTAMP(pcb);
        pcb_insert(fb, pcb);
        new_pcb[LOCAL_CPU_ID]++;
    }

    PORTSCAN_TABLE_UNLOCK(fb);

    return PortScan_Detect_Begin(mb, pcb);

}



uint32_t PortScan_Item_init()
{
    Mem_Pool_Cfg *mpc = NULL;

    portscan_item_size_judge();

    printf("PortScan_Item_init\n");
    mpc = (Mem_Pool_Cfg *)cvmx_bootmem_alloc_named(MEM_POOL_TOTAL_PORTSCAN_BUFFER,
                                                    CACHE_LINE_SIZE,
                                                    MEM_POOL_NAME_PORTSCAN_BUFFER);
    if(NULL == mpc)
        return SEC_NO;

    memset((void *)mpc, 0, MEM_POOL_TOTAL_PORTSCAN_BUFFER);

    mpc->slicesize = MEM_POOL_PORTSCAN_BUFFER_SIZE;
    mpc->slicenum = MEM_POOL_PORTSCAN_BUFFER_NUM;
    mpc->datasize = MEM_POOL_PORTSCAN_BUFFER_SIZE - MEM_POOL_SLICE_CTRL_SIZE;
    mpc->start = (uint8_t *)mpc + sizeof(Mem_Pool_Cfg);
    mpc->totalsize = MEM_POOL_PORTSCAN_BUFFER_NUM * MEM_POOL_PORTSCAN_BUFFER_SIZE;
    mem_pool[MEM_POOL_ID_PORTSCAN_BUFFER] = mpc;

    if( SEC_NO == mem_pool_sw_slice_inject(MEM_POOL_ID_PORTSCAN_BUFFER))
    {
        return SEC_NO;
    }

    return SEC_OK;
}



uint32_t PortScan_Module_init()
{
    int i;
    portscan_bucket_t *base;
    portscan_bucket_t *f;

    if(SEC_OK != PortScan_Item_init())
    {
        return SEC_NO;
    }

    portscan_table = (portscan_table_info_t *)cvmx_bootmem_alloc_named((sizeof(portscan_table_info_t) + PORTSCAN_BUCKET_NUM * PORTSCAN_BUCKET_SIZE),  CACHE_LINE_SIZE, PORTSCAN_HASH_TABLE_NAME);
    if(NULL == portscan_table)
    {
        printf("PortScan_Module_init: no memory\n");
        return SEC_NO;
    }
    memset(portscan_table, 0, (sizeof(portscan_table_info_t) + PORTSCAN_BUCKET_NUM * PORTSCAN_BUCKET_SIZE));

    portscan_table->bucket_num = PORTSCAN_BUCKET_NUM;
    portscan_table->bucket_size = PORTSCAN_BUCKET_SIZE;

    portscan_table->item_num = PORTSCAN_ITEM_NUM;
    portscan_table->item_size = PORTSCAN_ITEM_SIZE;

    portscan_table->bucket_base_ptr = (void *)((uint8_t *)portscan_table + sizeof(portscan_table_info_t));

    base = (portscan_bucket_t *)portscan_table->bucket_base_ptr;

    for (i = 0; i < FRAG_BUCKET_NUM; i++)
    {
        INIT_HLIST_HEAD(&base[i].hash);
        f = &base[i];
        PORTSCAN_TABLE_INITLOCK(f);
    }

    portscan_table->match = portscan_match;
    portscan_table->hashfn = portscan_hashfn;

    if(OCT_Timer_Create(0xFFFFFF, 0, 2, LOCAL_CPU_ID, PortScan_timeout, NULL, 0, 1000))/*1s*/
    {
        printf("port scan timer create fail\n");
        return SEC_NO;
    }

    printf("port scan timer create ok\n");

    return SEC_OK;
}

uint32_t PortScan_Module_Release()
{
    int rc;
    rc = cvmx_bootmem_free_named(MEM_POOL_NAME_PORTSCAN_BUFFER);
    printf("%s free rc=%d\n", MEM_POOL_NAME_PORTSCAN_BUFFER, rc);

    rc = cvmx_bootmem_free_named(PORTSCAN_HASH_TABLE_NAME);
    printf("%s free rc=%d\n", PORTSCAN_HASH_TABLE_NAME, rc);

    return SEC_OK;
}

