#include <oct-common.h>
#include <sec-util.h>
#include <sec-common.h>

#include "mem_pool.h"



Mem_Pool_Cfg *mem_pool[MEM_POOL_ID_MAX];




void *mem_pool_alloc(int pool_id, uint32_t alloc_size)
{
    int index;
    Mem_Pool_Cfg *mp;
    struct list_head *l;
    Mem_Slice_Ctrl_B *mscb;

    if(MEM_POOL_ID_SMALL_BUFFER <= pool_id && pool_id < MEM_POOL_ID_MAX)
    {
        mp = mem_pool[pool_id];

        if(MEM_POOL_ID_SMALL_BUFFER == pool_id ||  MEM_POOL_ID_LARGE_BUFFER == pool_id)
        {
            if(alloc_size > mp->datasize)
            {
                return NULL;
            }
        }

        index = cvmx_atomic_fetch_and_add32_nosync(&mp->mpc.global_index, 1);
        index = index & (MEM_POOL_INTERNAL_NUM - 1);

        cvmx_spinlock_lock(&mp->mpc.msc[index].chain_lock);
        if(list_empty(&mp->mpc.msc[index].head))
        {
            cvmx_spinlock_unlock(&mp->mpc.msc[index].chain_lock);
            return NULL;
        }
        l = mp->mpc.msc[index].head.next;
        list_del(l);
        mp->mpc.msc[index].freenum--;
        cvmx_spinlock_unlock(&mp->mpc.msc[index].chain_lock);

        mscb = container_of(l, Mem_Slice_Ctrl_B, list);
        if(mscb->ref != 0)
        {
            printf("mscb ref alloc error %d, %p, pool id is %d\n", mscb->ref, mscb, pool_id);
            return NULL;
        }
        mscb->ref = 1;
        return (void *)((uint8_t *)mscb + sizeof(Mem_Slice_Ctrl_B));
    }
    else
    {
        printf("invalid request pool id!\n");
        return NULL;
    }
}


void mem_pool_free(void *buf)
{
    int pool_id;
    int subpool_id;
    Mem_Slice_Ctrl_B *mscb;
    Mem_Pool_Cfg *mp;

    mscb = (Mem_Slice_Ctrl_B *)((uint8_t *)buf - sizeof(Mem_Slice_Ctrl_B));

    if(mscb->magic != MEM_POOL_MAGIC_NUM)
    {
        printf("buf %p has been destroyed!\n", mscb);
        return;
    }

    pool_id = mscb->pool_id;
    if(pool_id >= MEM_POOL_ID_MAX)
    {
        printf("pool id is error %p!\n", mscb);
        return;
    }

    subpool_id = mscb->subpool_id;
    if(subpool_id >= MEM_POOL_INTERNAL_NUM)
    {
        printf("subpool id is error %p!\n", mscb);
        return;
    }

    if(mscb->ref != 1)
    {
        printf("mscb ref free error %d, %p, pool id is %d\n", mscb->ref, mscb, pool_id);
        return;
    }
    mscb->ref = 0;

    mp = mem_pool[pool_id];

    cvmx_spinlock_lock(&mp->mpc.msc[subpool_id].chain_lock);
    list_add(&mscb->list, &mp->mpc.msc[subpool_id].head);
    mp->mpc.msc[subpool_id].freenum++;
    cvmx_spinlock_unlock(&mp->mpc.msc[subpool_id].chain_lock);

    return;
}








int mem_pool_sw_slice_inject(int pool_id)
{
    int i, j;
    int num_perchain;
    uint64_t start_address;
    Mem_Slice_Ctrl_B *mscb;
    Mem_Pool_Cfg *mpc = mem_pool[pool_id];

    if(0 != mpc->slicenum % MEM_POOL_INTERNAL_NUM)
        return SEC_NO;

    num_perchain = mpc->slicenum/MEM_POOL_INTERNAL_NUM;
    start_address = (uint64_t)mpc->start;
    for(i = 0; i < MEM_POOL_INTERNAL_NUM; i++)
    {
        INIT_LIST_HEAD(&mpc->mpc.msc[i].head);
        for(j = 0; j < num_perchain; j++)
        {
            mscb = (Mem_Slice_Ctrl_B *)start_address;
            mscb->magic = MEM_POOL_MAGIC_NUM;
            mscb->pool_id = pool_id;
            mscb->subpool_id = i;
            list_add(&mscb->list, &mpc->mpc.msc[i].head);
            start_address += mpc->slicesize;
        }
        mpc->mpc.msc[i].freenum = num_perchain;
    }

    return SEC_OK;
}





int mem_pool_fpa_slice_inject(int pool_id)
{
    uint32_t i, fpa_pool_id;
    uint64_t start_address;
    Mem_Slice_Ctrl_B *mscb = NULL;

    if(MEM_POOL_ID_HOST_MBUF == pool_id)
    {
        fpa_pool_id = FPA_POOL_ID_HOST_MBUF;
    }
    else if(MEM_POOL_ID_FLOW_NODE == pool_id)
    {
        fpa_pool_id = FPA_POOL_ID_FLOW_NODE;
    }
    else
    {
        printf("invalid pool id: %d\n", pool_id);
        return SEC_NO;
    }

    start_address = (uint64_t)mem_pool[pool_id]->start;
    for (i = 0; i < mem_pool[pool_id]->slicenum; i++)
    {
        mscb = (Mem_Slice_Ctrl_B *)start_address;
        mscb->magic = MEM_POOL_MAGIC_NUM;
        mscb->pool_id = fpa_pool_id;
        cvmx_fpa_free((void *)start_address, fpa_pool_id, 0);
        start_address += mem_pool[pool_id]->slicesize;
    }

    return SEC_OK;
}


int Mem_Pool_Init(void)
{
    /* HOST MBUF POOL INIT*/
    Mem_Pool_Cfg *mpc = (Mem_Pool_Cfg *)cvmx_bootmem_alloc_named(MEM_POOL_TOTAL_HOST_MBUF , CACHE_LINE_SIZE, MEM_POOL_NAME_HOST_MBUF);
    if(NULL == mpc)
    {
        return SEC_NO;
    }

    memset((void *)mpc, 0, MEM_POOL_TOTAL_HOST_MBUF);

    mpc->slicesize = MEM_POOL_HOST_MBUF_SIZE;
    mpc->slicenum = MEM_POOL_HOST_MBUF_NUM;
    mpc->start = (uint8_t *)mpc + MEM_POOL_CFG_SIZE;
    mpc->totalsize = MEM_POOL_HOST_MBUF_NUM * MEM_POOL_HOST_MBUF_SIZE;
    mem_pool[MEM_POOL_ID_HOST_MBUF] = mpc;

    printf("mbuf slicesize is %d, slicenum is %d, start is 0x%p, totalsize is %d\n",
        mpc->slicesize,mpc->slicenum,mpc->start,mpc->totalsize);

    if( SEC_NO == mem_pool_fpa_slice_inject(MEM_POOL_ID_HOST_MBUF))
    {
        return SEC_NO;
    }
    printf("host mbuf pool init ok!\n");


    /* FLOW NODE POOL INIT*/
    mpc = (Mem_Pool_Cfg *)cvmx_bootmem_alloc_named(MEM_POOL_TOTAL_FLOW_NODE, CACHE_LINE_SIZE, MEM_POOL_NAME_FLOW_NODE);
    if(NULL == mpc)
    {
        printf("FLOW NODE POOL INIT FAIL!\n");
        return SEC_NO;
    }

    memset((void *)mpc, 0, MEM_POOL_TOTAL_FLOW_NODE);

    mpc->slicesize = MEM_POOL_FLOW_NODE_SIZE;
    mpc->slicenum = MEM_POOL_FLOW_NODE_NUM;
    mpc->start = (uint8_t *)mpc + MEM_POOL_CFG_SIZE;
    mpc->totalsize = MEM_POOL_FLOW_NODE_NUM * MEM_POOL_FLOW_NODE_SIZE;
    mem_pool[MEM_POOL_ID_FLOW_NODE] = mpc;

    printf("flow node slicesize is %d, slicenum is %d, start is 0x%p, totalsize is %d\n",
        mpc->slicesize,mpc->slicenum,mpc->start,mpc->totalsize);

    if( SEC_NO == mem_pool_fpa_slice_inject(MEM_POOL_ID_FLOW_NODE))
    {
        return SEC_NO;
    }

    printf("flow node pool init ok!\n");

    /*SMALL BUF POOL INIT*/
    printf("small buf pool init\n");
    mpc = (Mem_Pool_Cfg *)cvmx_bootmem_alloc_named(MEM_POOL_TOTAL_SMALL_BUFFER, CACHE_LINE_SIZE, MEM_POOL_NAME_SMALL_BUFFER);
    if(NULL == mpc)
        return SEC_NO;

    memset((void *)mpc, 0, MEM_POOL_TOTAL_SMALL_BUFFER);

    mpc->slicesize = MEM_POOL_SMALL_BUFFER_SIZE;
    mpc->slicenum = MEM_POOL_SMALL_BUFFER_NUM;
    mpc->datasize = MEM_POOL_SMALL_BUFFER_SIZE - MEM_POOL_SLICE_CTRL_SIZE;
    mpc->start = (uint8_t *)mpc + sizeof(Mem_Pool_Cfg);
    mpc->totalsize = MEM_POOL_SMALL_BUFFER_NUM * MEM_POOL_SMALL_BUFFER_SIZE;
    mem_pool[MEM_POOL_ID_SMALL_BUFFER] = mpc;

    if( SEC_NO == mem_pool_sw_slice_inject(MEM_POOL_ID_SMALL_BUFFER))
    {
        return SEC_NO;
    }

    /*LARGE BUF POOL INIT*/
    printf("large buf pool init\n");
    mpc = (Mem_Pool_Cfg *)cvmx_bootmem_alloc_named(MEM_POOL_TOTAL_LARGE_BUFFER, CACHE_LINE_SIZE, MEM_POOL_NAME_LARGE_BUFFER);
    if(NULL == mpc)
        return SEC_NO;

    memset((void *)mpc, 0, MEM_POOL_TOTAL_LARGE_BUFFER);

    mpc->slicesize = MEM_POOL_LARGE_BUFFER_SIZE;
    mpc->slicenum = MEM_POOL_LARGE_BUFFER_NUM;
    mpc->datasize = MEM_POOL_LARGE_BUFFER_SIZE - MEM_POOL_SLICE_CTRL_SIZE;
    mpc->start = (uint8_t *)mpc + sizeof(Mem_Pool_Cfg);
    mpc->totalsize = MEM_POOL_LARGE_BUFFER_NUM * MEM_POOL_LARGE_BUFFER_SIZE;
    mem_pool[MEM_POOL_ID_LARGE_BUFFER] = mpc;

    if( SEC_NO == mem_pool_sw_slice_inject(MEM_POOL_ID_LARGE_BUFFER))
    {
        return SEC_NO;
    }

    return SEC_OK;

}




int Mem_Pool_Get()
{
    Mem_Pool_Cfg *mpc;
    const cvmx_bootmem_named_block_desc_t *block_desc;


    block_desc = cvmx_bootmem_find_named_block(MEM_POOL_NAME_HOST_MBUF);
    if (block_desc)
    {
        mpc = (Mem_Pool_Cfg *)(block_desc->base_addr);
        mem_pool[MEM_POOL_ID_HOST_MBUF] = mpc;
    }
    else
    {
        printf("oct_sched_Get error \n");
        return SEC_NO;
    }

    block_desc = cvmx_bootmem_find_named_block(MEM_POOL_NAME_FLOW_NODE);
    if (block_desc)
    {
        mpc = (Mem_Pool_Cfg *)(block_desc->base_addr);
        mem_pool[MEM_POOL_ID_FLOW_NODE] = mpc;
    }
    else
    {
        printf("oct_sched_Get error \n");
        return SEC_NO;
    }


    block_desc = cvmx_bootmem_find_named_block(MEM_POOL_NAME_SMALL_BUFFER);
    if (block_desc)
    {
        mpc = (Mem_Pool_Cfg *)(block_desc->base_addr);
        mem_pool[MEM_POOL_ID_SMALL_BUFFER] = mpc;
    }
    else
    {
        printf("oct_sched_Get error \n");
        return SEC_NO;
    }

    block_desc = cvmx_bootmem_find_named_block(MEM_POOL_NAME_LARGE_BUFFER);
    if (block_desc)
    {
        mpc = (Mem_Pool_Cfg *)(block_desc->base_addr);
        mem_pool[MEM_POOL_ID_LARGE_BUFFER] = mpc;
    }
    else
    {
        printf("oct_sched_Get error \n");
        return SEC_NO;
    }

    return SEC_OK;
}


void Mem_Pool_Release()
{
    int rc;

    rc = cvmx_bootmem_free_named(MEM_POOL_NAME_HOST_MBUF);
    printf("%s free rc=%d\n", MEM_POOL_NAME_HOST_MBUF, rc);

    rc = cvmx_bootmem_free_named(MEM_POOL_NAME_FLOW_NODE);
    printf("%s free rc=%d\n", MEM_POOL_NAME_FLOW_NODE, rc);

    rc = cvmx_bootmem_free_named(MEM_POOL_NAME_SMALL_BUFFER);
    printf("%s free rc=%d\n", MEM_POOL_NAME_SMALL_BUFFER, rc);

    rc = cvmx_bootmem_free_named(MEM_POOL_NAME_LARGE_BUFFER);
    printf("%s free rc=%d\n", MEM_POOL_NAME_LARGE_BUFFER, rc);


    while(1)
    {
        void *ptr = cvmx_fpa_alloc(FPA_POOL_ID_HOST_MBUF);
        if (!ptr)
			break;
    }

    while(1)
    {
        void *ptr = cvmx_fpa_alloc(FPA_POOL_ID_FLOW_NODE);
        if (!ptr)
			break;
    }


}




