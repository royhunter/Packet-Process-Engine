#include "sos_malloc.h"


sos_mem_pool_region_t *sos_mem_pool;




sos_mem_size_t sos_mem_size[SOS_SIZE_NUM] = {
    {16, 4096},
    {32, 4096},
    {64, 4096},
    {96, 2048},
    {128, 2048},
    {256, 1024},
    {512, 512},
    {1024, 256},
    {2048, 128},
    {4096, 64},
    {8192, 32},
};


void sos_mem_block_ctrl_init(sos_mem_pool_region_t *psosmp, uint32_t size_id, void *start, uint32_t size, int initnum)
{
    int i,j;
    int numperchain = initnum/SOS_MEM_CHAIN_INTERNAL_NUM;
    sos_mem_slice_head_t *head;
    void *begin;
    sos_mem_block_Chain *bc;
    
    for(i = 0; i < SOS_MEM_CHAIN_INTERNAL_NUM; i++)
    {
        bc = &psosmp->sos_mem_block_region.sos_mem_block_cfg[size_id].msc[i];
        bc->totalnum = initnum;
        bc->freenum = initnum;

        INIT_LIST_HEAD(&bc->head);
        
        for(j = 0; j < numperchain; j++)
        {
            begin = (void *)((uint8_t *)start + i*j*size);
            head = (sos_mem_slice_head_t *)begin;
            head->headmagic = SOS_MEM_HEAD_MAGIC;
            head->subchain_id = i;
            head->size_type = size_id;
            *(uint32_t *)((uint8_t *)head + SOS_MEM_SLICE_HEAD_SIZE + sos_mem_size[size_id].size) = SOS_MEM_TAIL_MAGIC;
            list_add(&head->list, &bc->head);
        }
    }
}

void sos_mem_block_replenish(sos_mem_pool_region_t *psosmp, uint32_t size_id, void *start, uint32_t size, int init_num)
{
    int i,j;
    int numperchain = init_num/SOS_MEM_CHAIN_INTERNAL_NUM;

    sos_mem_slice_head_t *head;
    void *begin;
    sos_mem_block_Chain *bc;

    for(i = 0; i < SOS_MEM_CHAIN_INTERNAL_NUM; i++)
    {
        bc = &psosmp->sos_mem_block_region.sos_mem_block_cfg[size_id].msc[i];
        cvmx_spinlock_lock(&bc->chain_lock);

        bc->totalnum += init_num;
        bc->freenum += init_num;

        for(j = 0; j < numperchain; j++)
        {
            begin = (void *)((uint8_t *)start + i*j*size);
            head = (sos_mem_slice_head_t *)begin;
            head->headmagic = SOS_MEM_HEAD_MAGIC;
            head->subchain_id = i;
            head->size_type = size_id;
            *(uint32_t *)((uint8_t *)head + SOS_MEM_SLICE_HEAD_SIZE + sos_mem_size[size_id].size) = SOS_MEM_TAIL_MAGIC;
            list_add(&head->list, &bc->head);
        }
        
        cvmx_spinlock_unlock(&bc->chain_lock);
    }
}


int sos_mem_block_init(sos_mem_pool_region_t *psosmp)
{
    uint32_t i;
    int block_used;
    uint32_t size;
    uint32_t initnum;
    uint32_t slicewholesize;
    uint32_t requestsize;
    void *start;
    for (i = 0; i < SOS_SIZE_NUM; i++)
    {
        size = sos_mem_size[i].size;
        initnum = sos_mem_size[i].init_num;
        slicewholesize = size + SOS_MEM_SLICE_HEAD_SIZE + SOS_MEM_TAIL_MAGIC_SIZE;
        requestsize = slicewholesize * initnum;

        if( psosmp->current_size < requestsize)
        {
            printf("sos mem not enough size id is %d\n", i);
            return SEC_NO;
        }
    
        start = psosmp->current_start;      

        sos_mem_block_ctrl_init(psosmp, i, start, slicewholesize, initnum);

        block_used = psosmp->block_num;
        psosmp->sos_mem_block[block_used].size_type = i;
        psosmp->sos_mem_block[block_used].start = start;
        psosmp->sos_mem_block[block_used].len = requestsize;
        psosmp->block_num = block_used + 1;
        
        psosmp->current_size = psosmp->current_size - requestsize;
        psosmp->current_start = (uint8_t *)psosmp->current_start + requestsize;
    } 

    return SEC_OK;
}



int sos_mem_init(void)
{
    void *ptr = (void *)cvmx_bootmem_alloc_named(SOS_MEM_POOL_SIZE , 128, SOS_MEM_POOL_NAME);

    if(NULL == ptr)
        return SEC_NO;

    memset(ptr, 0, SOS_MEM_POOL_SIZE);


    sos_mem_pool = (sos_mem_pool_region_t *)ptr;
    sos_mem_pool->start = ptr;
    sos_mem_pool->total_size = SOS_MEM_POOL_SIZE;

    sos_mem_pool->current_start = (uint8_t *)ptr + SOS_MEM_POOL_REGION_SIZE;
    sos_mem_pool->current_size = sos_mem_pool->total_size - SOS_MEM_POOL_REGION_SIZE;

    if(SEC_OK != sos_mem_block_init(sos_mem_pool))
        return SEC_NO;


    return SEC_OK;  
}

int sos_mem_get(void)
{
    const cvmx_bootmem_named_block_desc_t *block_desc; 

    block_desc = cvmx_bootmem_find_named_block( SOS_MEM_POOL_NAME ); 
    if (block_desc)
    {
        sos_mem_pool = (sos_mem_pool_region_t *)(block_desc->base_addr);
        return SEC_OK;
    }
    else
    {
        printf("sos_mem_get error \n");
        return SEC_NO;
    }
}


static inline int get_best_size(uint32_t size)
{
    int i;
    
    for(i = 0; i < SOS_SIZE_NUM; i++)
    {
        if(size <= sos_mem_size[i].size)
        {
            return i;
        }
    }

    return -1;
}


int sos_mem_replenish(int size_type)
{
    int initnum;
    int slicerawsize;
    int slicewholesize;
    uint32_t requestsize;
    int block_used;
    void *start;

    initnum = sos_mem_size[size_type].init_num;
    slicerawsize = sos_mem_size[size_type].size;

    slicewholesize = slicerawsize + SOS_MEM_SLICE_HEAD_SIZE + SOS_MEM_TAIL_MAGIC_SIZE;
    requestsize = slicewholesize * initnum;

    cvmx_spinlock_lock(&sos_mem_pool->region_lock);

    if( SOS_MEM_BLOCK_MAX == sos_mem_pool->block_num )
    {
        cvmx_spinlock_unlock(&sos_mem_pool->region_lock);
        return SEC_NO;
    }

    if( requestsize > sos_mem_pool->current_size )
    {
        cvmx_spinlock_unlock(&sos_mem_pool->region_lock);
        return SEC_NO;
    }

    start = sos_mem_pool->current_start;

    block_used = sos_mem_pool->block_num;
    sos_mem_pool->sos_mem_block[block_used].size_type = size_type;
    sos_mem_pool->sos_mem_block[block_used].start = start;
    sos_mem_pool->sos_mem_block[block_used].len = requestsize;
    sos_mem_pool->block_num = block_used + 1;

    sos_mem_block_replenish(sos_mem_pool, size_type, start, slicewholesize, initnum);

    sos_mem_pool->current_start = (void *)((uint8_t *)start + requestsize);
    sos_mem_pool->current_size = sos_mem_pool->current_size - requestsize;
    
    cvmx_spinlock_unlock(&sos_mem_pool->region_lock);

    return SEC_OK;
}


void *_sos_mem_alloc(uint32_t size_type)
{
    sos_mem_block_Cfg_t *dst;
    struct list_head *l;
    uint32_t index;
    sos_mem_slice_head_t *slice;
    
    dst = &sos_mem_pool->sos_mem_block_region.sos_mem_block_cfg[size_type];

    index = cvmx_atomic_fetch_and_add32_nosync(&dst->global_index, 1);
    index = index & (SOS_MEM_CHAIN_INTERNAL_NUM - 1);

    cvmx_spinlock_lock(&dst->msc[index].chain_lock);
    if(list_empty(&dst->msc[index].head))
    {
        cvmx_spinlock_unlock(&dst->msc[index].chain_lock);
        return NULL;
    }
    
    l = dst->msc[index].head.next;
    list_del(l);
    dst->msc[index].freenum--;
    cvmx_spinlock_unlock(&dst->msc[index].chain_lock);
    
    slice = container_of(l, sos_mem_slice_head_t, list);
    if(slice->ref != 0)
    {
        printf("slice ref alloc error %d, %p\n", slice->ref, slice);
        return NULL;
    }
    slice->ref = 1;
    return (void *)((uint8_t *)slice + SOS_MEM_SLICE_HEAD_SIZE);
}


void *sos_mem_alloc(uint32_t size)
{
    void *ptr;
    int size_type = get_best_size(size);
    if(size_type < 0)
        return NULL;
    
    ptr = (void *)_sos_mem_alloc(size_type);
    if(NULL == ptr)
    {
        if(SEC_OK == sos_mem_replenish(size_type))
        {
            return _sos_mem_alloc(size_type);
        }
        else
        {
            return NULL;
        }
    }

    return ptr;
}

void sos_mem_free(void *p)
{
    sos_mem_slice_head_t *slice;
    uint32_t subchain_id;
    uint32_t size_type;
    sos_mem_block_Cfg_t *dst;
    slice = (sos_mem_slice_head_t *)((uint8_t *)p - SOS_MEM_SLICE_HEAD_SIZE);

    if(slice->headmagic != SOS_MEM_HEAD_MAGIC)
    {
        printf("buf %p has been destroyed!\n", slice);
        return;
    }

    subchain_id = slice->subchain_id;
    if(subchain_id >= SOS_MEM_CHAIN_INTERNAL_NUM)
    {
        printf("buf %p has been destroyed!\n", slice);
        return;
    }

    size_type = slice->size_type;
    if( size_type > SOS_SIZE_NUM )
    {
        printf("buf %p has been destroyed!\n", slice);
        return;
    }

    if(slice->ref != 1)
    {
        printf("slice ref free error %d, %p\n", slice->ref, slice);
        return;
    }
    slice->ref = 0;


    dst = &sos_mem_pool->sos_mem_block_region.sos_mem_block_cfg[size_type];

    cvmx_spinlock_lock(&dst->msc[subchain_id].chain_lock);
    list_add(&slice->list, &dst->msc[subchain_id].head);
    dst->msc[subchain_id].freenum++;
    cvmx_spinlock_unlock(&dst->msc[subchain_id].chain_lock);

    return;
    
}

