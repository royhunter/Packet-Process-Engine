
#include "oct-sched.h"
#include <sec-util.h>


oct_sched_t *sched_tbl;


int oct_sched_init(void)
{
    sched_tbl = (oct_sched_t *)cvmx_bootmem_alloc_named(sizeof(oct_sched_t) , CACHE_LINE_SIZE, OCT_SCHED_TABLE_NAME);
    if(NULL == sched_tbl)
    {
        printf("oct_sched_init no mem\n");
        return SEC_NO;
    }

    memset((void *)sched_tbl, 0, sizeof(oct_sched_t));

    return SEC_OK;
}

void oct_seched_Release(void)
{
    int rc;
    rc = cvmx_bootmem_free_named(OCT_SCHED_TABLE_NAME);
    printf("%s free rc=%d\n", OCT_SCHED_TABLE_NAME, rc);
}



int oct_sched_Get(void)
{
#if 0
    const cvmx_bootmem_named_block_desc_t *block_desc = cvmx_bootmem_find_named_block(OCT_SCHED_TABLE_NAME);
    if (block_desc)
    {
        sched_tbl = (oct_sched_t *)(block_desc->base_addr);
    }
    else
    {
        printf("oct_sched_Get error \n");
        return SEC_NO;
    }
#endif
    return SEC_OK;
}
