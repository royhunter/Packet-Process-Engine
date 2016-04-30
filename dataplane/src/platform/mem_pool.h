#ifndef __MEM_POOL_H__
#define __MEM_POOL_H__

#include <list.h>
#include <oct-common.h>
#include <sec-util.h>
#include <oct-fpa.h>

#define MEM_POOL_MAGIC_NUM  0xab01ab01






#define MEM_POOL_INTERNAL_NUM    4


typedef struct MEM_SLICE_CTRL_B_TAG_S
{
    uint32_t magic;
    uint16_t pool_id;
    uint8_t subpool_id;
    uint8_t  ref;
    struct list_head list;
}Mem_Slice_Ctrl_B;



typedef struct MEM_SLICE_CHAIN_TAG_S
{
    cvmx_spinlock_t chain_lock;
    uint32_t freenum;
    struct list_head head;
}Mem_Slice_Chain;

typedef struct MEM_POOL_CTRL_TAG_S
{
    int32_t global_index;
    Mem_Slice_Chain msc[MEM_POOL_INTERNAL_NUM];
}Mem_Pool_Ctrl;



typedef struct MEM_POOL_CFG_TAG_S
{
    void *start;
    uint32_t totalsize;
    uint32_t slicesize;
    uint32_t slicenum;
    uint32_t datasize;
    Mem_Pool_Ctrl mpc;
}CACHE_ALIGNED Mem_Pool_Cfg;


#define MEM_POOL_SLICE_CTRL_SIZE       sizeof(Mem_Slice_Ctrl_B)
#define MEM_POOL_CFG_SIZE              sizeof(Mem_Pool_Cfg)


#define MEM_POOL_HOST_MBUF_SIZE                 256
#define MEM_POOL_FLOW_NODE_SIZE                 256
#define MEM_POOL_SMALL_BUFFER_SIZE              2048
#define MEM_POOL_LARGE_BUFFER_SIZE              8192
#define MEM_POOL_STREAM_TCP_SESSION_SIZE        256
#define MEM_POOL_STREAM_TCP_SEGMENT_SIZE        64
#define MEM_POOL_PORTSCAN_BUFFER_SIZE           128




#define MEM_POOL_HOST_MBUF_NUM               3000
#define MEM_POOL_FLOW_NODE_NUM               100000
#define MEM_POOL_SMALL_BUFFER_NUM            1000
#define MEM_POOL_LARGE_BUFFER_NUM            256
#define MEM_POOL_STREAM_TCP_SESSION_NUM      10000
#define MEM_POOL_STREAM_TCP_SEGMENT_NUM      20000
#define MEM_POOL_PORTSCAN_BUFFER_NUM         100000



#define MEM_POOL_ID_HOST_MBUF     0     /*by fpa 6    256 bytes used for mbuf + fcb*/
#define MEM_POOL_NAME_HOST_MBUF "HOST_MBUF_POOL"
#define MEM_POOL_TOTAL_HOST_MBUF MEM_POOL_HOST_MBUF_NUM * MEM_POOL_HOST_MBUF_SIZE + MEM_POOL_CFG_SIZE

#define MEM_POOL_ID_FLOW_NODE     1     /*by fpa 7    256 bytes used for flowitem*/
#define MEM_POOL_NAME_FLOW_NODE "FLOW_NODE_POOL"
#define MEM_POOL_TOTAL_FLOW_NODE MEM_POOL_FLOW_NODE_NUM * MEM_POOL_FLOW_NODE_SIZE + MEM_POOL_CFG_SIZE

#define MEM_POOL_ID_SMALL_BUFFER  2     /* 2048 bytes*/
#define MEM_POOL_NAME_SMALL_BUFFER "SMALL_BUF_POOL"
#define MEM_POOL_TOTAL_SMALL_BUFFER MEM_POOL_SMALL_BUFFER_NUM * MEM_POOL_SMALL_BUFFER_SIZE + MEM_POOL_CFG_SIZE

#define MEM_POOL_ID_LARGE_BUFFER  3     /* 8192 bytes*/
#define MEM_POOL_NAME_LARGE_BUFFER "LARGE_BUF_POOL"
#define MEM_POOL_TOTAL_LARGE_BUFFER MEM_POOL_LARGE_BUFFER_NUM * MEM_POOL_LARGE_BUFFER_SIZE + MEM_POOL_CFG_SIZE


#define MEM_POOL_ID_STREAMTCP_SESSION_BUFFER  4      /* 256 bytes*/
#define MEM_POOL_NAME_STREAMTCP_SESSION_BUFFER "STREAMTCP_SESSION"
#define MEM_POOL_TOTAL_STREAMTCP_SESSION_BUFFER MEM_POOL_STREAM_TCP_SESSION_NUM * MEM_POOL_STREAM_TCP_SESSION_SIZE + MEM_POOL_CFG_SIZE


#define MEM_POOL_ID_STREAMTCP_SEGMENT_BUFFER  5     /* 64 BYTES*/
#define MEM_POOL_NAME_STREAMTCP_SEGMENT_BUFFER  "STREAMTCP_SEGMENT"
#define MEM_POOL_TOTAL_STREAMTCP_SEGMENT_BUFFER MEM_POOL_STREAM_TCP_SEGMENT_NUM * MEM_POOL_STREAM_TCP_SEGMENT_SIZE + MEM_POOL_CFG_SIZE


#define MEM_POOL_ID_PORTSCAN_BUFFER    6   /*128 BYTES*/
#define MEM_POOL_NAME_PORTSCAN_BUFFER  "PORTSCAN_POOL"
#define MEM_POOL_TOTAL_PORTSCAN_BUFFER MEM_POOL_PORTSCAN_BUFFER_NUM * MEM_POOL_PORTSCAN_BUFFER_SIZE + MEM_POOL_CFG_SIZE



#define MEM_POOL_ID_MAX           (MEM_POOL_ID_PORTSCAN_BUFFER + 1)





static inline void *mem_pool_fpa_slice_alloc(int pool_id)
{
    return cvmx_fpa_alloc(pool_id);
}


static inline void mem_pool_fpa_slice_free(void *buf, int pool_id)
{
    cvmx_fpa_free(buf, pool_id, 0);
}



extern void *mem_pool_alloc(int pool_id, uint32_t size);
extern void mem_pool_free(void *buf);

#define MEM_PORTSCAN_ITEM_ALLOC(size)   mem_pool_alloc(MEM_POOL_ID_PORTSCAN_BUFFER, size)
#define MEM_PORTSCAN_ITEM_FREE(b)    mem_pool_free(b)


#define MEM_2K_ALLOC(size)   mem_pool_alloc(MEM_POOL_ID_SMALL_BUFFER, size)
#define MEM_2K_FREE(b)   mem_pool_free(b)

#define MEM_8K_ALLOC(size)  mem_pool_alloc(MEM_POOL_ID_LARGE_BUFFER, size)
#define MEM_8K_FREE(b)    mem_pool_free(b)

#define MEM_2OR8K_FREE(b) mem_pool_free(b)



extern Mem_Pool_Cfg *mem_pool[];

extern int Mem_Pool_Init(void);
extern int Mem_Pool_Get(void);

extern int mem_pool_sw_slice_inject(int pool_id);
extern void Mem_Pool_Release();



#endif
