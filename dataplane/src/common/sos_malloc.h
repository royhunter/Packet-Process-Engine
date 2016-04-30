#ifndef __SOS_MALLOC_H__
#define __SOS_MALLOC_H__

#include <sec-common.h>
#include <oct-common.h>
#include <list.h>
typedef enum
{
    SOS_SIZE_16 = 0,
    SOS_SIZE_32,
    SOS_SIZE_64,
    SOS_SIZE_96,
    SOS_SIZE_128,
    SOS_SIZE_192,
    SOS_SIZE_256,
    SOS_SIZE_512,
    SOS_SIZE_1024,
    SOS_SIZE_2048,
    SOS_SIZE_4096,
    SOS_SIZE_8192,
    SOS_SIZE_NUM,
}SOS_MEM_SIZE;

typedef struct {
    uint32_t size;
    uint32_t init_num;
}sos_mem_size_t;




#define SOS_MEM_POOL_SIZE 1*1024*1024*50  /*50M*/
#define SOS_MEM_POOL_NAME "SOS_MEM_REGION"




#define SOS_MEM_CHAIN_INTERNAL_NUM    4

#define SOS_MEM_TAIL_MAGIC_SIZE   4

#define SOS_MEM_HEAD_MAGIC  0x87654321
#define SOS_MEM_TAIL_MAGIC  0x12345678


typedef struct
{
    uint32_t headmagic;
    SOS_MEM_SIZE size_type;
    uint8_t subchain_id;
    uint8_t  ref;
    uint32_t mod_info;
#ifdef SOS_MEM_DBG
    uint8_t *file;
    uint32_t line;
#endif
    struct list_head list;
}sos_mem_slice_head_t;

#define SOS_MEM_SLICE_HEAD_SIZE      sizeof(sos_mem_slice_head_t)



typedef struct
{
    cvmx_spinlock_t chain_lock;
    uint32_t totalnum;
    uint32_t freenum;
    struct list_head head;
}sos_mem_block_Chain;


typedef struct
{
    int32_t global_index;
    cvmx_spinlock_t cfg_lock;
    sos_mem_block_Chain msc[SOS_MEM_CHAIN_INTERNAL_NUM];
}sos_mem_block_Cfg_t;



typedef struct {
    sos_mem_block_Cfg_t sos_mem_block_cfg[SOS_SIZE_NUM];
}sos_mem_block_region_t;



#define SOS_MEM_BLOCK_MAX 4096

typedef struct {
    SOS_MEM_SIZE size_type;
    void *start;
    uint64_t len;
}sos_mem_block_t;



typedef struct {
    
}sos_mem_raw_region_t;






typedef struct {
    void *start;
    uint32_t total_size;
    uint32_t current_size;
    void *current_start;
    cvmx_spinlock_t region_lock;
    uint32_t block_num;
    sos_mem_block_t  sos_mem_block[SOS_MEM_BLOCK_MAX];
    sos_mem_block_region_t sos_mem_block_region;
    sos_mem_raw_region_t sos_mem_raw_region;
}sos_mem_pool_region_t;



#define SOS_MEM_POOL_REGION_SIZE sizeof(sos_mem_pool_region_t)




#ifdef SOS_MEM_DBG

#else
#define SOS_MALLOC(size) sos_mem_alloc(size)
#define SOS_FREE(p)      sos_mem_free(p)
#endif

extern int sos_mem_get(void);
extern int sos_mem_init(void);



#endif
