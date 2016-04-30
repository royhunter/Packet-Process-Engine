#include <sec-common.h>
#include <jhash.h>
#include <mbuf.h>
#include <sec-debug.h>
#include "decode-defrag.h"
#include "decode-ipv4.h"
#include "decode-statistic.h"
#include "oct-rxtx.h"
#include "dp_log.h"
#include "output.h"
#include "dp_attack.h"



uint64_t new_fcb[CPU_HW_RUNNING_MAX] = {0, 0, 0, 0};
uint64_t del_fcb[CPU_HW_RUNNING_MAX] = {0, 0, 0, 0};


int32_t fcb_running_num = 0;


frag_table_info_t *ip4_frags_table;

uint32_t defrag_cache_max = 8;



static inline fcb_t *fcb_alloc()
{
    Mem_Slice_Ctrl_B *mscb;
    void *buf = mem_pool_fpa_slice_alloc(FPA_POOL_ID_HOST_MBUF);
    if(NULL == buf)
        return NULL;

    mscb = (Mem_Slice_Ctrl_B *)buf;
    mscb->ref = 1;

    return (fcb_t *)((uint8_t *)buf + sizeof(Mem_Slice_Ctrl_B));
}


static inline void fcb_free(fcb_t *fcb)
{
    Mem_Slice_Ctrl_B *mscb = (Mem_Slice_Ctrl_B *)((uint8_t *)fcb - sizeof(Mem_Slice_Ctrl_B));

    cvmx_atomic_add32(&fcb_running_num, -1);

    if(MEM_POOL_MAGIC_NUM != mscb->magic)
    {
        return;
    }
    if(FPA_POOL_ID_HOST_MBUF != mscb->pool_id)
    {
        return;
    }

    if(mscb->ref != 1)
    {
        printf("mscb ref free error %d, %p\n", mscb->ref, mscb);
        return;
    }
    mscb->ref = 0;

    mem_pool_fpa_slice_free((void *)mscb, mscb->pool_id);

    return;
}



static inline fcb_t *fcb_create(mbuf_t *mb)
{

    uint32_t fcb_num;
    fcb_num = cvmx_atomic_fetch_and_add32(&fcb_running_num, 1);
    if(fcb_num >= DEFRAG_FCB_MAX)
    {
        cvmx_atomic_add32(&fcb_running_num, -1);
        LOGDBG(SEC_DEFRAG_DBG_BIT, "FCB IS FULL\n");
        STAT_FRAG_FCB_FULL;
        return NULL;
    }

    fcb_t *fcb = fcb_alloc();
    if(NULL == fcb)
    {
        STAT_FRAG_FCB_NO;
        cvmx_atomic_add32(&fcb_running_num, -1);
        return NULL;
    }

    memset((void *)fcb, 0, sizeof(fcb_t));

    fcb->sip = mb->ipv4.sip;
    fcb->dip = mb->ipv4.dip;
    fcb->id  = mb->defrag_id;

    return fcb;
}

static inline void fcb_insert(frag_bucket_t *fb, fcb_t *fcb)
{
    hlist_add_head(&fcb->list, &fb->hash);
}



uint32_t ip4_frag_hashfn(mbuf_t *mb)
{
    return jhash_3words(mb->ipv4.sip, mb->ipv4.dip, mb->defrag_id, 0) & FRAG_BUCKET_MASK;
}



uint32_t ip4_frag_match(fcb_t *fcb, mbuf_t *mb)
{
    return (fcb->id == mb->defrag_id
        && fcb->sip == mb->ipv4.sip
        && fcb->dip == mb->ipv4.dip);
}



fcb_t *FragFind(frag_bucket_t *fbucket, mbuf_t *mbuf, uint32_t hash)
{
    fcb_t *fcb;
    struct hlist_node *n;

    LOGDBG(SEC_DEFRAG_DBG_BIT, "============>enter FragFind\n");

    hlist_for_each_entry(fcb, n, &fbucket->hash, list)
    {
        if(ip4_frags_table->match(fcb, mbuf))
        {
            LOGDBG(SEC_DEFRAG_DBG_BIT, "frag match is ok\n");

            FCB_UPDATE_TIMESTAMP(fcb);
            return fcb;
        }
    }

    LOGDBG(SEC_DEFRAG_DBG_BIT, "frag match is fail\n");

    return NULL;

}


void Frag_defrag_freefrags(fcb_t *fcb)
{
    mbuf_t *head;
    mbuf_t *next;
    head = fcb->fragments;
    while(head)
    {
        next = head->next;
        PACKET_DESTROY_ALL(head);
        head = next;
    }
    fcb->fragments = NULL;
    fcb->fragments_tail = NULL;
}

mbuf_t *Frag_defrag_setup(mbuf_t *head, fcb_t *fcb)
{
    mbuf_t *new_mb;
    void *packet_buffer;

    new_mb = MBUF_ALLOC();
    if(NULL == new_mb)
    {
        return NULL;
    }

    if(head->proto == PROTO_ICMP)
    {
        packet_buffer = MEM_8K_ALLOC(1000);
    }
    else
    {
        packet_buffer = MEM_8K_ALLOC(fcb->total_fraglen +
            ((uint64_t)(head->network_header) - (uint64_t)(head->pkt_ptr) + IPV4_GET_HLEN(head)));
    }

    if(NULL == packet_buffer)
    {
        MBUF_FREE(new_mb);
        return NULL;
    }

    memset((void *)new_mb, 0, sizeof(mbuf_t));

    PKTBUF_SET_SW(new_mb);
    new_mb->pkt_ptr = packet_buffer;


    new_mb->ethh = head->ethh;
    new_mb->vlan_idx = head->vlan_idx;
    new_mb->vlan_id = head->vlan_id;
    new_mb->network_header = head->network_header;
    new_mb->transport_header = head->transport_header;
    new_mb->payload = head->payload;
    packet_header_ptr_adjust(new_mb, head->pkt_ptr, packet_buffer);

    new_mb->magic_flag = MBUF_MAGIC_NUM;
    new_mb->input_port = head->input_port;

    memcpy((void *)new_mb->eth_dst, (void *)head->eth_dst, sizeof(new_mb->eth_dst));
    memcpy((void *)new_mb->eth_src, (void *)head->eth_src, sizeof(new_mb->eth_src));

    new_mb->ipv4.sip = head->ipv4.sip;
    new_mb->ipv4.dip = head->ipv4.dip;

    new_mb->sport = head->sport;
    new_mb->dport = head->dport;

    new_mb->proto = head->proto;

    return new_mb;
}

mbuf_t *Frag_defrag_reasm(fcb_t *fcb)
{
    int ihlen;
    int len;
    mbuf_t *reasm_mb;
    mbuf_t *next;
    mbuf_t *head = fcb->fragments;

    /* Allocate a new buffer for the datagram. */
    ihlen = IPV4_GET_HLEN(head);
    len = ihlen + fcb->total_fraglen;

    //if(len > IPV4_PKTLEN_MAX)
        //goto out_oversize;

    reasm_mb = Frag_defrag_setup(head, fcb);
    if(NULL == reasm_mb)
        goto setup_err;

    memcpy((void *)reasm_mb->pkt_ptr, (void *)head->pkt_ptr, head->pkt_totallen);
    reasm_mb->pkt_totallen += head->pkt_totallen;
    next = head->next;
    if(head->proto != PROTO_ICMP)
    {
        while(next)
        {
            memcpy((void *)((uint8_t *)reasm_mb->pkt_ptr + reasm_mb->pkt_totallen), (void *)((uint8_t *)next->pkt_ptr + next->pkt_totallen - next->frag_len), next->frag_len);
            reasm_mb->pkt_totallen += next->frag_len;
            next = next->next;
        }

        IPV4_SET_IPLEN(reasm_mb, len);
        ((IPV4Hdr *)(reasm_mb->network_header))->ip_off = 0;
        IPV4_SET_IPCSUM(reasm_mb, IPV4CalculateChecksum((uint16_t *)((reasm_mb->network_header)), ihlen));
    }
    else
    {
        while(next)
        {
            reasm_mb->pkt_totallen += next->frag_len;
            next = next->next;
        }
        ((IPV4Hdr *)(reasm_mb->network_header))->ip_off = 0;
        //printf("reasm_mb->pkt_totallen is %d\n", reasm_mb->pkt_totallen);
    }

    reasm_mb->fcb = (void *)fcb;
    reasm_mb->fragments = fcb->fragments;

    fcb->fragments = NULL;
    fcb->fragments_tail = NULL;

    reasm_mb->flags |= PKT_FRAG_REASM_COMP;
    fcb->status |= DEFRAG_COMPLETE;
    FCB_SET_DELETE(fcb);

    LOGDBG(SEC_DEFRAG_DBG_BIT, "REASM Success!\n");
    STAT_FRAG_REASM_OK;
    return reasm_mb;
setup_err:
    STAT_FRAG_SETUP_ERR;
    return NULL;
//out_oversize:
    //STAT_FRAG_OUT_OVERSIZE;
    //return NULL;
}




mbuf_t *Frag_defrag_process(mbuf_t * mbuf,fcb_t * fcb)
{
    int i;
    mbuf_t *prev, *next;
    int offset;
    int end;
    int teardrop;

    if(fcb->last_in & DEFRAG_COMPLETE)
        goto err;

    /* Determine the position of this fragment. */
    offset = mbuf->frag_offset;
    end = offset + mbuf->frag_len;

    /* Is this the final fragment? */
    if(0 == IPV4_GET_MF(mbuf))/*final*/
    {
        if( end < fcb->total_fraglen || (fcb->last_in & DEFRAG_LAST_IN) )/*but last already in, so error*/
            goto err;
        fcb->last_in |= DEFRAG_LAST_IN;
        fcb->total_fraglen = end;
    }
    else/*not final*/
    {
        if(end > fcb->total_fraglen)/*last must be not in*/
        {
            if(fcb->last_in & DEFRAG_LAST_IN)/*but last already in, so error*/
                goto err;
            fcb->total_fraglen = end;
        }
    }

    /*
        * Find out which fragments are in front and at the back of us
        * in the chain of fragments so far.  We must know where to put
        * this fragment, right?
        */
    prev = fcb->fragments_tail;
    if(!prev || prev->frag_offset < offset)
    {
        next = NULL;
        goto found;
    }
    prev = NULL;
    for(next = fcb->fragments; next != NULL; next = next->next)
    {
        if(next->frag_len >= offset)
            break;   /*bingo*/
        prev = next;
    }

found:
    /*
        * We found where to put this one.  Check for overlap with
         * preceding fragment, and, if needed, align things so that
         * any overlaps are eliminated.
        */
    if(prev){
        i = (prev->frag_offset + prev->frag_len) - offset;
        if(i > 0)    /*overlap with prev*/
        {
            teardrop = 1;
            goto err;
        }
    }

    if(next){
        i = next->frag_offset - end;
        if(i < 0)  /*overlap with next*/
        {
            teardrop = 1;
            goto err;
        }
    }

    /* Insert this fragment in the chain of fragments. */
    mbuf->next = next;
    if(!next)
        fcb->fragments_tail = mbuf;
    if(prev)
        prev->next = mbuf;
    else
        fcb->fragments = mbuf;

    fcb->cache_num++;

    fcb->meat += mbuf->frag_len;
    if(offset == 0)
        fcb->last_in |= DEFRAG_FIRST_IN;

    if(fcb->last_in == (DEFRAG_FIRST_IN | DEFRAG_LAST_IN) &&
        fcb->meat == fcb->total_fraglen)
    {
        LOGDBG(SEC_DEFRAG_DBG_BIT, "all in begin to reasm\n");
        return Frag_defrag_reasm(fcb);
    }
    else
    {
        STAT_FRAG_CACHE_OK;
        return NULL;  /*cached*/
    }

err:
    if(teardrop == 1)
    {
        DP_Teardrop_Attack_Monitor(mbuf);
    }
    output_drop_proc(mbuf);
    STAT_FRAG_DEFRAG_ERR;
    return NULL;
}



/*
 * PACKET_HW TO PACKET_SW
 * Cache
 * merge
 */
mbuf_t *Frag_defrag_begin(mbuf_t *mbuf, fcb_t *fcb)
{
    mbuf_t *mb;
    if(SEC_OK != PACKET_HW2SW(mbuf, SW2K_ZONE))
    {
        output_drop_proc(mbuf);
        STAT_FRAG_HW2SW_ERR;
        return NULL;
    }

    FCB_LOCK(fcb);

    if(fcb->status & DEFRAG_DELETE)
    {
        output_drop_proc(mbuf);
        FCB_UNLOCK(fcb);
        return NULL;
    }

    if(fcb->cache_num >= defrag_cache_max)
    {
        FCB_UNLOCK(fcb);
        output_drop_proc(mbuf);
        LOGDBG(SEC_DEFRAG_DBG_BIT, "CACHE FULL\n");
        DP_Log_Func(mbuf);
        STAT_FRAG_CACHE_FULL;
        return NULL;
    }

    mb = Frag_defrag_process(mbuf, fcb);

    FCB_UNLOCK(fcb);

    return mb;
}


mbuf_t *Defrag(mbuf_t *mb)
{
    uint32_t hash;
    frag_bucket_t *base;
    frag_bucket_t *fb;
    fcb_t *fcb;

    hash = ip4_frags_table->hashfn(mb);

    LOGDBG(SEC_DEFRAG_DBG_BIT, "frag hash is %d\n", hash);

    mb->fcb_hash = hash;

    base = (frag_bucket_t *)ip4_frags_table->bucket_base_ptr;
    fb = &base[hash];

    FCB_TABLE_LOCK(fb);

    fcb = FragFind(fb, mb, hash);

    if(NULL == fcb) /*not find , create a new one and add it into table*/
    {
        fcb = fcb_create(mb);
        if(NULL == fcb)
        {
            FCB_TABLE_UNLOCK(fb);
            output_drop_proc(mb);
            return NULL;
        }

        FCB_UPDATE_TIMESTAMP(fcb);
        fcb_insert(fb, fcb);
        new_fcb[LOCAL_CPU_ID]++;
    }

    FCB_TABLE_UNLOCK(fb);

    return Frag_defrag_begin(mb, fcb);
}


void Frag_defrag_timeout(Oct_Timer_Threat *o, void *param)
{
    int i;
    uint64_t current_cycle;

    frag_bucket_t *base;
    frag_bucket_t *fb;
    fcb_t *fcb;
    fcb_t *tfcb;
    mbuf_t *mb;
    mbuf_t *next;
    struct hlist_node *n;
    struct hlist_node *t;
    struct hlist_head timeout;

    base = (frag_bucket_t *)ip4_frags_table->bucket_base_ptr;

    current_cycle = cvmx_get_cycle();

    for(i = 0; i < FRAG_BUCKET_NUM; i++)
    {
        INIT_HLIST_HEAD(&timeout);
        fb = &base[i];

        if(FCB_TABLE_TRYLOCK(fb) != 0)
            continue;

        hlist_for_each_entry_safe(fcb, t, n, &base[i].hash, list)
        {
            if(((current_cycle > fcb->cycle) && ((current_cycle - fcb->cycle) > FRAG_MAX_TIMEOUT))
                || fcb->status & DEFRAG_DELETE)
            {
                hlist_del(&fcb->list);

                LOGDBG(SEC_DEFRAG_DBG_BIT, "delete one fcb %p\n", fcb);

                del_fcb[LOCAL_CPU_ID]++;
                hlist_add_head(&fcb->list, &timeout);
            }
        }

        FCB_TABLE_UNLOCK(fb);

        hlist_for_each_entry_safe(tfcb, t, n, &timeout, list)
        {
            hlist_del(&tfcb->list);

            /*TODO: session ageing do something*/
            mb = tfcb->fragments;
            while(mb)
            {
                next = mb->next;
                output_drop_proc(mb);
                mb = next;
            }
            fcb_free(tfcb);
        }

    }

    return;
}


void Frag_defrag_sendfrags(mbuf_t *mb)
{
    mbuf_t *head;
    mbuf_t *next;
    fcb_t *fcb = (fcb_t *)mb->fcb;
    uint8_t outport;

    head = fcb->fragments;
    while(head)
    {
        next = head->next;
        outport = oct_tx_port_get(head->input_port);
        oct_tx_process_sw(head, outport);
        head = next;
    }
    fcb->fragments = NULL;
    fcb->fragments_tail = NULL;

    PKT_CLEAR_IP_FRAG_COMP(mb);

    PACKET_DESTROY_ALL(mb);
}






uint32_t FragModule_init()
{
    int i;
    frag_bucket_t *base;
    frag_bucket_t *f;

    ip4_frags_table = (frag_table_info_t *)cvmx_bootmem_alloc_named((sizeof(frag_table_info_t) + FRAG_BUCKET_NUM * FRAG_BUCKET_SIZE),  CACHE_LINE_SIZE, FRAG_HASH_TABLE_NAME);
    if(NULL == ip4_frags_table)
    {
        printf("ipfrag_init: no memory\n");
        return SEC_NO;
    }

    memset(ip4_frags_table, 0, (sizeof(frag_table_info_t) + FRAG_BUCKET_NUM * FRAG_BUCKET_SIZE));

    ip4_frags_table->bucket_num = FRAG_BUCKET_NUM;
    ip4_frags_table->bucket_size = FRAG_BUCKET_SIZE;

    ip4_frags_table->item_num = FRAG_ITEM_NUM;
    ip4_frags_table->item_size = FRAG_ITEM_SIZE;

    ip4_frags_table->bucket_base_ptr = (void *)((uint8_t *)ip4_frags_table + sizeof(frag_table_info_t));

    base = (frag_bucket_t *)ip4_frags_table->bucket_base_ptr;

    for (i = 0; i < FRAG_BUCKET_NUM; i++)
    {
        INIT_HLIST_HEAD(&base[i].hash);
        f = &base[i];
        FCB_TABLE_INITLOCK(f);
    }

    ip4_frags_table->match = ip4_frag_match;
    ip4_frags_table->hashfn = ip4_frag_hashfn;

    if(OCT_Timer_Create(0xFFFFFF, 0, 2, LOCAL_CPU_ID, Frag_defrag_timeout, NULL, 0, 1000))/*1s*/
    {
        printf("timer create fail\n");
        return SEC_NO;
    }

    printf("frag age timer create ok\n");

    return SEC_OK;
}

void FragModule_Release()
{
    int rc;
    rc = cvmx_bootmem_free_named(FRAG_HASH_TABLE_NAME);
    printf("%s free rc=%d\n", FRAG_HASH_TABLE_NAME, rc);

}


uint32_t FragModuleInfo_Get()
{

    const cvmx_bootmem_named_block_desc_t *block_desc = cvmx_bootmem_find_named_block(FRAG_HASH_TABLE_NAME);
    if (block_desc)
    {
        ip4_frags_table = (frag_table_info_t *)(block_desc->base_addr);
    }
    else
    {
        printf("FragModuleInfo_Get error \n");
        return SEC_NO;
    }


    return SEC_OK;
}

