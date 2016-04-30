#include <mbuf.h>
#include <decode-defrag.h>
#include <decode.h>
#include <flow.h>


static inline void packet_recycle(mbuf_t *mbuf)
{
    FlowDeReference((flow_item_t **)&(mbuf->flow));
}


mbuf_t *mbuf_alloc()
{
    void *buf = mem_pool_fpa_slice_alloc(FPA_POOL_ID_HOST_MBUF);
    if(NULL == buf)
        return NULL;

    Mem_Slice_Ctrl_B *mscb = (Mem_Slice_Ctrl_B *)((uint8_t *)buf);
    mscb->ref = 1;

    return (mbuf_t *)((uint8_t *)buf + sizeof(Mem_Slice_Ctrl_B));
}


void mbuf_free(mbuf_t *mb)
{

    //packet_recycle(mb);

    Mem_Slice_Ctrl_B *mscb = (Mem_Slice_Ctrl_B *)((uint8_t *)mb - sizeof(Mem_Slice_Ctrl_B));
    if(MEM_POOL_MAGIC_NUM != mscb->magic)
    {
        printf("mbuf has been destroyed\n");
        return;
    }
    if(FPA_POOL_ID_HOST_MBUF != mscb->pool_id)
    {
        printf("mbuf pool id error\n");
        return;
    }

    if(mscb->ref != 1)
    {
        printf("mbuf mscb ref free error %d, %p\n", mscb->ref, mscb);
        return;
    }
    mscb->ref = 0;

    mem_pool_fpa_slice_free((void *)mscb, mscb->pool_id);

    return;
}




/*
 *   first: free packet
 *   second: free mbuf
 */
void packet_destroy_all(mbuf_t *mbuf)
{
    cvmx_buf_ptr_t buffer_ptr;
    uint64_t start_of_buffer;

    /*free packet, find start of packet buffer*/
    if(PKTBUF_IS_HW(mbuf))
    {
        buffer_ptr = mbuf->packet_ptr;
        start_of_buffer = ((buffer_ptr.s.addr >> 7) - buffer_ptr.s.back) << 7;

        cvmx_fpa_free(cvmx_phys_to_ptr(start_of_buffer), buffer_ptr.s.pool, 0);
    }
    else if(PKTBUF_IS_SW(mbuf))
    {
        MEM_2OR8K_FREE(mbuf->pkt_ptr);
    }
    else
    {
        printf("pkt buffer region error\n");
    }

    /*free mbuf*/
    MBUF_FREE(mbuf);
}


/*only free packet*/
void packet_destroy_data(mbuf_t *mbuf)
{
    cvmx_buf_ptr_t buffer_ptr;
    uint64_t start_of_buffer;

    /*free packet, find start of packet buffer*/
    if(PKTBUF_IS_HW(mbuf))
    {
        buffer_ptr = mbuf->packet_ptr;
        start_of_buffer = ((buffer_ptr.s.addr >> 7) - buffer_ptr.s.back) << 7;

        cvmx_fpa_free(cvmx_phys_to_ptr(start_of_buffer), buffer_ptr.s.pool, 0);
    }
}


void packet_destory_rawdata(cvmx_buf_ptr_t buffer_ptr)
{
    uint64_t start_of_buffer;

    start_of_buffer = ((buffer_ptr.s.addr >> 7) - buffer_ptr.s.back) << 7;

    cvmx_fpa_free(cvmx_phys_to_ptr(start_of_buffer), buffer_ptr.s.pool, 0);
}




uint32_t packet_hw2sw(mbuf_t *mbuf, uint32_t flag)
{
    void *pkt_buf_sw;
    void *pkt_buf_hw;
    cvmx_buf_ptr_t cvmx_buffer_ptr;

    if(PKTBUF_IS_SW(mbuf))
    {
        return SEC_OK;
    }

    if(SW2K_ZONE == flag)
    {
        pkt_buf_sw = MEM_2K_ALLOC(mbuf->pkt_totallen);
    }
    else
    {
        pkt_buf_sw = MEM_8K_ALLOC(mbuf->pkt_totallen);
    }

    if(NULL == pkt_buf_sw)
    {
        return SEC_NO;
    }
    pkt_buf_hw = mbuf->pkt_ptr;

    memcpy((void *)pkt_buf_sw, (void *)pkt_buf_hw, mbuf->pkt_totallen);

    cvmx_buffer_ptr.u64 = mbuf->packet_ptr.u64;

    /*need adjuest the mbuf from hw2sw*/
    PKTBUF_SET_SW(mbuf);

    mbuf->pkt_ptr = pkt_buf_sw;

    packet_header_ptr_adjust(mbuf, pkt_buf_hw, pkt_buf_sw);

    mbuf->packet_ptr.u64 = 0;

    packet_destory_rawdata(cvmx_buffer_ptr);

    return SEC_OK;
}


uint32_t packet_sw2hw(mbuf_t *mbuf)
{
    void *pkt_buf_sw;
    void *pkt_buf_hw;
    cvmx_buf_ptr_t cvmx_buffer_ptr;

    if(PKTBUF_IS_HW(mbuf))
    {
        return SEC_OK;
    }

    if(mbuf->pkt_totallen >= CVMX_FPA_PACKET_POOL_SIZE)
    {
        return SEC_NO;
    }

    /* Get a HW buffer */
    pkt_buf_hw = cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);
    if(NULL == pkt_buf_hw)
    {
        return SEC_NO;
    }

    memset(pkt_buf_hw, 0, CVMX_FPA_PACKET_POOL_SIZE);

    pkt_buf_sw = mbuf->pkt_ptr;

    memcpy((void *)pkt_buf_hw, (void *)pkt_buf_sw, mbuf->pkt_totallen);

    cvmx_buffer_ptr.u64 = 0;
    cvmx_buffer_ptr.u64 = cvmx_ptr_to_phys(pkt_buf_hw);

    /*need adjuest the mbuf from hw2sw*/
    PKTBUF_SET_HW(mbuf);

    mbuf->pkt_ptr = pkt_buf_hw;

    packet_header_ptr_adjust(mbuf, pkt_buf_sw, pkt_buf_hw);

    mbuf->packet_ptr.u64 = cvmx_buffer_ptr.u64;

    MEM_2OR8K_FREE(pkt_buf_sw);

    return SEC_OK;
}




