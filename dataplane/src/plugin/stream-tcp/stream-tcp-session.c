#include "stream-tcp-session.h"
#include "stream-tcp-segment.h"
#include "output.h"
#include "dp_attack.h"

TcpSession *StreamTcp_Session_Alloc()
{
    void *buf = mem_pool_alloc(MEM_POOL_ID_STREAMTCP_SESSION_BUFFER, 0);
    if(NULL == buf)
        return NULL;

    return (TcpSession *)(buf);
}

void StreamTcp_Session_Free(void *psession)
{
    mem_pool_free(psession);
}



TcpSession *StreamTcpNewSession (mbuf_t *mbuf)
{
    TcpSession *ptcpsession = (TcpSession *)StreamTcp_Session_Alloc();
    if(NULL == ptcpsession)
        return NULL;

    ((flow_item_t *)(mbuf->flow))->protoctx = (void *)ptcpsession;

    ptcpsession->state = TCP_NONE;

    return ptcpsession;
}


void StreamTcp_Segment_RawPkt_Free(TcpSegment *seg)
{
    output_drop_proc(seg->mbuf);
}

void StreamTcp_Session_Segment_Release(TcpStream *stream)
{
    TcpSegment *seg = stream->seg_list;
    TcpSegment *next_seg;

    if (seg == NULL)
        return;

    while (seg != NULL) {
        next_seg = seg->next;
        StreamTcp_Segment_RawPkt_Free(seg);
        StreamTcp_Segment_Free((void *)seg);
        seg = next_seg;
    }

    stream->seg_list = NULL;
    stream->seg_list_tail = NULL;
}


void StreamTcp_Flow_ResRelease(flow_item_t *f)
{
    if(f->protoctx == NULL)
        return;

    TcpSession *ptcpsession = (TcpSession *)f->protoctx;

    if(ptcpsession->state <= TCP_SYN_RECV)
    {
        DP_Attack_SynCountFins_Byport(f->input_port);
    }

    StreamTcp_Session_Segment_Release(&ptcpsession->server);
    StreamTcp_Session_Segment_Release(&ptcpsession->client);

    StreamTcp_Session_Free(f->protoctx);
}





uint32_t StreamTcpSessionInit()
{
    Mem_Pool_Cfg *mpc = NULL;

    stream_tcp_session_size_judge();

    printf("stream tcp session pool init\n");
    mpc = (Mem_Pool_Cfg *)cvmx_bootmem_alloc_named(MEM_POOL_TOTAL_STREAMTCP_SESSION_BUFFER,
                                                    CACHE_LINE_SIZE,
                                                    MEM_POOL_NAME_STREAMTCP_SESSION_BUFFER);
    if(NULL == mpc)
        return SEC_NO;

    memset((void *)mpc, 0, sizeof(Mem_Pool_Cfg));

    mpc->slicesize = MEM_POOL_STREAM_TCP_SESSION_SIZE;
    mpc->slicenum = MEM_POOL_STREAM_TCP_SESSION_NUM;
    mpc->datasize = MEM_POOL_STREAM_TCP_SESSION_SIZE - MEM_POOL_SLICE_CTRL_SIZE;
    mpc->start = (uint8_t *)mpc + sizeof(Mem_Pool_Cfg);
    mpc->totalsize = MEM_POOL_STREAM_TCP_SESSION_NUM * MEM_POOL_STREAM_TCP_SESSION_SIZE;
    mem_pool[MEM_POOL_ID_STREAMTCP_SESSION_BUFFER] = mpc;

    if( SEC_NO == mem_pool_sw_slice_inject(MEM_POOL_ID_STREAMTCP_SESSION_BUFFER))
    {
        return SEC_NO;
    }


    stream_tcp_segment_size_judge();

    printf("stream tcp segment pool init\n");
    mpc = (Mem_Pool_Cfg *)cvmx_bootmem_alloc_named(MEM_POOL_TOTAL_STREAMTCP_SEGMENT_BUFFER,
                                                    CACHE_LINE_SIZE,
                                                    MEM_POOL_NAME_STREAMTCP_SEGMENT_BUFFER);
    if(NULL == mpc)
        return SEC_NO;

    memset((void *)mpc, 0, sizeof(Mem_Pool_Cfg));

    mpc->slicesize = MEM_POOL_STREAM_TCP_SEGMENT_SIZE;
    mpc->slicenum = MEM_POOL_STREAM_TCP_SEGMENT_NUM;
    mpc->datasize = MEM_POOL_STREAM_TCP_SEGMENT_SIZE - MEM_POOL_SLICE_CTRL_SIZE;
    mpc->start = (uint8_t *)mpc + sizeof(Mem_Pool_Cfg);
    mpc->totalsize = MEM_POOL_STREAM_TCP_SEGMENT_NUM * MEM_POOL_STREAM_TCP_SEGMENT_SIZE;
    mem_pool[MEM_POOL_ID_STREAMTCP_SEGMENT_BUFFER] = mpc;

    if( SEC_NO == mem_pool_sw_slice_inject(MEM_POOL_ID_STREAMTCP_SEGMENT_BUFFER))
    {
        return SEC_NO;
    }

    return SEC_OK;
}

void StreamTcpSessionRelease()
{
    int rc;
    rc = cvmx_bootmem_free_named(MEM_POOL_NAME_STREAMTCP_SESSION_BUFFER);
    printf("%s free rc=%d\n", MEM_POOL_NAME_STREAMTCP_SESSION_BUFFER, rc);

    rc = cvmx_bootmem_free_named(MEM_POOL_NAME_STREAMTCP_SEGMENT_BUFFER);
    printf("%s free rc=%d\n", MEM_POOL_NAME_STREAMTCP_SEGMENT_BUFFER, rc);

}



