#include "stream-tcp-segment.h"


TcpSegment *StreamTcp_Segment_Alloc()
{
    void *buf = mem_pool_alloc(MEM_POOL_ID_STREAMTCP_SEGMENT_BUFFER, 0);
    if(NULL == buf)
        return NULL;

    return (TcpSegment *)(buf);
}


void StreamTcp_Segment_Free(void *pbuf)
{
    mem_pool_free(pbuf);
}


TcpSegment *StreamTcpNewSegment ()
{
    return StreamTcp_Segment_Alloc();
}


