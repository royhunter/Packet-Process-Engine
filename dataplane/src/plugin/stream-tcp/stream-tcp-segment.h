#ifndef __STREAM_TCP_SEGMENT_H__
#define __STREAM_TCP_SEGMENT_H__


#include <mem_pool.h>
#include "stream-tcp-private.h"




#define STREAM_TCP_REASSEMBLE_PACKET_MAX_LEN   8192-128


static inline void stream_tcp_segment_size_judge(void)
{
    BUILD_BUG_ON((sizeof(TcpSegment) + sizeof(Mem_Slice_Ctrl_B)) > MEM_POOL_STREAM_TCP_SESSION_SIZE);

    return;
}


extern TcpSegment *StreamTcpNewSegment();
extern void StreamTcp_Segment_Free(void *pbuf);


#endif