#ifndef __STREAM_TCP_SESSION_H__
#define __STREAM_TCP_SESSION_H__


#include <mbuf.h>
#include "flow.h"
#include <mem_pool.h>
#include "stream-tcp-private.h"







static inline void stream_tcp_session_size_judge(void)
{
    BUILD_BUG_ON((sizeof(TcpSession) + sizeof(Mem_Slice_Ctrl_B)) > MEM_POOL_STREAM_TCP_SESSION_SIZE);

    return;
}




extern TcpSession *StreamTcpNewSession (mbuf_t *mbuf);
extern uint32_t StreamTcpSessionInit();
extern void StreamTcp_Flow_ResRelease(flow_item_t *f);
extern void StreamTcpSessionRelease();


#endif
