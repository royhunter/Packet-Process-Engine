#ifndef __STREAM_TCP_H__
#define __STREAM_TCP_H__

#include <decode-ipv4.h>
#include <decode-tcp.h>


#include "stream-tcp-private.h"
#include "stream-tcp-session.h"


#define STREAMTCP_OK       0
#define STREAMTCP_ERR      1
#define STREAMTCP_CACHE    2
#define STREAMTCP_REASM_BEFORE 3
#define STREAMTCP_REASM_OVERLAP 4


static inline void StreamTcpPacketSwitchDir(TcpSession *ssn, mbuf_t *m)
{
    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "ssn %p: switching pkt direction", ssn);

    if (PKT_IS_TOSERVER(m)) {
        m->flags &= ~PKT_TO_SERVER;
        m->flags |= PKT_TO_CLIENT;
    } else {
        m->flags &= ~PKT_TO_CLIENT;
        m->flags |= PKT_TO_SERVER;
    }
}


extern uint32_t stream_tcp_track_enable;
extern uint32_t stream_tcp_reasm_enable;

extern uint32_t StreamTcpPacket(mbuf_t *mbuf, mbuf_t **reasm_m);
extern int StreamTcp(mbuf_t *mbuf, mbuf_t **reasm_m);
extern uint32_t StreamTcpInit(void);


#endif
