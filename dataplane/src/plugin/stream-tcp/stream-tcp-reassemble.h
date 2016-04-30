#ifndef __STREAM_TCP_REASSEMBLE_H__
#define __STREAM_TCP_REASSEMBLE_H__


extern uint32_t StreamTcpReassembleHandleSegment(TcpSession *ssn, TcpStream *stream, mbuf_t *m, mbuf_t **reasm_m);
extern void StreamTcpReturnStreamSegments (TcpStream *stream);
#endif