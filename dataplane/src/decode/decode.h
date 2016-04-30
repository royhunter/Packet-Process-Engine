#ifndef __DECODE_H__
#define __DECODE_H__

#include <sec-common.h>


#define DECODE_OK   0
#define DECODE_DROP 1
#define DECODE_DONE 2


#define PKT_IP_FRAG                     (1<<1)
#define PKT_FIRST_FRAG                  (1<<2)
#define PKT_FRAG_REASM_COMP             (1<<3)
#define PKT_TO_SERVER                   (1<<4)
#define PKT_TO_CLIENT                   (1<<5)
#define PKT_HAS_WS                      (1<<6)
#define PKT_HAS_STREAMTCP_REASM         (1<<7) // flag of reasm packet, means mbuf->tcp_seg_raw_next has raw packet
#define PKT_HAS_FLOW                    (1<<8)
#define PKT_HAS_REASM_BEFORE            (1<<9)
#define PKT_HAS_REASM_OVERLAP            (1<<10)



#define PKT_SET_IP_FRAG(m) (m->flags |= PKT_IP_FRAG)
#define PKT_CLEAR_IP_FRAG(m) (m->flags &= ~PKT_IP_FRAG)
#define PKT_IS_IP_FRAG(m) (m->flags & PKT_IP_FRAG)

#define PKT_SET_FIRST_FRAG(m) (m->flags |= PKT_FIRST_FRAG)
#define PKT_CLEAR_FIRST_FRAG(m) (m->flags &= ~PKT_FIRST_FRAG)
#define PKT_IS_FIRST_FRAG(m) (m->flags & PKT_FIRST_FRAG)


#define PKT_SET_IP_FRAG_COMP(m)   (m->flags |= PKT_FRAG_REASM_COMP)
#define PKT_CLEAR_IP_FRAG_COMP(m) (m->flags &= ~PKT_FRAG_REASM_COMP)
#define PKT_IS_IP_FRAG_COMP(m)    (m->flags & PKT_FRAG_REASM_COMP)

#define PKT_SET_STREAMTCP_REASM(m) (m->flags |= PKT_HAS_STREAMTCP_REASM)
#define PKT_CLEAR_STREAMTCP_REASM(m) (m->flags &= ~PKT_HAS_STREAMTCP_REASM)
#define PKT_IS_STREAMTCP_REASM(m) (m->flags & PKT_HAS_STREAMTCP_REASM)

#define PKT_SET_REASM_BEFORE(m)  (m->flags |= PKT_HAS_REASM_BEFORE)
#define PKT_CLEAR_REASM_BEFORE(m) (m->flags &= ~PKT_HAS_REASM_BEFORE)
#define PKT_IS_REASM_BEFORE(m) (m->flags & PKT_HAS_REASM_BEFORE)

#define PKT_SET_REASM_OVERLAP(m) (m->flags |= PKT_HAS_REASM_OVERLAP)
#define PKT_CLEAR_REASM_OVERLAP(m) (m->flags &= ~PKT_HAS_REASM_OVERLAP)
#define PKT_IS_REASM_OVERLAP(m) (m->flags & PKT_HAS_REASM_OVERLAP)



#define GET_PKT_LEN(p)   ((p)->pkt_totallen)
#define GET_PKT_DATA(p)  ((p)->pkt_ptr)


/*Given a packet pkt offset to the start of the ip header in a packet
 *We determine the ip version. */
#define IP_GET_RAW_VER(pkt) ((((pkt)[0] & 0xf0) >> 4))


#define PKT_IS_TOSERVER(p)  (((p)->flags & PKT_TO_SERVER))
#define PKT_IS_TOCLIENT(p)  (((p)->flags & PKT_TO_CLIENT))



#define CMP_ADDR(a1, a2) \
    ((a1) == (a2))



#define CMP_PORT(p1, p2) \
    ((p1) == (p2))






#endif
