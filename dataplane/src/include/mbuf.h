#ifndef __MBUF_H__
#define __MBUF_H__

#include <oct-common.h>
#include <sec-common.h>
#include <sec-util.h>
#include <mem_pool.h>

#include <decode-tcp.h>



typedef void (*FreeAlState)(void *s);

typedef struct {
    uint32_t sip;
    uint32_t dip;
}ipv4_tuple_t;


/*packet info description
 */
typedef struct m_buf_
{
    uint32_t magic_flag;         //mbuf memory magic num

    uint8_t pkt_space;          //pkt is hw or sw buffer
    uint8_t flow_log;
    uint16_t frag_len;                //len of ip fragment packet


    cvmx_buf_ptr_t packet_ptr;   //copy from wqe packet_ptr, packet info

    struct m_buf_ *next;         //for cache frag chain

    void *pkt_ptr;               //pointer to begin of packet from wqe packet_ptr

    void *ethh;                  //l2 layer header
    void *vlanh;
    void *network_header;        //network layer header
    void *transport_header;      //transport layer header

    uint32_t input_port;         //input port of interface

    uint8_t eth_dst[6];          //DMAC
    uint8_t eth_src[6];          //SMAC

    ipv4_tuple_t ipv4;           //sip + dip

    uint16_t  sport;             //sport
    uint16_t  dport;             //dport

    uint8_t proto;               //protocol , now only support TCP + UDP
    uint8_t vlan_idx;            //if vlan exist, set vlan_idx = 1
    uint16_t payload_len;        //L7 payload_len

    uint16_t vlan_id;            //if vlan_idx support, vlan_id
    uint16_t defrag_id;

    uint64_t timestamp;          //seconds since 1970
    void *payload;               //L7 payload pointer

    union {
        TCPVars tcpvars;
    };

    uint16_t frag_offset;             //offset of ip fragment packet
    uint16_t tcp_reasm_overlap;
    uint32_t pkt_totallen;       //pkt total len

    uint32_t flags;              //features of packet
    uint32_t fcb_hash;

    void    *fcb;                //if frag_reasm   pointer to fcb
    struct m_buf_  *fragments;          //if frag_reasm ok, linked to fragments
    void    *flow;               //flow node

    struct m_buf_  *tcp_seg_raw;
    struct m_buf_  *tcp_seg_raw_tail;    //if seg_reassem   pointer to raw packet

    struct m_buf_  *tcp_seg_reassem;

    void   *alState;			//L7 state data
    FreeAlState FreeState;		//L7 free alState's memory

    uint32_t tag;
}mbuf_t;


#define MBUF_MAGIC_NUM 0xab00ab00


#define PKTBUF_HW    1
#define PKTBUF_SW    2

#define PKTBUF_IS_HW(m) (PKTBUF_HW == m->pkt_space)
#define PKTBUF_IS_SW(m) (PKTBUF_SW == m->pkt_space)

#define PKTBUF_SET_HW(m) (m->pkt_space = PKTBUF_HW)
#define PKTBUF_SET_SW(m) (m->pkt_space = PKTBUF_SW)

#define PKTBUF_SPACE_GET(m) (m->pkt_space)


static inline void mbuf_size_judge(void)
{
    BUILD_BUG_ON((sizeof(mbuf_t) + sizeof(Mem_Slice_Ctrl_B)) > MEM_POOL_HOST_MBUF_SIZE);

    return;
}

static inline void packet_header_ptr_adjust(mbuf_t *mb, void *old_pkt, void *new_pkt)
{
    void *oldethh;
    void *vlanh;
    void *networkh;
    void *transporth;
    void *payload;

    if(NULL != mb->ethh)
    {
        oldethh = mb->ethh;
        mb->ethh = (void *)((uint8_t *)new_pkt + ((uint64_t)oldethh - (uint64_t)old_pkt));
    }

    if(mb->vlan_idx)
    {
        vlanh = mb->vlanh;
        mb->vlanh = (void *)((uint8_t *)new_pkt + ((uint64_t)vlanh - (uint64_t)old_pkt));
    }

    if(NULL != mb->network_header)
    {
        networkh = mb->network_header;
        mb->network_header = (void *)((uint8_t *)new_pkt + ((uint64_t)networkh - (uint64_t)old_pkt));
    }

    if(NULL != mb->transport_header)
    {
        transporth = mb->transport_header;
        mb->transport_header = (void *)((uint8_t *)new_pkt + ((uint64_t)transporth - (uint64_t)old_pkt));
    }

    if(NULL != mb->payload)
    {
        payload = mb->payload;
        mb->payload = (void *)((uint8_t *)new_pkt + ((uint64_t)payload - (uint64_t)old_pkt));
    }

}


extern mbuf_t *mbuf_alloc();
extern void mbuf_free(mbuf_t *mb);
extern void packet_destroy_all(mbuf_t *m);
extern void packet_destroy_data(mbuf_t *mbuf);
extern uint32_t packet_hw2sw(mbuf_t *mbuf, uint32_t flag);
extern uint32_t packet_sw2hw(mbuf_t *mbuf);


#define SW2K_ZONE    0
#define SW8K_ZONE    1

#define MBUF_ALLOC()  mbuf_alloc()
#define MBUF_FREE(m)   mbuf_free(m)


#define PACKET_DESTROY_ALL(m)   packet_destroy_all(m)
#define PACKET_DESTROY_DATA(m)  packet_destroy_data(m)

#define PACKET_HW2SW(m, flag) packet_hw2sw(m, flag)



#endif
