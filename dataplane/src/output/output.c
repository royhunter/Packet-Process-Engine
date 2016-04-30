#include "sec-common.h"
#include "mbuf.h"
#include "decode.h"
#include "oct-rxtx.h"
#include "decode-defrag.h"
#include "output.h"
#include "decode-statistic.h"



static inline int output_routing(mbuf_t *m)
{
    uint8_t inport, outport;

    inport = m->input_port;

    if(inport > OCT_PHY_PORT_MAX)
    {
        return -1;
    }

    outport = oct_tx_port_get(inport);

    return outport;
}



void output_fw_hwzone_proc(mbuf_t *m)
{
    int outport;
    outport = output_routing(m);
    if(outport < 0)
    {
        PACKET_DESTROY_ALL(m);
    }
    else
    {
        oct_tx_process_hw(m, outport);
    }
}


void output_fw_ipfrag_proc(mbuf_t *m)
{
    mbuf_t *head;
    mbuf_t *next;
    head = m->fragments;
    while(head)
    {
        next = head->next;
        output_fw_proc(head);
        head = next;
    }

    PKT_CLEAR_IP_FRAG_COMP(m);

    PACKET_DESTROY_ALL(m);
}

void output_fw_tcpseg_proc(mbuf_t *m)
{
    mbuf_t *head = m->tcp_seg_raw;
    mbuf_t *next = NULL;
    for( ; head != NULL; head = next)
    {
        next = head->tcp_seg_raw;
        head->tcp_seg_raw = NULL;
        output_fw_proc(head);
    }
    PKT_CLEAR_STREAMTCP_REASM(m);

    PACKET_DESTROY_ALL(m);
}



void output_fw_swzone_proc(mbuf_t *m)
{
    if(PKT_IS_STREAMTCP_REASM(m))
    {
        output_fw_tcpseg_proc(m);
    }
    else if(PKT_IS_IP_FRAG_COMP(m))
    {
        output_fw_ipfrag_proc(m);
    }
    else
    {
        int outport;
        outport = output_routing(m);
        if(outport < 0)
        {
            PACKET_DESTROY_ALL(m);
        }
        else
        {
            oct_tx_process_sw(m, outport);
        }
    }
}




void output_fw_proc(mbuf_t *m)
{
    if(PKTBUF_IS_HW(m))
    {
        output_fw_hwzone_proc(m);
    }
    else if(PKTBUF_IS_SW(m))
    {
        output_fw_swzone_proc(m);
    }
    else
    {
        printf("pkt space %d is wrong, please check it\n", PKTBUF_SPACE_GET(m));
    }
}

static inline void output_drop_frag(mbuf_t *m)
{
    mbuf_t *head;
    mbuf_t *next;
    head = m->fragments;
    while(head)
    {
        next = head->next;
        PACKET_DESTROY_ALL(head);
        head = next;
    }

    PKT_CLEAR_IP_FRAG_COMP(m);
}

static inline void output_drop_streamtcp_seg(mbuf_t *m)
{
    mbuf_t *head = m->tcp_seg_raw;
    mbuf_t *next = NULL;
    for( ; head != NULL; head = next)
    {
        next = head->tcp_seg_raw;
        PACKET_DESTROY_ALL(head);
    }
    PKT_CLEAR_STREAMTCP_REASM(m);
}



void output_drop_proc(mbuf_t *m)
{
    if(PKTBUF_IS_HW(m))
    {
        PACKET_DESTROY_ALL(m);
    }
    else  if(PKTBUF_IS_SW(m))
    {
        if(PKT_IS_IP_FRAG_COMP(m))//free ip fragments
        {
            output_drop_frag(m);
        }
        else if(PKT_IS_STREAMTCP_REASM(m))//free tcp segments
        {
            output_drop_streamtcp_seg(m);
        }

        PACKET_DESTROY_ALL(m);
    }
}



void output_l7_follow_proc(mbuf_t *m, uint32_t action)
{
    if(SEC_DROP == action)
    {
        STAT_OUTPUT_DROP;
        output_drop_proc(m);
        return;
    }
    else if(SEC_FW == action)
    {
        STAT_OUTPUT_FW;
        output_fw_proc(m);
        return;
    }
    else if(SEC_CACHE == action)
    {
        STAT_OUTPUT_CACHE;
        return;
    }
    else
    {
        STAT_OUTPUT_UNSUPPORT;
        printf("unsupport action follow l7 %d\n", action);
    }

    return;
}







mbuf_t *MBUF_CREATE(uint32_t size)
{
    mbuf_t *new_mb = NULL;
    void *packet_buffer = NULL;

    new_mb = MBUF_ALLOC();
    if(NULL == new_mb)
    {
        return NULL;
    }

    if(size < 1600)
    {
        packet_buffer = MEM_2K_ALLOC(1000);
    }
    else if (size < 7500)
    {
        packet_buffer = MEM_8K_ALLOC(1000);
    }
    else
    {
        packet_buffer = NULL;
    }

    if(NULL == packet_buffer)
    {
        MBUF_FREE(new_mb);
        return NULL;
    }

    memset((void *)new_mb, 0, sizeof(mbuf_t));

    PKTBUF_SET_SW(new_mb);
    new_mb->pkt_ptr = packet_buffer;
    new_mb->pkt_totallen = size;

    new_mb->magic_flag = MBUF_MAGIC_NUM;

    return new_mb;
}







