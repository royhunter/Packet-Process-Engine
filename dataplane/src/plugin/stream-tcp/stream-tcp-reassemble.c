#include "sec-common.h"
#include <mbuf.h>
#include "stream-tcp.h"
#include "stream-tcp-segment.h"
#include "stream-tcp-reassemble.h"
#include "output.h"
#include "decode-statistic.h"



static inline void StreamTcpReassembleAddRawMbuf(mbuf_t *reasm_m, mbuf_t *raw)
{
    if(reasm_m->tcp_seg_raw == NULL)
    {
        reasm_m->tcp_seg_raw = raw;
        reasm_m->tcp_seg_raw_tail = raw;
    }
    else
    {
        reasm_m->tcp_seg_raw_tail->tcp_seg_raw = raw;
        reasm_m->tcp_seg_raw_tail = raw;
    }
}


/**
 *  \internal
 *  \brief Get the active ra_base_seq, considering stream gaps
 *
 *  \retval seq the active ra_base_seq
 */
static inline uint32_t StreamTcpReassembleGetRaBaseSeq(TcpStream *stream)
{
    return stream->ra_app_base_seq;
}



/**
 *  \brief return all segments in this stream into the pool(s)
 *
 *  \param stream the stream to cleanup
 */
void StreamTcpReturnStreamSegments (TcpStream *stream)
{
    TcpSegment *seg = stream->seg_list;
    TcpSegment *next_seg;

    if (seg == NULL)
        return;

    while (seg != NULL) {
        next_seg = seg->next;
        output_drop_proc(seg->mbuf);
        StreamTcp_Segment_Free((void *)seg);
        seg = next_seg;
    }

    stream->seg_list = NULL;
    stream->seg_list_tail = NULL;
    return;
}


uint32_t StreamTcpReassembleInsertSegment(TcpStream *stream, TcpSegment *seg)
{
    TcpSegment *list_seg = stream->seg_list;
    TcpSegment *next_list_seg = NULL;

    LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nSEQ %"PRIu32", SEQ+payload %"PRIu32", last_ack %"PRIu32", "
            "ra_app_base_seq %"PRIu32, TCP_GET_SEQ(seg->mbuf), (TCP_GET_SEQ(seg->mbuf) + seg->mbuf->payload_len),
            stream->last_ack, stream->ra_app_base_seq);

    /* fast track */
    if (list_seg == NULL) {
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nempty list, inserting seg %p seq %" PRIu32 ", "
                   "len %" PRIu32 "", seg, seg->seq, seg->payload_len);
        stream->seg_list = seg;
        seg->prev = NULL;
        stream->seg_list_tail = seg;

        return STREAMTCP_CACHE;
    }

    /* insert the segment in the stream list using this fast track, if seg->seq
        * is equal or higher than stream->seg_list_tail.*/
    if (SEQ_GEQ(seg->seq,stream->seg_list_tail->seq))
    {
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nadd seg_list tail\n");
        stream->seg_list_tail->next = seg;
        seg->prev = stream->seg_list_tail;
        stream->seg_list_tail = seg;

        return STREAMTCP_CACHE;
    }

    for (; list_seg != NULL; list_seg = next_list_seg) {
        next_list_seg = list_seg->next;

        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nseg %p, list_seg %p, list_prev %p list_seg->next %p, "
                   "segment length %" PRIu32 "", seg, list_seg, list_seg->prev,
                   list_seg->next, seg->payload_len);
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nseg->seq %"PRIu32", list_seg->seq %"PRIu32"",
                   seg->seq, list_seg->seq);

        if( seg->seq <= list_seg->seq )
        {
            if(NULL == list_seg->prev)
            {
                stream->seg_list = seg;
                seg->next = list_seg;
                list_seg->prev = seg;
            }
            else
            {
                seg->prev = list_seg->prev;
                list_seg->prev->next = seg;
                seg->next =list_seg;
                list_seg->prev = seg;
            }
            return STREAMTCP_CACHE;
        }
    }

    return STREAMTCP_CACHE;
}


static uint32_t StreamTcpReassmbleCache(TcpStream *stream, mbuf_t *m)
{
    TcpSegment *seg = NULL;

    seg = StreamTcpNewSegment();
    if(NULL == seg)
    {
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nStreamTcpNewSegment error %s, %d", __FILE__, __LINE__);
        STREAMTCP_REASM_SEG_NO_MEM;
        return STREAMTCP_ERR;
    }

    if(SEC_OK != PACKET_HW2SW(m, SW2K_ZONE))
    {
        StreamTcp_Segment_Free((void *)seg);
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nPACKET_HW2SW error %s, %d", __FILE__, __LINE__);
        STREAMTCP_REASM_HW2SW_ERR;
        return STREAMTCP_ERR;
    }

    memset((void *)seg, 0, sizeof(TcpSegment));

    seg->mbuf = m;
    seg->payload_len = m->payload_len;
    seg->seq = TCP_GET_SEQ(m);

    STREAMTCP_REASM_CACHE;
    return StreamTcpReassembleInsertSegment(stream, seg);
}

mbuf_t *StreamTcpReassamble_Setup(mbuf_t *head)
{
    mbuf_t *new_mb;
    void *packet_buffer;

    new_mb = MBUF_ALLOC();
    if(NULL == new_mb)
    {
        return NULL;
    }

    packet_buffer = MEM_8K_ALLOC(STREAM_TCP_REASSEMBLE_PACKET_MAX_LEN);
    if(NULL == packet_buffer)
    {
        MBUF_FREE(new_mb);
        return NULL;
    }

    memset((void *)new_mb, 0, sizeof(mbuf_t));

    PKTBUF_SET_SW(new_mb);
    new_mb->pkt_ptr = packet_buffer;

    new_mb->ethh = head->ethh;
    new_mb->vlan_idx = head->vlan_idx;
    new_mb->vlan_id = head->vlan_id;
    new_mb->network_header = head->network_header;
    new_mb->transport_header = head->transport_header;
    new_mb->payload = head->payload;
    new_mb->payload_len = head->payload_len;
    new_mb->flow = head->flow;

    memcpy((void *)new_mb->pkt_ptr, (void *)head->pkt_ptr, head->pkt_totallen);

    packet_header_ptr_adjust(new_mb, head->pkt_ptr, packet_buffer);

    new_mb->magic_flag = MBUF_MAGIC_NUM;
    //new_mb->input_port = head->input_port;

    memcpy((void *)new_mb->eth_dst, (void *)head->eth_dst, sizeof(new_mb->eth_dst));
    memcpy((void *)new_mb->eth_src, (void *)head->eth_src, sizeof(new_mb->eth_src));

    new_mb->ipv4.sip = head->ipv4.sip;
    new_mb->ipv4.dip = head->ipv4.dip;

    new_mb->sport = head->sport;
    new_mb->dport = head->dport;

    new_mb->proto = head->proto;

    PKT_SET_STREAMTCP_REASM(new_mb);

    return new_mb;
}


uint32_t StreamTcpReassmble(TcpStream *stream, mbuf_t *m, mbuf_t **reasm_m)
{
    TcpSegment *list_seg = stream->seg_list;
    TcpSegment *next_list_seg = NULL;
    mbuf_t *reasm_mb_head = NULL;
    mbuf_t *reasm_mb_tail = NULL;
    mbuf_t *reasm_mb = NULL;

    LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\n================>StreamTcpReassmble()");

    uint32_t ra_base_seq = StreamTcpReassembleGetRaBaseSeq(stream);

    LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nlist_seg's seq is %u", list_seg->seq);

    if((TCP_GET_SEQ(m) + m->payload_len) < list_seg->seq)//have a gap
    {
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\npacket have a gap with list_seg");
        if(SEQ_EQ(TCP_GET_SEQ(m), ra_base_seq))//eq
        {
            LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\npacket seq eq ra_base, direct deliver and add ra_base");
            STREAMTCP_SET_RA_BASE_SEQ(stream, ( TCP_GET_SEQ(m) + m->payload_len ));
            LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nnow ra base is %u", StreamTcpReassembleGetRaBaseSeq(stream));
            *reasm_m = m;
            STREAMTCP_REASM_NO_NEED_REASM;
            return STREAMTCP_OK;
        }
        else//overlap
        {
            LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\npacket seq overlap with ra_base");
        #if 0
            reasm_mb = StreamTcpReassamble_Setup(m);
            if(NULL == reasm_mb)
            {
                STREAMTCP_REASM_SETUP_FAIL;
                return STREAMTCP_ERR;
            }

            uint8_t *src = (uint8_t *)reasm_mb->payload + ra_base_seq - TCP_GET_SEQ(m);
            uint8_t *dst = (uint8_t *)reasm_mb->payload;
            uint32_t len = TCP_GET_SEQ(m) + m->payload_len - ra_base_seq;
            memcpy((void *)dst, (void *)src, len);
            TCP_SET_SEQ(reasm_mb, ra_base_seq);
            reasm_mb->payload_len = len;

            StreamTcpReassembleAddRawMbuf(reasm_mb, m);
            STREAMTCP_SET_RA_BASE_SEQ(stream, (TCP_GET_SEQ(m) + m->payload_len));
            LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\now : ra_base is %u", StreamTcpReassembleGetRaBaseSeq(stream));
            *reasm_m = reasm_mb;
            STREAMTCP_REASM_OK;
            return STREAMTCP_OK;
        #endif
            m->tcp_reasm_overlap = TCP_GET_SEQ(m) + m->payload_len - ra_base_seq;
            STREAMTCP_SET_RA_BASE_SEQ(stream, (TCP_GET_SEQ(m) + m->payload_len));
            LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nnow: ra_base_seq is %u", StreamTcpReassembleGetRaBaseSeq(stream));
            *reasm_m = m;
            STREAMTCP_REASM_REASM_OVERLAP;
            return STREAMTCP_REASM_OVERLAP;
        }
    }
    else//no gap, need reassemble
    {
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\npacket seq is %u, payload_len is %d, ra_base is %u\n",
            TCP_GET_SEQ(m), m->payload_len, ra_base_seq);

        reasm_mb = StreamTcpReassamble_Setup(m);
        if(NULL == reasm_mb)
        {
            STREAMTCP_REASM_SETUP_FAIL;
            return STREAMTCP_ERR;
        }

        if(SEC_OK != PACKET_HW2SW(m, SW2K_ZONE))
        {
            output_drop_proc(reasm_mb);
            STREAMTCP_REASM_HW2SW_ERR;
            return STREAMTCP_ERR;
        }

        if(SEQ_EQ(TCP_GET_SEQ(m), ra_base_seq))//eq
        {
            TCP_SET_SEQ(reasm_mb, TCP_GET_SEQ(m));
        }
        else//overlap
        {
            /*adjust*/
        #if 0
            uint8_t *src = (uint8_t *)reasm_mb->payload + ra_base_seq - TCP_GET_SEQ(m);
            uint8_t *dst = (uint8_t *)reasm_mb->payload;
            uint32_t len = TCP_GET_SEQ(m) + m->payload_len - ra_base_seq;
            memcpy((void *)dst, (void *)src, len);
            TCP_SET_SEQ(reasm_mb, ra_base_seq);
            reasm_mb->payload_len = len;
        #endif
            TCP_SET_SEQ(reasm_mb, TCP_GET_SEQ(m));
            reasm_mb->tcp_reasm_overlap = TCP_GET_SEQ(m) + m->payload_len - ra_base_seq;
        }

        STREAMTCP_SET_RA_BASE_SEQ(stream, (TCP_GET_SEQ(m) + m->payload_len));

        StreamTcpReassembleAddRawMbuf(reasm_mb, m);

        reasm_mb_head = reasm_mb;
        reasm_mb_tail = reasm_mb;

        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\npacket seq is %u, payload_len is %d, ra_base is %u\n",
            TCP_GET_SEQ(reasm_mb), reasm_mb->payload_len, StreamTcpReassembleGetRaBaseSeq(stream));
    }

    for (; list_seg != NULL; list_seg = next_list_seg) {
        next_list_seg = list_seg->next;

        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nreasm_mb seq is %u, payload_len is %d, ra_base is %u\n",
            TCP_GET_SEQ(reasm_mb), reasm_mb->payload_len, StreamTcpReassembleGetRaBaseSeq(stream));

        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nlist_seg seq is %u, payload_len is %d\n",
            TCP_GET_SEQ(list_seg->mbuf), list_seg->mbuf->payload_len);

        if((TCP_GET_SEQ(reasm_mb) + reasm_mb->payload_len) == list_seg->seq) //follow
        {
            uint32_t src_len = list_seg->payload_len;
            uint32_t reasm_packet_head_len = (uint64_t)reasm_mb->payload - (uint64_t)reasm_mb->pkt_ptr;
            if( reasm_packet_head_len + reasm_mb->payload_len + src_len > STREAM_TCP_REASSEMBLE_PACKET_MAX_LEN)
            {//no free space to reassemble, need a new buffer
                reasm_mb = StreamTcpReassamble_Setup(list_seg->mbuf);
                if(NULL == reasm_mb)
                {
                    *reasm_m = reasm_mb_head;
                    STREAMTCP_REASM_SETUP_FAIL;
                    return STREAMTCP_OK;
                }
                TCP_SET_SEQ(reasm_mb, TCP_GET_SEQ(list_seg->mbuf));

                if(reasm_mb_head == NULL)
                {
                    reasm_mb_head = reasm_mb;
                    reasm_mb_tail = reasm_mb;
                }
                else
                {
                    reasm_mb_tail->tcp_seg_reassem = reasm_mb;
                    reasm_mb_tail = reasm_mb;
                }
            }
            else//have free space
            {
                uint8_t *dst = ((uint8_t *)reasm_mb->payload) + reasm_mb->payload_len;
                uint8_t *src = ((uint8_t *)list_seg->mbuf->payload);
                uint32_t len = list_seg->mbuf->payload_len;
                memcpy((void *)dst, (void *)src, len);
                reasm_mb->payload_len += len;
            }

            StreamTcpReassembleAddRawMbuf(reasm_mb, list_seg->mbuf);

            STREAMTCP_SET_RA_BASE_SEQ(stream, (list_seg->seq + list_seg->payload_len));

            stream->seg_list = next_list_seg;
            if(next_list_seg == NULL)
                stream->seg_list_tail = NULL;

            StreamTcp_Segment_Free((void *)list_seg);
        }
        else if((TCP_GET_SEQ(reasm_mb) + reasm_mb->payload_len) > list_seg->seq)
        {
            if((TCP_GET_SEQ(reasm_mb) + reasm_mb->payload_len) >= (list_seg->seq + list_seg->payload_len))
            {//cover it, no need to reassemble
                StreamTcpReassembleAddRawMbuf(reasm_mb, list_seg->mbuf);

                stream->seg_list = next_list_seg;
                if(next_list_seg == NULL)
                    stream->seg_list_tail = NULL;

                StreamTcp_Segment_Free(list_seg);
            }
            else//have a overlap
            {
                uint32_t overlap_len =  (TCP_GET_SEQ(reasm_mb) + reasm_mb->payload_len) - list_seg->seq;
                uint32_t src_len = (list_seg->seq + list_seg->payload_len) - (TCP_GET_SEQ(reasm_mb) + reasm_mb->payload_len);
                uint32_t reasm_packet_head_len = (uint64_t)reasm_mb->payload - (uint64_t)reasm_mb->pkt_ptr;
                if( reasm_packet_head_len + reasm_mb->payload_len + src_len > STREAM_TCP_REASSEMBLE_PACKET_MAX_LEN)
                {//no free space to reassemble, need a new buffer
                    reasm_mb = StreamTcpReassamble_Setup(list_seg->mbuf);
                    if(NULL == reasm_mb)
                    {
                        *reasm_m = reasm_mb_head;
                        STREAMTCP_REASM_SETUP_FAIL;
                        return STREAMTCP_OK;
                    }
                    //adjust
                    uint8_t *dst = (uint8_t *)reasm_mb->payload;
                    uint8_t *src = dst + (uint32_t)list_seg->mbuf->payload_len - src_len;
                    uint32_t len = src_len;
                    memcpy((void *)dst, (void *)src, len);
                    reasm_mb->payload_len = len;
                    TCP_SET_SEQ(reasm_mb, list_seg->seq + overlap_len);

                    if(reasm_mb_head == NULL)
                    {
                        reasm_mb_head = reasm_mb;
                        reasm_mb_tail = reasm_mb;
                    }
                    else
                    {
                        reasm_mb_tail->tcp_seg_reassem = reasm_mb;
                        reasm_mb_tail = reasm_mb;
                    }
                }
                else//have free space
                {
                    uint8_t *dst = ((uint8_t *)reasm_mb->payload) + reasm_mb->payload_len;
                    uint8_t *src = ((uint8_t *)list_seg->mbuf->payload) + (list_seg->seq + list_seg->payload_len) - (TCP_GET_SEQ(reasm_mb) + reasm_mb->payload_len);
                    uint32_t len = src_len;
                    memcpy((void *)dst, (void *)src, len);
                    reasm_mb->payload_len += len;
                }

                StreamTcpReassembleAddRawMbuf(reasm_mb, list_seg->mbuf);

                STREAMTCP_SET_RA_BASE_SEQ(stream, (list_seg->seq + list_seg->payload_len));

                stream->seg_list = next_list_seg;
                if(next_list_seg == NULL)
                    stream->seg_list_tail = NULL;

                StreamTcp_Segment_Free(list_seg);
            }
        }
        else if((TCP_GET_SEQ(reasm_mb) + reasm_mb->payload_len) < list_seg->seq)
        {//have a gap, no need to reassemble
            *reasm_m = reasm_mb_head;
            STREAMTCP_REASM_OK;
            return STREAMTCP_OK;
        }
    }

    LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nnow: ra_base is %u\n", StreamTcpReassembleGetRaBaseSeq(stream));

    *reasm_m = reasm_mb_head;
    STREAMTCP_REASM_OK;
    return STREAMTCP_OK;
}


uint32_t StreamTcpReassembleHandleSegment(TcpSession *ssn, TcpStream *stream, mbuf_t *m, mbuf_t **reasm_m)
{
    if(!stream_tcp_reasm_enable)
    {
        *reasm_m = m;
        return STREAMTCP_OK;
    }

    LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\n=====>StreamTcpReassembleHandleSegment");

    if(PKT_IS_TOSERVER(m))
    {
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\npkt is client------>server");
    }
    else
    {
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\npkt is server------>client");
    }

    LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nssn %p, stream %p, p %p, p->payload_len %"PRIu16"",
                ssn, stream, m, m->payload_len);

    uint32_t ra_base_seq = StreamTcpReassembleGetRaBaseSeq(stream);
    LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nra_base_seq is %u", ra_base_seq);
    LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\npacket seq is %u", TCP_GET_SEQ(m));
    LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\npacket payload_len is %d", m->payload_len);

    if(m->payload_len == 0) // payload is zero, no need to reassemble, return raw packet
    {
        *reasm_m = m;
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nseq is %u, payload is zero, no need reasm, direct deliver", TCP_GET_SEQ(m));
        return STREAMTCP_OK;
    }

    /* before our ra_app_base_seq we don't insert it in our list */
    if(SEQ_LEQ((TCP_GET_SEQ(m) + m->payload_len), ra_base_seq)) //TCP_GET_SEQ(m) + m->payload_len <= ra_base_seq
    {
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nnot inserting: SEQ+payload %"PRIu32", last_ack %"PRIu32", "
                "ra_(app|raw)_base_seq %"PRIu32, (TCP_GET_SEQ(m) + m->payload_len),
                stream->last_ack, StreamTcpReassembleGetRaBaseSeq(stream));
        STREAMTCP_REASM_BEFORE_RA_BASE;
        *reasm_m = m;
        return STREAMTCP_REASM_BEFORE;
    }

    if (SEQ_GT(TCP_GET_SEQ(m), ra_base_seq)) { // may out of order   TCP_GET_SEQ(m) > ra_base_seq
        LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nseq big than ra_base, out of order, need cache");
        return StreamTcpReassmbleCache(stream, m);
    }

    /* if the segment ends beyond ra_base_seq we need to consider it */
    LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nm->seq %" PRIu32 ", m->payload_len %" PRIu32 ", "
                "ra_base_seq %" PRIu32 "", TCP_GET_SEQ(m),
                m->payload_len, ra_base_seq);

    if(SEQ_LEQ(TCP_GET_SEQ(m), ra_base_seq))//TCP_GET_SEQ(m) <= ra_base_seq
    {
        if( NULL == stream->seg_list ) //cache list is null and this is first seq, then return raw packet
        {
            LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nseg_list is null");

            if(SEQ_EQ(TCP_GET_SEQ(m), ra_base_seq))
            {
                LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\npacket seq eq ra_base, direct deliver and add ra_base");
                STREAMTCP_SET_RA_BASE_SEQ(stream, TCP_GET_SEQ(m) + m->payload_len);
                LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nnow: ra_base_seq is %u", StreamTcpReassembleGetRaBaseSeq(stream));
                *reasm_m = m;
                STREAMTCP_REASM_NO_NEED_REASM;
                return STREAMTCP_OK;
            }
            else//partly, handle segments partly before ra_base_seq
            {
            #if 0
                mbuf_t *reasm_mb;
                reasm_mb = StreamTcpReassamble_Setup(m);
                if(NULL == reasm_mb)
                {
                    STREAMTCP_REASM_SETUP_FAIL;
                    return STREAMTCP_ERR;
                }
                /*adjust*/
                LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nseq <-> payload_len partly overlap with ra_base, need adjust");
                uint8_t *src = (uint8_t *)reasm_mb->payload + ra_base_seq - TCP_GET_SEQ(m);
                uint8_t *dst = (uint8_t *)reasm_mb->payload;
                uint32_t len = TCP_GET_SEQ(m) + m->payload_len - ra_base_seq;
                memcpy((void *)dst, (void *)src, len);
                TCP_SET_SEQ(reasm_mb, ra_base_seq);
                reasm_mb->payload_len = len;

                StreamTcpReassembleAddRawMbuf(reasm_mb, m);

                STREAMTCP_SET_RA_BASE_SEQ(stream, (TCP_GET_SEQ(m) + m->payload_len));
                LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nnow: ra_base_seq is %u", StreamTcpReassembleGetRaBaseSeq(stream));
                *reasm_m = reasm_mb;
                STREAMTCP_REASM_OK;
                return STREAMTCP_OK;
            #endif
                LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nseq <-> payload_len partly overlap with ra_base, need adjust");
                m->tcp_reasm_overlap = TCP_GET_SEQ(m) + m->payload_len - ra_base_seq;
                STREAMTCP_SET_RA_BASE_SEQ(stream, (TCP_GET_SEQ(m) + m->payload_len));
                LOGDBG(SEC_STREAMTCP_REASM_DBG_BIT, "\nnow: ra_base_seq is %u", StreamTcpReassembleGetRaBaseSeq(stream));
                *reasm_m = m;
                STREAMTCP_REASM_REASM_OVERLAP;
                return STREAMTCP_REASM_OVERLAP;
            }
        }
        else
        {
            return StreamTcpReassmble(stream, m, reasm_m);
        }

    }

    return 0;
}

