#include "sec-common.h"
#include <mbuf.h>

#include <shm.h>
#include <flow.h>

#include "stream-tcp.h"
#include "stream-tcp-session.h"
#include "decode-statistic.h"
#include "stream-tcp-reassemble.h"
#include "dp_attack.h"
//#include "plugin.h"



uint32_t stream_tcp_track_enable = 1;
uint32_t stream_tcp_reasm_enable = 1;


uint32_t stream_tcp_midstream = 0;
uint32_t stream_tcp_async_oneside = 0;



#if 0
void TmModuleStreamTcpRegister (void)
{
    plugin_modules[PLUGIN_STREAMTCP].name = "StreamTcp";
    plugin_modules[PLUGIN_STREAMTCP].Init = StreamTcpInit;
    plugin_modules[PLUGIN_STREAMTCP].Func = StreamTcp;
}
#endif



#define StreamTcpUpdateLastAck(ssn, stream, ack) { \
    if (SEQ_GT((ack), (stream)->last_ack)) { \
        (stream)->last_ack = (ack); \
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: last_ack set to %"PRIu32, (ssn), (stream)->last_ack); \
    } \
}
#if 0
#define StreamTcpUpdateNextWin(ssn, stream, win) { \
#if 0
    uint32_t sacked_size__ = StreamTcpSackedSize((stream)); \
#endif
    if (SEQ_GT(((win) + 0/*sacked_size__*/), (stream)->next_win)) { \
        (stream)->next_win = ((win) + 0/*sacked_size__*/); \
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: next_win set to %"PRIu32, (ssn), (stream)->next_win); \
    } \
}
#else
#define StreamTcpUpdateNextWin(ssn, stream, win) { \
    if (SEQ_GT(((win) + 0), (stream)->next_win)) { \
        (stream)->next_win = ((win) + 0); \
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: next_win set to %"PRIu32, (ssn), (stream)->next_win); \
    } \
}

#endif




/**
 *  \brief  Function to test the received ACK values against the stream window
 *          and previous ack value. ACK values should be higher than previous
 *          ACK value and less than the next_win value.
 *
 *  \retval 0  ACK is valid, last_ack is updated if ACK was higher
 *  \retval -1 ACK is invalid
 */
static inline int StreamTcpValidateAck(TcpSession *ssn, TcpStream *stream, mbuf_t *mbuf)
{
    TCPHdr *tcph = (TCPHdr *)(mbuf->transport_header);
    uint32_t ack = TCP_GET_ACK(mbuf);

    /* fast track */
    if (SEQ_GT(ack, stream->last_ack) && SEQ_LEQ(ack, stream->next_win))
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nACK in bounds");
        return 0;
    }
    else if (SEQ_EQ(ack, stream->last_ack)) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\npkt ACK %"PRIu32" == stream last ACK %"PRIu32, TCP_GET_ACK(mbuf), stream->last_ack);
        return 0;
    }

    /* exception handling */
    if (SEQ_LT(ack, stream->last_ack)) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\npkt ACK %"PRIu32" < stream last ACK %"PRIu32, TCP_GET_ACK(mbuf), stream->last_ack);

        /* This is an attempt to get a 'left edge' value that we can check against.
         * It doesn't work when the window is 0, need to think of a better way. */
        if (stream->window != 0 && SEQ_LT(ack, (stream->last_ack - stream->window))) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nACK %"PRIu32" is before last_ack %"PRIu32" - window "
                    "%"PRIu32" = %"PRIu32, ack, stream->last_ack,
                    stream->window, stream->last_ack - stream->window);
            goto invalid;
        }
        return 0;
    }

    if (ssn->state > TCP_SYN_SENT && SEQ_GT(ack, stream->next_win)) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nACK %"PRIu32" is after next_win %"PRIu32, ack, stream->next_win);
        goto invalid;
    }

    /* a toclient RST as a reponse to SYN, next_win is 0, ack will be isn+1, just like the syn ack */
    else if (ssn->state == TCP_SYN_SENT && PKT_IS_TOCLIENT(mbuf) &&
            tcph->th_flags & TH_RST &&
            SEQ_EQ(ack, stream->isn + 1)) {
        return 0;
    }

    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\ndefault path leading to invalid: ACK %"PRIu32", last_ack %"PRIu32
        " next_win %"PRIu32, ack, stream->last_ack, stream->next_win);

invalid:
    STREAM_PKT_INVALID_ACK;
    return -1;
}




void StreamTcpPacketSetState(TcpSession *ssn, uint8_t state)
{
    if (state == ssn->state)
        return;

    ssn->state = state;
}

uint32_t StreamTcpHandleFin(TcpSession *ssn, mbuf_t *mbuf, mbuf_t **reasm_m)
{
    if (PKT_IS_TOSERVER(mbuf)){
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ","
                " ACK %" PRIu32 "", ssn, mbuf->payload_len, TCP_GET_SEQ(mbuf),
                TCP_GET_ACK(mbuf));

        if (StreamTcpValidateAck(ssn, &ssn->server, mbuf) == -1)
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
            STREAM_FIN_INVALID_ACK;
            return STREAMTCP_ERR;
        }

        if (SEQ_LT(TCP_GET_SEQ(mbuf), ssn->client.next_seq) ||
            SEQ_GT(TCP_GET_SEQ(mbuf), (ssn->client.last_ack + ssn->client.window)))
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(mbuf),
                    ssn->client.next_seq);
            STREAM_FIN_OUT_OF_WINDOW;
            return STREAMTCP_ERR;
        }

        StreamTcpPacketSetState(ssn, TCP_CLOSE_WAIT);
        ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_CLOSE_WAIT", ssn);

        if (SEQ_EQ(TCP_GET_SEQ(mbuf), ssn->client.next_seq))
            ssn->client.next_seq = TCP_GET_SEQ(mbuf) + mbuf->payload_len;

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.next_seq %" PRIu32 "", ssn,
                    ssn->client.next_seq);

        ssn->server.window = TCP_GET_WINDOW(mbuf) << ssn->server.wscale;

        StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));

        /* Update the next_seq, in case if we have missed the client packet
              * and server has already received and acked it */
        if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(mbuf)))
            ssn->server.next_seq = TCP_GET_ACK(mbuf);

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                ssn, ssn->client.next_seq, ssn->server.last_ack);

        return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
    }
    else//implied to client
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", "
                   "ACK %" PRIu32 "", ssn, mbuf->payload_len, TCP_GET_SEQ(mbuf),
                    TCP_GET_ACK(mbuf));

        if (StreamTcpValidateAck(ssn, &ssn->client, mbuf) == -1) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
            STREAM_FIN_INVALID_ACK;
            return STREAMTCP_ERR;
        }

        if (SEQ_LT(TCP_GET_SEQ(mbuf), ssn->server.next_seq) ||
            SEQ_GT(TCP_GET_SEQ(mbuf), (ssn->server.last_ack + ssn->server.window)))
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != "
                       "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(mbuf),
                        ssn->server.next_seq);
            STREAM_FIN_OUT_OF_WINDOW;
            return STREAMTCP_ERR;
        }

        StreamTcpPacketSetState(ssn, TCP_FIN_WAIT1);
        ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT,"\nssn %p: state changed to TCP_FIN_WAIT1", ssn);

        if (SEQ_EQ(TCP_GET_SEQ(mbuf), ssn->server.next_seq))
            ssn->server.next_seq = TCP_GET_SEQ(mbuf) + mbuf->payload_len;

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                    ssn->server.next_seq);

        ssn->client.window = TCP_GET_WINDOW(mbuf) << ssn->client.wscale;

        StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(mbuf));

        /* Update the next_seq, in case if we have missed the client packet
                and server has already received and acked it */
        if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(mbuf)))
            ssn->client.next_seq = TCP_GET_ACK(mbuf);

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                ssn, ssn->server.next_seq, ssn->client.last_ack);

        return StreamTcpReassembleHandleSegment(ssn, &ssn->server, mbuf, reasm_m);
    }

    *reasm_m = mbuf;
    return STREAMTCP_OK;
}




static uint32_t StreamTcpPacketStateNone(mbuf_t *mbuf, TcpSession *ssn, mbuf_t **reasm_m)
{
    TCPHdr *tcph = (TCPHdr *)(mbuf->transport_header);

    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\n======================>StreamTcpPacketStateNone");

    if (tcph->th_flags & TH_RST)     //STREAM_RST_BUT_NO_SESSION
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nRST packet received, no session setup");
        STREAM_RST_BUT_NO_SESSION;
        return STREAMTCP_ERR;
    }
    else if(tcph->th_flags & TH_FIN) //STREAM_FIN_BUT_NO_SESSION
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nFIN packet received, no session setup");
        STREAM_FIN_BUT_NO_SESSION;
        return STREAMTCP_ERR;
    }
    else if((tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
    {
        if(stream_tcp_midstream == 0 && stream_tcp_async_oneside == 0)
        {
            STREAM_SESSION_MIDSTREAM_OR_ONESIDE_DISABLE;
            return STREAMTCP_ERR;
        }

        if(NULL == ssn)
        {
            ssn = StreamTcpNewSession(mbuf);
            if(NULL == ssn)
            {
                STREAM_SESSION_NO_MEM;
                return STREAMTCP_ERR;
            }
        }
        /* set the state */
        StreamTcpPacketSetState(ssn, TCP_SYN_RECV);
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =~ midstream picked ssn state is now "
                "TCP_SYN_RECV", ssn);
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM;
        /* Flag used to change the direct in the later stage in the session */
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_SYNACK;

        /* sequence number & window */
        ssn->server.isn = TCP_GET_SEQ(mbuf);
    #if 0
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
    #else
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn + 1);
    #endif
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.window = TCP_GET_WINDOW(mbuf);
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: server window %u", ssn, ssn->server.window);

        ssn->client.isn = TCP_GET_ACK(mbuf) - 1;
    #if 0
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
    #else
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn + 1);
    #endif
        ssn->client.next_seq = ssn->client.isn + 1;

        ssn->client.last_ack = TCP_GET_ACK(mbuf);
        ssn->server.last_ack = TCP_GET_SEQ(mbuf);

        /*  If the client has a wscale option the server had it too,
              *  so set the wscale for the server to max. Otherwise none
              *  will have the wscale opt just like it should.
              */
        if (mbuf->tcpvars.ws != NULL) {
            ssn->client.wscale = TCP_GET_WSCALE(mbuf);
            ssn->server.wscale = TCP_WSCALE_MAX;
        }

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.isn %"PRIu32", ssn->client.next_seq"
                " %"PRIu32", ssn->client.last_ack %"PRIu32"", ssn,
                ssn->client.isn, ssn->client.next_seq,
                ssn->client.last_ack);
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.isn %"PRIu32", ssn->server.next_seq"
                " %"PRIu32", ssn->server.last_ack %"PRIu32"", ssn,
                ssn->server.isn, ssn->server.next_seq,
                ssn->server.last_ack);
    #if 0
        if (TCP_GET_SACKOK(p) == 1) {
            ssn->flags |= STREAMTCP_FLAG_SACKOK;
            SCLogDebug("ssn %p: SYN/ACK with SACK permitted, assuming "
                    "SACK permitted for both sides", ssn);
        }
    #endif

    }
    else if (tcph->th_flags & TH_SYN)
    {
        if(NULL == ssn)
        {
            ssn = StreamTcpNewSession(mbuf);
            if(NULL == ssn)
            {
                STREAM_SESSION_NO_MEM;
                return STREAMTCP_ERR;
            }
        }

        /* set the state */
        StreamTcpPacketSetState(ssn, TCP_SYN_SENT);
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =~ ssn state is now TCP_SYN_SENT", ssn);

        /* set the sequence numbers and window */
        ssn->client.isn = TCP_GET_SEQ(mbuf);
    #if 0
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
    #else
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn + 1);
    #endif
        ssn->client.next_seq = ssn->client.isn + 1;

        ssn->server.window = TCP_GET_WINDOW(mbuf);
        if (mbuf->tcpvars.ws != NULL) {
            ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
            ssn->server.wscale = TCP_GET_WSCALE(mbuf);
        }

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.isn %" PRIu32 ", "
                "ssn->client.next_seq %" PRIu32 ", ssn->client.last_ack "
                "%"PRIu32"", ssn, ssn->client.isn, ssn->client.next_seq,
                ssn->client.last_ack);
    }
    else if (tcph->th_flags & TH_ACK)
    {
        if(stream_tcp_midstream == 0)
        {
            STREAM_SESSION_MIDSTREAM_DISABLE;
            return STREAMTCP_ERR;
        }

        if(NULL == ssn)
        {
            ssn = StreamTcpNewSession(mbuf);
            if(NULL == ssn)
            {
                STREAM_SESSION_NO_MEM;
                return STREAMTCP_ERR;
            }
        }
        /* set the state */
        StreamTcpPacketSetState(ssn, TCP_ESTABLISHED);
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =~ midstream picked ssn state is now "
                "TCP_ESTABLISHED", ssn);

        ssn->flags = STREAMTCP_FLAG_MIDSTREAM;
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;

        /* set the sequence numbers and window */
        ssn->client.isn = TCP_GET_SEQ(mbuf) - 1;

    #if 0
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
    #else
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn + 1);
    #endif

        ssn->client.next_seq = TCP_GET_SEQ(mbuf) + mbuf->payload_len;
        ssn->client.window = TCP_GET_WINDOW(mbuf);
        ssn->client.last_ack = TCP_GET_SEQ(mbuf);
        ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.isn %u, ssn->client.next_seq %u",
                ssn, ssn->client.isn, ssn->client.next_seq);

        ssn->server.isn = TCP_GET_ACK(mbuf) - 1;

    #if 0
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
    #else
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn + 1);
    #endif

        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.last_ack = TCP_GET_ACK(mbuf);
        ssn->server.next_win = ssn->server.last_ack;

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.next_win %"PRIu32", "
                "ssn->server.next_win %"PRIu32"", ssn,
                ssn->client.next_win, ssn->server.next_win);
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.last_ack %"PRIu32", "
                "ssn->server.last_ack %"PRIu32"", ssn,
                ssn->client.last_ack, ssn->server.last_ack);

        /** window scaling for midstream pickups, we can't do much other
         *  than assume that it's set to the max value: 14 */
        ssn->client.wscale = TCP_WSCALE_MAX;
        ssn->server.wscale = TCP_WSCALE_MAX;

        ssn->flags |= STREAMTCP_FLAG_SACKOK;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: assuming SACK permitted for both sides", ssn);

        return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
    }
    else
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\ndefault case");
    }

    *reasm_m = mbuf;
    return STREAMTCP_OK;
}

void StreamTcp3whsSynAckUpdate(TcpSession *ssn, mbuf_t *m)
{
    if (m->tcpvars.ws != NULL) {
        m->flags |= PKT_HAS_WS;
    }

    if (ssn->state != TCP_SYN_RECV) {
        /* update state */
        StreamTcpPacketSetState(ssn, TCP_SYN_RECV);
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =~ ssn state is now TCP_SYN_RECV", ssn);
    }

    /* sequence number & window */
    ssn->server.isn = TCP_GET_SEQ(m);

#if 0
    STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
#else
    STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn + 1);
#endif

    ssn->server.next_seq = ssn->server.isn + 1;

    ssn->client.window = TCP_GET_WINDOW(m);
    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: window %" PRIu32 "", ssn, ssn->server.window);

    ssn->client.last_ack = TCP_GET_ACK(m);
    ssn->server.last_ack = ssn->server.isn + 1;

    /** check for the presense of the ws ptr to determine if we
        *  support wscale at all */
    if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) &&
            (m->flags & PKT_HAS_WS))
    {
        ssn->client.wscale = TCP_GET_WSCALE(m);
    } else {
        ssn->client.wscale = 0;
    }

    ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
    ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.next_win %" PRIu32 "", ssn,
            ssn->server.next_win);
    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.next_win %" PRIu32 "", ssn,
            ssn->client.next_win);
    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.isn %" PRIu32 ", "
            "ssn->server.next_seq %" PRIu32 ", "
            "ssn->server.last_ack %" PRIu32 " "
            "(ssn->client.last_ack %" PRIu32 ")", ssn,
            ssn->server.isn, ssn->server.next_seq,
            ssn->server.last_ack, ssn->client.last_ack);

    /* unset the 4WHS flag as we received this SYN/ACK as part of a (so far) valid 3WHS */
    if (ssn->flags & STREAMTCP_FLAG_4WHS)
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: STREAMTCP_FLAG_4WHS unset, normal SYN/ACK"
                " so considering 3WHS", ssn);

    ssn->flags &=~ STREAMTCP_FLAG_4WHS;

}

uint32_t StreamTcpPacketStateSynRecv(mbuf_t *m, TcpSession *ssn, mbuf_t **reasm_m)
{
    TCPHdr *tcph = (TCPHdr *)(m->transport_header);

    if (ssn == NULL){
        STREAM_SESSION_PARAM_ERR;
        return STREAMTCP_ERR;
    }

    if (tcph->th_flags & TH_RST) {//RST
    #if 0
        if (!StreamTcpValidateRst(ssn, p))
            return -1;
    #endif

        uint8_t reset = TRUE;

        if (reset == TRUE) {
            StreamTcpPacketSetState(ssn, TCP_CLOSED);
            ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received and state changed to ""TCP_CLOSED", ssn);
        }
    } else if (tcph->th_flags & TH_FIN) {//FIN
        /* FIN is handled in the same way as in TCP_ESTABLISHED case */;
        return StreamTcpHandleFin(ssn, m, reasm_m);
    }
    else if ((tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))//SYN/ACK
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN/ACK packet on state SYN_RECV. resent", ssn);

        if (PKT_IS_TOSERVER(m)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN/ACK-pkt to server in SYN_RECV state", ssn);
            STREAM_3WHS_SYNACK_TOSERVER_ON_SYN_RECV;
            return STREAMTCP_ERR;
        }

        /* Check if the SYN/ACK packets ACK matches the earlier
              * received SYN/ACK packet. */
        if (!(SEQ_EQ(TCP_GET_ACK(m), ssn->client.last_ack))) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(m),
                    ssn->client.isn + 1);
            STREAM_3WHS_SYNACK_RESEND_WITH_DIFFERENT_ACK;
            return STREAMTCP_ERR;
        }

        /* Check if the SYN/ACK packet SEQ the earlier
              * received SYN/ACK packet, server resend with different ISN. */
        if (!(SEQ_EQ(TCP_GET_SEQ(m), ssn->server.isn))) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(m),
                    ssn->client.isn);
            STERAM_3WHS_SYNACK_SEQ_MISMATCH;
            return STREAMTCP_ERR;
        }
    }
    else if (tcph->th_flags & TH_SYN) //SYN
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN packet on state SYN_RECV... resent", ssn);

        if (PKT_IS_TOCLIENT(m)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN-pkt to client in SYN_RECV state", ssn);
            STREAM_3WHS_SYN_TOCLIENT_ON_SYN_RECV;
            return STREAMTCP_ERR;
        }

        if (!(SEQ_EQ(TCP_GET_SEQ(m), ssn->client.isn))) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN with different SEQ on SYN_RECV state", ssn);
            STREAM_3WHS_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV;
            return STREAMTCP_ERR;
        }
    }
    else if (tcph->th_flags & TH_ACK) //ACK
    {


        if ((ssn->flags & STREAMTCP_FLAG_4WHS) && PKT_IS_TOCLIENT(m)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ACK received on 4WHS session",ssn);

            if (!(SEQ_EQ(TCP_GET_SEQ(m), ssn->server.next_seq))) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: 4WHS wrong seq nr on packet", ssn);
                STREAM_4WHS_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, m) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: 4WHS invalid ack nr on packet", ssn);
                STREAM_4WHS_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\n4WHS normal pkt");
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, m->payload_len,
                    TCP_GET_SEQ(m), TCP_GET_ACK(m));


            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(m));
            ssn->server.next_seq += m->payload_len;
            ssn->client.window = TCP_GET_WINDOW(m) << ssn->client.wscale;
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

            DP_Attack_SynCountFins(m);
            StreamTcpPacketSetState(ssn, TCP_ESTABLISHED);
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.next_win %" PRIu32 ", "
                    "ssn->client.last_ack %"PRIu32"", ssn,
                    ssn->client.next_win, ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, m, reasm_m);
        }

        if (PKT_IS_TOCLIENT(m)){
            /* special case, handle 4WHS, so SYN/ACK in the opposite direction */
            if(ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK)
            {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ACK received on midstream SYN/ACK "
                        "pickup session",ssn);
            }
            else
            {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ACK received in the wrong direction", ssn);
                STREAM_3WHS_ACK_IN_WRONG_DIR;
                return STREAMTCP_ERR;
            }
        }

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ""
                ", ACK %" PRIu32 "", ssn, m->payload_len, TCP_GET_SEQ(m),
                TCP_GET_ACK(m));

        /* Check both seq and ack number before accepting the packet and changing to ESTABLISHED state */
        if ((SEQ_EQ(TCP_GET_SEQ(m), ssn->client.next_seq)) &&
                SEQ_EQ(TCP_GET_ACK(m), ssn->server.next_seq))
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nnormal pkt");

            /* process the packet normal, No Async streams :) */
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(m));

            ssn->client.next_seq += m->payload_len;
            ssn->server.window = TCP_GET_WINDOW(m) << ssn->server.wscale;
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->client.window = TCP_GET_WINDOW(m);
                ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
                /* window scaling for midstream pickups, we can't do much
                           * other than assume that it's set to the max value: 14 */
                ssn->server.wscale = TCP_WSCALE_MAX;
                ssn->client.wscale = TCP_WSCALE_MAX;
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
            }
            DP_Attack_SynCountFins(m);
            StreamTcpPacketSetState(ssn, TCP_ESTABLISHED);
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.next_win %" PRIu32 ", "
                    "ssn->client.last_ack %"PRIu32"", ssn,
                    ssn->client.next_win, ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, m, reasm_m);
        }
        else if (stream_tcp_async_oneside == 1 && SEQ_EQ(TCP_GET_SEQ(m), ssn->server.next_seq))//async_oneside
        {
            /*set the ASYNC flag used to indicate the session as async stream
                     *and helps in relaxing the windows checks.*/
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
            ssn->server.next_seq += m->payload_len;
            ssn->server.last_ack = TCP_GET_SEQ(m);

            ssn->client.window = TCP_GET_WINDOW(m) << ssn->client.wscale;
            ssn->client.last_ack = TCP_GET_ACK(m);

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->server.window = TCP_GET_WINDOW(m);
                ssn->client.next_win = ssn->server.last_ack +
                    ssn->server.window;
                /* window scaling for midstream pickups, we can't do much
                           * other than assume that it's set to the max value: 14 */
                ssn->server.wscale = TCP_WSCALE_MAX;
                ssn->client.wscale = TCP_WSCALE_MAX;
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
            }

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: synrecv => Asynchronous stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->server.next_seq %" PRIu32 "\n"
                    , ssn, TCP_GET_SEQ(m), m->payload_len, TCP_GET_SEQ(m)
                    + m->payload_len, ssn->server.next_seq);

            StreamTcpPacketSetState(ssn, TCP_ESTABLISHED);
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.next_win %" PRIu32 ", "
                "ssn->server.last_ack %"PRIu32"", ssn,
                ssn->server.next_win, ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, m, reasm_m);
            /* Upon receiving the packet with correct seq number and wrong
                    * ACK number, it causes the other end to send RST. But some target
                    * system (Linux & solaris) does not RST the connection, so it is
                    * likely to avoid the detection */
        }
        else if (SEQ_EQ(TCP_GET_SEQ(m), ssn->client.next_seq))
        {
            ssn->flags |= STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT;
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: wrong ack nr on packet, possible evasion!!", ssn);
            STREAM_3WHS_RIGHT_SEQ_WRONG_ACK_EVASION;
            return STREAMTCP_ERR;
        }
        else
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: wrong seq nr on packet", ssn);
            STREAM_3WHS_WRONG_SEQ_WRONG_ACK;
            return STREAMTCP_ERR;
        }
    }
    else
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: default case", ssn);
    }

    *reasm_m = m;
    return STREAMTCP_OK;
}


uint32_t StreamTcpPacketStateSynSent(mbuf_t *m, TcpSession *ssn, mbuf_t **reasm_m)
{
    TCPHdr *tcph = (TCPHdr *)(m->transport_header);

    if(NULL == ssn)
    {
        STREAM_SESSION_PARAM_ERR;
        return STREAMTCP_ERR;
    }
    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt received: %s", ssn, PKT_IS_TOCLIENT(m) ?
               "toclient":"toserver");

    if (tcph->th_flags & TH_RST) { // RST
    #if 0
        if (!StreamTcpValidateRst(ssn, p))
            return -1;
    #endif
        if (PKT_IS_TOSERVER(m)) {
            if (SEQ_EQ(TCP_GET_SEQ(m), ssn->client.isn) &&
                    SEQ_EQ(TCP_GET_WINDOW(m), 0) &&
                    SEQ_EQ(TCP_GET_ACK(m), (ssn->client.isn + 1)))
            {
                StreamTcpPacketSetState(ssn, TCP_CLOSED);
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received and state changed to "
                        "TCP_CLOSED", ssn);
            }
        } else {
            StreamTcpPacketSetState(ssn, TCP_CLOSED);
            ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received and state changed to "
                    "TCP_CLOSED", ssn);
        }
    }
    else if (tcph->th_flags & TH_FIN) { // FIN
        /** \todo  will sync with suricata*/
    }
    else if ((tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))//SYN/ACK
    {
        if ((ssn->flags & STREAMTCP_FLAG_4WHS) && PKT_IS_TOSERVER(m)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN/ACK received on 4WHS session", ssn);

            /*
                    * Check if the SYN/ACK packet ack's the earlier
                    * received SYN packet.
                    */
            if (!(SEQ_EQ(TCP_GET_ACK(m), ssn->server.isn + 1))) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: 4WHS ACK mismatch, packet ACK %"PRIu32""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_ACK(m), ssn->server.isn + 1);
                STREAM_4WHS_SYNACK_WITH_WRONG_ACK;
                return STREAMTCP_ERR;
            }

            /* Check if the SYN/ACK packet SEQ's the *FIRST* received SYN packet. */
            if (!(SEQ_EQ(TCP_GET_SEQ(m), ssn->client.isn))) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: 4WHS SEQ mismatch, packet SEQ %"PRIu32""
                        " != %" PRIu32 " from *first* SYN pkt", ssn,
                        TCP_GET_SEQ(m), ssn->client.isn);
                STREAM_4WHS_SYNACK_WITH_WRONG_SYN;
                return STREAMTCP_ERR;
            }


            /* update state */
            StreamTcpPacketSetState(ssn, TCP_SYN_RECV);
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =~ 4WHS ssn state is now TCP_SYN_RECV", ssn);

            /* sequence number & window */
            ssn->client.isn = TCP_GET_SEQ(m);

        #if 0
            STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        #else
            STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn + 1);
        #endif

            ssn->client.next_seq = ssn->client.isn + 1;

            ssn->server.window = TCP_GET_WINDOW(m);
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: 4WHS window %" PRIu32 "", ssn, ssn->client.window);

            ssn->server.last_ack = TCP_GET_ACK(m);
            ssn->client.last_ack = ssn->client.isn + 1;

            /** check for the presense of the ws ptr to determine if we support wscale at all */
            if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) && (m->tcpvars.ws != NULL)) {
                ssn->server.wscale = TCP_GET_WSCALE(m);
            } else {
                ssn->server.wscale = 0;
            }
        #if 0
            if ((ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) &&
                    TCP_GET_SACKOK(p) == 1) {
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
                SCLogDebug("ssn %p: SACK permitted for 4WHS session", ssn);
            }
        #endif
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: 4WHS ssn->client.next_win %" PRIu32 "", ssn, ssn->client.next_win);
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: 4WHS ssn->server.next_win %" PRIu32 "", ssn, ssn->server.next_win);
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: 4WHS ssn->client.isn %" PRIu32 ", "
                    "ssn->client.next_seq %" PRIu32 ", "
                    "ssn->client.last_ack %" PRIu32 " "
                    "(ssn->server.last_ack %" PRIu32 ")", ssn,
                    ssn->client.isn, ssn->client.next_seq,
                    ssn->client.last_ack, ssn->server.last_ack);

            /* done here */
            *reasm_m = m;
            return STREAMTCP_OK;
        }

        if (PKT_IS_TOSERVER(m)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN/ACK received in the wrong direction", ssn);
            STREAM_3WHS_SYNACK_IN_WRONG_DIRECTION;
            return STREAMTCP_ERR;
        }

        /* Check if the SYN/ACK packet ack's the earlier received SYN packet. */
        if (!(SEQ_EQ(TCP_GET_ACK(m), ssn->client.isn + 1))) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(m),
                    ssn->client.isn + 1);
            STREAM_3WHS_SYNACK_WITH_WRONG_ACK;
            return STREAMTCP_ERR;
        }

        StreamTcp3whsSynAckUpdate(ssn, m);
    } else if (tcph->th_flags & TH_SYN) {  // SYN
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN packet on state SYN_SENT... resent", ssn);

        if (ssn->flags & STREAMTCP_FLAG_4WHS) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN packet on state SYN_SENT... resent of " "4WHS SYN", ssn);
        }

        if (PKT_IS_TOCLIENT(m)) {
            /*
                    *  a SYN only packet in the opposite direction could be:
                    *  http://www.breakingpointsystems.com/community/blog/tcp-
                    *  portals-the-three-way-handshake-is-a-lie
                    *
                    * \todo improve resetting the session
                    */

            /* indicate that we're dealing with 4WHS here */
            ssn->flags |= STREAMTCP_FLAG_4WHS;
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: STREAMTCP_FLAG_4WHS flag set", ssn);

            /*
                    * set the sequence numbers and window for server
                    * We leave the ssn->client.isn in place as we will
                    * check the SYN/ACK pkt with that.
                    */
            ssn->server.isn = TCP_GET_SEQ(m);

        #if 0
            STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        #else
            STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn + 1);
        #endif

            ssn->server.next_seq = ssn->server.isn + 1;

            ssn->server.window = TCP_GET_WINDOW(m);
            if (m->tcpvars.ws != NULL) {
                ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
                ssn->server.wscale = TCP_GET_WSCALE(m);
            } else {
                ssn->flags &= ~STREAMTCP_FLAG_SERVER_WSCALE;
                ssn->server.wscale = 0;
            }

        #if 0
            if (TCP_GET_SACKOK(p) == 1) {
                ssn->flags |= STREAMTCP_FLAG_CLIENT_SACKOK;
            } else {
                ssn->flags &= ~STREAMTCP_FLAG_CLIENT_SACKOK;
            }
        #endif

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: 4WHS ssn->server.isn %" PRIu32 ", "
                    "ssn->server.next_seq %" PRIu32 ", "
                    "ssn->server.last_ack %"PRIu32"", ssn,
                    ssn->server.isn, ssn->server.next_seq,
                    ssn->server.last_ack);
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: 4WHS ssn->client.isn %" PRIu32 ", "
                    "ssn->client.next_seq %" PRIu32 ", "
                    "ssn->client.last_ack %"PRIu32"", ssn,
                    ssn->client.isn, ssn->client.next_seq,
                    ssn->client.last_ack);
        }

        /** \todo check if it's correct or set event */
    }
    else if (tcph->th_flags & TH_ACK) {  //ACK
        /* Handle the asynchronous stream, when we receive a  SYN packet
           and now istead of receving a SYN/ACK we receive a ACK from the
           same host, which sent the SYN, this suggests the ASNYC streams.*/
        if(stream_tcp_async_oneside == 0)
        {
            STREAM_SESSION_ONESIDE_DISABLE;
            return STREAMTCP_ERR;
        }

        /* we are in AYNC (one side) mode now. */

        /* one side async means we won't see a SYN/ACK, so we can
         * only check the SYN. */
         if (!(SEQ_EQ(TCP_GET_SEQ(m), ssn->client.next_seq))) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream",ssn, TCP_GET_SEQ(m),
                    ssn->client.next_seq);
            STREAM_3WHS_ASYNC_WRONG_SEQ;
            return STREAMTCP_ERR;
        }

        ssn->flags |= STREAMTCP_FLAG_ASYNC;
        StreamTcpPacketSetState(ssn, TCP_ESTABLISHED);

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

        ssn->client.window = TCP_GET_WINDOW(m);
        ssn->client.last_ack = TCP_GET_SEQ(m);
        ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

        /* Set the server side parameters */
        ssn->server.isn = TCP_GET_ACK(m) - 1;
    #if 0
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
    #else
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn + 1);
    #endif
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.last_ack = ssn->server.next_seq;
        ssn->server.next_win = ssn->server.last_ack;

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: synsent => Asynchronous stream, packet SEQ"
                " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                "ssn->client.next_seq %" PRIu32 ""
                ,ssn, TCP_GET_SEQ(m), m->payload_len, TCP_GET_SEQ(m)
                + m->payload_len, ssn->client.next_seq);

        ssn->client.wscale = TCP_WSCALE_MAX;
        ssn->server.wscale = TCP_WSCALE_MAX;

    } else {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: default case", ssn);
    }

    *reasm_m = m;
    return STREAMTCP_OK;
}



uint32_t HandleEstablishedPacketToClient(TcpSession *ssn, mbuf_t *mbuf, mbuf_t **reasm_m)
{
    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ","
               " ACK %" PRIu32 ", WIN %"PRIu16"", ssn, mbuf->payload_len,
                TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf), TCP_GET_WINDOW(mbuf));

    if (StreamTcpValidateAck(ssn, &ssn->client, mbuf) == -1) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
        STREAM_EST_INVALID_ACK;
        return STREAMTCP_ERR;
    }

        /* To get the server window value from the servers packet, when connection
       is picked up as midstream */
    if ((ssn->flags & STREAMTCP_FLAG_MIDSTREAM) &&
        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED))
    {
        ssn->server.window = TCP_GET_WINDOW(mbuf);
        ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
        ssn->flags &= ~STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: adjusted midstream ssn->server.next_win to "
                "%" PRIu32 "", ssn, ssn->server.next_win);
    }

    /* check for Keep Alive */
    if ((mbuf->payload_len == 0 || mbuf->payload_len == 1) &&
        (TCP_GET_SEQ(mbuf) == (ssn->server.next_seq - 1))) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt is keep alive", ssn);
    /* normal pkt */
    } else if (!(SEQ_GEQ((TCP_GET_SEQ(mbuf) + mbuf->payload_len), ssn->server.last_ack))) {
        if (ssn->flags & STREAMTCP_FLAG_ASYNC) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: client => Asynchrouns stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                    " ssn->client.last_ack %" PRIu32 ", ssn->client.next_win"
                    " %"PRIu32"(%"PRIu32")", ssn, TCP_GET_SEQ(mbuf),
                    mbuf->payload_len, TCP_GET_SEQ(mbuf) + mbuf->payload_len,
                    ssn->server.last_ack, ssn->server.next_win,
                    TCP_GET_SEQ(mbuf) + mbuf->payload_len - ssn->server.next_win);

            ssn->server.last_ack = TCP_GET_SEQ(mbuf);
        } else {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16
                    " before last_ack %"PRIu32,
                    ssn, TCP_GET_SEQ(mbuf), mbuf->payload_len, ssn->server.last_ack);
            STREAM_EST_PKT_BEFORE_LAST_ACK;
            return STREAMTCP_ERR;
        }
    }

    int zerowindowprobe = 0;
    /* zero window probe */

    if (mbuf->payload_len == 1 && TCP_GET_SEQ(mbuf) == ssn->server.next_seq && ssn->server.window == 0) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: zero window probe", ssn);
        zerowindowprobe = 1;
    } else if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(mbuf))) { //expected packet
        ssn->server.next_seq += mbuf->payload_len;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.next_seq %" PRIu32 "",
                ssn, ssn->server.next_seq);
    }

    if (zerowindowprobe) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: zero window probe, skipping oow check", ssn);
    } else if (SEQ_LEQ(TCP_GET_SEQ(mbuf) + mbuf->payload_len, ssn->server.next_win)  ||
            (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
            (ssn->flags & STREAMTCP_FLAG_ASYNC)) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: seq %"PRIu32" in window, ssn->server.next_win "
                "%" PRIu32 "", ssn, TCP_GET_SEQ(mbuf), ssn->server.next_win);
        ssn->client.window = TCP_GET_WINDOW(mbuf) << ssn->client.wscale;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.window %"PRIu32"", ssn,
                    ssn->client.window);

        StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(mbuf));

        /* Update the next_seq, in case if we have missed the client packet
           and server has already received and acked it */
        if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(mbuf)))
            ssn->client.next_seq = TCP_GET_ACK(mbuf);

        //StreamTcpSackUpdatePacket(&ssn->client, p);

        StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

        return StreamTcpReassembleHandleSegment(ssn, &ssn->server, mbuf, reasm_m);
    }
    else
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: client => SEQ out of window, packet SEQ"
                   "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                   " ssn->server.last_ack %" PRIu32 ", ssn->server.next_win "
                   "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(mbuf),
                   mbuf->payload_len, TCP_GET_SEQ(mbuf) + mbuf->payload_len,
                   ssn->server.last_ack, ssn->server.next_win,
                   TCP_GET_SEQ(mbuf) + mbuf->payload_len - ssn->server.next_win);
        STREAM_EST_PACKET_OUT_OF_WINDOW;
        return STREAMTCP_ERR;
    }

    *reasm_m = mbuf;
    return STREAMTCP_OK;
}


uint32_t HandleEstablishedPacketToServer(TcpSession *ssn, mbuf_t *mbuf, mbuf_t **reasm_m)
{
    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ","
               "ACK %" PRIu32 ", WIN %"PRIu16"", ssn, mbuf->payload_len,
                TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf), TCP_GET_WINDOW(mbuf));

    if (StreamTcpValidateAck(ssn, &(ssn->server), mbuf) == -1) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
        STREAM_EST_INVALID_ACK;
        return STREAMTCP_ERR;
    }

    /* check for Keep Alive */
    if ((mbuf->payload_len == 0 || mbuf->payload_len == 1) &&
            (TCP_GET_SEQ(mbuf) == (ssn->client.next_seq - 1))) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt is keep alive", ssn);
    }
    /* normal pkt */
    else if (!(SEQ_GEQ((TCP_GET_SEQ(mbuf) + mbuf->payload_len), ssn->client.last_ack)))
    {
        if (ssn->flags & STREAMTCP_FLAG_ASYNC) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: server => Asynchrouns stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                    " ssn->client.last_ack %" PRIu32 ", ssn->client.next_win"
                    "%" PRIu32"(%"PRIu32")", ssn, TCP_GET_SEQ(mbuf),
                    mbuf->payload_len, TCP_GET_SEQ(mbuf) + mbuf->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(mbuf) + mbuf->payload_len - ssn->client.next_win);

            /* update the last_ack to current seq number as the session is
             * async and other stream is not updating it anymore :( */
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(mbuf));
        }
        else if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(mbuf)) &&
                (stream_tcp_async_oneside == 1) &&
                (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: server => Asynchronous stream, packet SEQ."
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(mbuf),
                    mbuf->payload_len, TCP_GET_SEQ(mbuf) + mbuf->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(mbuf) + mbuf->payload_len - ssn->client.next_win);

            /* it seems we missed SYN and SYN/ACK packets of this session.
             * Update the last_ack to current seq number as the session
             * is async and other stream is not updating it anymore :( */
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(mbuf));
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
        }
        else if (SEQ_EQ(ssn->client.last_ack, (ssn->client.isn + 1)) &&
                (stream_tcp_async_oneside == 1) &&
                (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: server => Asynchronous stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(mbuf),
                    mbuf->payload_len, TCP_GET_SEQ(mbuf) + mbuf->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(mbuf) + mbuf->payload_len - ssn->client.next_win);

            /* it seems we missed SYN and SYN/ACK packets of this session.
             * Update the last_ack to current seq number as the session
             * is async and other stream is not updating it anymore :(*/
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(mbuf));
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
        }
        else
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: server => SEQ before last_ack, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(mbuf),
                    mbuf->payload_len, TCP_GET_SEQ(mbuf) + mbuf->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(mbuf) + mbuf->payload_len - ssn->client.next_win);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because pkt before last_ack", ssn);
            STREAM_EST_PKT_BEFORE_LAST_ACK;
            return STREAMTCP_ERR;
        }
    }

    int zerowindowprobe = 0;
    /* zero window probe */

    if (mbuf->payload_len == 1 && TCP_GET_SEQ(mbuf) == ssn->client.next_seq && ssn->client.window == 0) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: zero window probe", ssn);
        zerowindowprobe = 1;
    /* expected packet */
    } else if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(mbuf))) {
        ssn->client.next_seq += mbuf->payload_len;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.next_seq %" PRIu32 "",
                    ssn, ssn->client.next_seq);
    }

    /* in window check */
    if (zerowindowprobe) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: zero window probe, skipping oow check", ssn);
    }else if (SEQ_LEQ(TCP_GET_SEQ(mbuf) + mbuf->payload_len, ssn->client.next_win) ||
        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
        (ssn->flags & STREAMTCP_FLAG_ASYNC))
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: seq %"PRIu32" in window, ssn->client.next_win "
                   "%" PRIu32 "", ssn, TCP_GET_SEQ(mbuf), ssn->client.next_win);
        ssn->server.window = TCP_GET_WINDOW(mbuf) << ssn->server.wscale;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.window %"PRIu32"", ssn,
                    ssn->server.window);
        /* Check if the ACK value is sane and inside the window limit */
        StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));

        /* Update the next_seq, in case if we have missed the server packet
           and client has already received and acked it */
        if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(mbuf)))
            ssn->server.next_seq = TCP_GET_ACK(mbuf);
#if 0
        StreamTcpSackUpdatePacket(&ssn->server, p);
#endif
        /* update next_win */
        StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

        /* handle data (if any) */
        return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
    }
    else {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: toserver => SEQ out of window, packet SEQ "
                "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(mbuf),
                mbuf->payload_len, TCP_GET_SEQ(mbuf) + mbuf->payload_len,
                ssn->client.last_ack, ssn->client.next_win,
                (TCP_GET_SEQ(mbuf) + mbuf->payload_len) - ssn->client.next_win);
        //LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "ssn %p: window %u sacked %u", ssn, ssn->client.window,
        //        StreamTcpSackedSize(&ssn->client));
        STREAM_EST_PACKET_OUT_OF_WINDOW;
        return STREAMTCP_ERR;
    }

    *reasm_m = mbuf;
    return STREAMTCP_OK;

}



static inline uint32_t StreamTcpResetGetMaxAck(TcpStream *stream, uint32_t seq) {
    uint32_t ack = seq;
#if 0
    if (stream->seg_list_tail != NULL) {
        if (SEQ_GT((stream->seg_list_tail->seq + stream->seg_list_tail->payload_len), ack))
        {
            ack = stream->seg_list_tail->seq + stream->seg_list_tail->payload_len;
        }
    }
#endif
    return (ack);
}

uint32_t StreamTcpPacketStateEstablished(mbuf_t *mbuf, TcpSession *ssn, mbuf_t **reasm_m)
{
    TCPHdr *tcph = (TCPHdr *)(mbuf->transport_header);

    if (ssn == NULL){
        STREAM_SESSION_PARAM_ERR;
        return STREAMTCP_ERR;
    }
    if (tcph->th_flags & TH_RST){     //RST
    #if 0
        if (!StreamTcpValidateRst(ssn, p))
            return -1;
    #endif

        if (PKT_IS_TOSERVER(mbuf)) {
            StreamTcpPacketSetState(ssn, TCP_CLOSED);
            ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received and state changed to ""TCP_CLOSED", ssn);

            ssn->server.next_seq = TCP_GET_ACK(mbuf);
            ssn->client.next_seq = TCP_GET_SEQ(mbuf) + mbuf->payload_len;
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                    ssn->server.next_seq);

            ssn->client.window = TCP_GET_WINDOW(mbuf) << ssn->client.wscale;

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(mbuf)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(mbuf)));


            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, mbuf, reasm_m);

        } else{   //to client

            StreamTcpPacketSetState(ssn, TCP_CLOSED);
            ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received and state changed to "
                    "TCP_CLOSED", ssn);

            ssn->server.next_seq = TCP_GET_SEQ(mbuf) + mbuf->payload_len + 1;
            ssn->client.next_seq = TCP_GET_ACK(mbuf);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                    ssn->server.next_seq);
            ssn->server.window = TCP_GET_WINDOW(mbuf) << ssn->server.wscale;

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(mbuf)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(mbuf)));


            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);


        }
    }
    else if (tcph->th_flags & TH_FIN){      //FIN
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn (%p: FIN received SEQ"
            " %" PRIu32 ", last ACK %" PRIu32 ", next win %"PRIu32","
            " win %" PRIu32 "", ssn, ssn->server.next_seq,
            ssn->client.last_ack, ssn->server.next_win,
            ssn->server.window);

        return StreamTcpHandleFin(ssn, mbuf, reasm_m);
    } else if ((tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) { //SYN/ACK
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN/ACK packet on state ESTABLISHED... resent", ssn);

        if (PKT_IS_TOSERVER(mbuf)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN/ACK-pkt to server in ESTABLISHED state", ssn);
            STREAM_EST_SYNACK_TOSERVER;
            return STREAMTCP_ERR;
        }

        /* Check if the SYN/ACK packets ACK matches the earlier
              * received SYN/ACK packet. */
        if (!(SEQ_EQ(TCP_GET_ACK(mbuf), ssn->client.last_ack))) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(mbuf),
                    ssn->client.isn + 1);
            STREAM_EST_SYNACK_RESEND_WITH_DIFFERENT_ACK;
            return STREAMTCP_ERR;
        }

        /* Check if the SYN/ACK packet SEQ the earlier
         * received SYN packet. */
        if (!(SEQ_EQ(TCP_GET_SEQ(mbuf), ssn->server.isn))) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(mbuf),
                    ssn->client.isn + 1);
            STREAM_EST_SYNACK_RESEND_WITH_DIFF_SEQ;
            return STREAMTCP_ERR;
        }

        if (ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED) {
            /* a resend of a SYN while we are established already -- fishy */
            STREAM_EST_SYNACK_RESEND;
            return STREAMTCP_ERR;
        }

        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN/ACK packet on state ESTABLISHED... resent. "
                "Likely due server not receiving final ACK in 3whs", ssn);

        /* resetting state to TCP_SYN_RECV as we should get another ACK now */
        StreamTcpPacketSetState(ssn, TCP_SYN_RECV);
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =~ ssn state is now reset to TCP_SYN_RECV", ssn);

        *reasm_m = mbuf;
        return STREAMTCP_OK;
    }
    else if (tcph->th_flags & TH_SYN) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN packet on state ESTABLISED... resent", ssn);
        if (PKT_IS_TOCLIENT(mbuf)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN-pkt to client in EST state", ssn);
            STREAM_EST_SYN_TOCLIENT;
            return STREAMTCP_ERR;
        }

        if (!(SEQ_EQ(TCP_GET_SEQ(mbuf), ssn->client.isn))) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: SYN with different SEQ on SYN_RECV state", ssn);
            STREAM_EST_SYN_RESEND_DIFF_SEQ;
            return STREAMTCP_ERR;
        }

        /* a resend of a SYN while we are established already -- fishy */
        STREAM_EST_SYN_RESEND;
        return STREAMTCP_ERR;
    } else if (tcph->th_flags & TH_ACK) {
        if (PKT_IS_TOSERVER(mbuf))
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 ","
                    " next win %" PRIu32 ", win %" PRIu32 "", ssn,
                    ssn->client.next_seq, ssn->server.last_ack
                    ,ssn->client.next_win, ssn->client.window);

            /* Process the received packet to server */
            return HandleEstablishedPacketToServer(ssn, mbuf, reasm_m);
        }
        else/* implied to client */
        {
            if (!(ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED)) {
                ssn->flags |= STREAMTCP_FLAG_3WHS_CONFIRMED;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\n3whs is now confirmed by server");
            }

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 ","
                    " next win %" PRIu32 ", win %" PRIu32 "", ssn,
                    ssn->server.next_seq, ssn->client.last_ack,
                    ssn->server.next_win, ssn->server.window);

            /* Process the received packet to client */
            return HandleEstablishedPacketToClient(ssn, mbuf, reasm_m);
        }
    }
    else
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: default case", ssn);
    }

    *reasm_m = mbuf;
    return STREAMTCP_OK;
}

int StreamTcpPacketIsRetransmission(TcpStream *stream, mbuf_t *m)
{
    if (m->payload_len == 0)
        return 0;

    /* retransmission of already ack'd data */
    if (SEQ_LEQ((TCP_GET_SEQ(m) + m->payload_len), stream->last_ack)) {
        STREAM_PKT_RETRANSMISSION;
        return 1;
    }

    /* retransmission of in flight data */
    if (SEQ_LEQ((TCP_GET_SEQ(m) + m->payload_len), stream->next_seq)) {
        STREAM_PKT_RETRANSMISSION;
        return 2;
    }

    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nseq %u payload_len %u => %u, last_ack %u", TCP_GET_SEQ(m),
            m->payload_len, (TCP_GET_SEQ(m) + m->payload_len), stream->last_ack);
    return 0;
}

uint32_t StreamTcpPacketStateFinWait2(mbuf_t *m, TcpSession *ssn, mbuf_t **reasm_m)
{
    TCPHdr *tcph = (TCPHdr *)(m->transport_header);

    if (ssn == NULL) {
        STREAM_SESSION_PARAM_ERR;
        return STREAMTCP_ERR;
    }

    if (tcph->th_flags & TH_RST) {
    #if 0
        if (!StreamTcpValidateRst(ssn, p))
            return -1;
    #endif

        StreamTcpPacketSetState(ssn, TCP_CLOSED);
        ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received state changed to TCP_CLOSED", ssn);

        if (PKT_IS_TOSERVER(m)) {
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(m));
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(m));

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, m, reasm_m);
        } else {
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(m));
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_SEQ(m));

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, m, reasm_m);
        }
    } else if (tcph->th_flags & TH_FIN) {
        if (PKT_IS_TOSERVER(m)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, m->payload_len,
                    TCP_GET_SEQ(m), TCP_GET_ACK(m));
            int retransmission = 0;

            if (SEQ_EQ(TCP_GET_SEQ(m), ssn->client.next_seq - 1) &&
                SEQ_EQ(TCP_GET_ACK(m), ssn->server.last_ack)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: retransmission", ssn);
                retransmission = 1;
            } else if (StreamTcpPacketIsRetransmission(&ssn->client, m)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(m), ssn->client.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(m), (ssn->client.last_ack + ssn->client.window)))
            {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ "
                        "%" PRIu32 " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(m), ssn->client.next_seq);
                STREAM_FIN2_FIN_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, m) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_FIN2_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_TIME_WAIT);
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->server.window = TCP_GET_WINDOW(m) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(m));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(m)))
                ssn->server.next_seq = TCP_GET_ACK(m);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, m, reasm_m);


        } else { /* implied to client */
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, m->payload_len,
                    TCP_GET_SEQ(m), TCP_GET_ACK(m));
            int retransmission = 0;

            if (SEQ_EQ(TCP_GET_SEQ(m), ssn->server.next_seq - 1) &&
                SEQ_EQ(TCP_GET_ACK(m), ssn->client.last_ack)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: retransmission", ssn);
                retransmission = 1;
            } else if (StreamTcpPacketIsRetransmission(&ssn->server, m)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(m), ssn->server.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(m), (ssn->server.last_ack + ssn->server.window)))
            {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ "
                        "%" PRIu32 " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(m), ssn->server.next_seq);
                STREAM_FIN2_FIN_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, m) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_FIN2_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_TIME_WAIT);
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(m) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(m));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(m)))
                ssn->client.next_seq = TCP_GET_ACK(m);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, m, reasm_m);

        }

    } else if (tcph->th_flags & TH_SYN) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn (%p): SYN pkt on FinWait2", ssn);
        STREAM_SHUTDOWN_SYN_RESEND;
        return STREAMTCP_ERR;
    } else if (tcph->th_flags & TH_ACK) {
        if (PKT_IS_TOSERVER(m)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, m->payload_len,
                    TCP_GET_SEQ(m), TCP_GET_ACK(m));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, m)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, m) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_FIN2_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(m) + m->payload_len, ssn->client.next_win) ||
                        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
                        (ssn->flags & STREAMTCP_FLAG_ASYNC))
                {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: seq %"PRIu32" in window, ssn->client.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(m), ssn->client.next_win);
                } else {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(m), ssn->client.next_seq);
                    STREAM_FIN2_ACK_WRONG_SEQ;
                    return STREAMTCP_ERR;
                }

                ssn->server.window = TCP_GET_WINDOW(m) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(m));

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(m))) {
                ssn->client.next_seq += m->payload_len;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.next_seq %" PRIu32 "",
                        ssn, ssn->client.next_seq);
            }

            //StreamTcpSackUpdatePacket(&ssn->server, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, m, reasm_m);


        } else { /* implied to client */
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, m->payload_len,
                    TCP_GET_SEQ(m), TCP_GET_ACK(m));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, m)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, m) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_FIN2_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(m) + m->payload_len, ssn->server.next_win) ||
                        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
                        (ssn->flags & STREAMTCP_FLAG_ASYNC))
                {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: seq %"PRIu32" in window, ssn->server.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(m), ssn->server.next_win);
                } else {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(m), ssn->server.next_seq);
                    STREAM_FIN2_ACK_WRONG_SEQ;
                    return STREAMTCP_ERR;
                }

                ssn->client.window = TCP_GET_WINDOW(m) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(m));

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(m))) {
                ssn->server.next_seq += m->payload_len;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.next_seq %" PRIu32 "",
                        ssn, ssn->server.next_seq);
            }

            //StreamTcpSackUpdatePacket(&ssn->client, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));


            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, m, reasm_m);
        }
    } else {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: default case", ssn);
    }

    *reasm_m = m;
    return STREAMTCP_OK;
}


uint32_t StreamTcpPacketStateFinWait1(mbuf_t *mbuf, TcpSession *ssn, mbuf_t **reasm_m)
{
    TCPHdr *tcph = (TCPHdr *)(mbuf->transport_header);

    if (ssn == NULL) {
        STREAM_SESSION_PARAM_ERR;
        return STREAMTCP_ERR;
    }

    if (tcph->th_flags & TH_RST) {
    #if 0
        if (!StreamTcpValidateRst(ssn, p))
            return -1;
    #endif
        StreamTcpPacketSetState(ssn, TCP_CLOSED);
        ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received state changed to TCP_CLOSED", ssn);

        if (PKT_IS_TOSERVER(mbuf)) {
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(mbuf));

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
        } else {
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(mbuf));
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_SEQ(mbuf));

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, mbuf, reasm_m);
        }
    }
    else if ((tcph->th_flags & (TH_FIN|TH_ACK)) == (TH_FIN|TH_ACK))
    {
        if (PKT_IS_TOSERVER(mbuf)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            } else if (SEQ_LT(TCP_GET_SEQ(mbuf), ssn->client.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(mbuf), (ssn->client.last_ack + ssn->client.window)))
            {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(mbuf), ssn->client.next_seq);
                STREAM_FIN1_FIN_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_FIN1_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_TIME_WAIT);
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_TIME_WAIT", ssn);
                ssn->server.window = TCP_GET_WINDOW(mbuf) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));


            /* Update the next_seq, in case if we have missed the client
                        packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(mbuf)))
                ssn->server.next_seq = TCP_GET_ACK(mbuf);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(mbuf))) {
                ssn->client.next_seq += mbuf->payload_len;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.next_seq %" PRIu32 "",
                        ssn, ssn->client.next_seq);
            }

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
        }else { /* implied to client */
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(mbuf), ssn->server.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(mbuf), (ssn->server.last_ack + ssn->server.window)))
            {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(mbuf), ssn->server.next_seq);
                STREAM_FIN1_FIN_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_FIN1_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_TIME_WAIT);
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(mbuf) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(mbuf));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(mbuf)))
                ssn->client.next_seq = TCP_GET_ACK(mbuf);

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(mbuf))) {
                ssn->server.next_seq += mbuf->payload_len;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.next_seq %" PRIu32 "",
                        ssn, ssn->server.next_seq);
            }

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, mbuf, reasm_m);
        }
    }
    else if (tcph->th_flags & TH_FIN)
    {
        if (PKT_IS_TOSERVER(mbuf)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(mbuf), ssn->client.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(mbuf), (ssn->client.last_ack + ssn->client.window)))
            {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(mbuf), ssn->client.next_seq);
                STREAM_FIN1_FIN_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_FIN1_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_CLOSING);
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_CLOSING", ssn);

                ssn->server.window = TCP_GET_WINDOW(mbuf) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(mbuf)))
                ssn->server.next_seq = TCP_GET_ACK(mbuf);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(mbuf))) {
                ssn->client.next_seq += mbuf->payload_len;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.next_seq %" PRIu32 "",
                        ssn, ssn->client.next_seq);
            }

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
        } else { /* implied to client */
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(mbuf), ssn->server.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(mbuf), (ssn->server.last_ack + ssn->server.window)))
            {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(mbuf), ssn->server.next_seq);
                STREAM_FIN1_FIN_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_FIN1_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_CLOSING);
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_CLOSING", ssn);

                ssn->client.window = TCP_GET_WINDOW(mbuf) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(mbuf));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(mbuf)))
                ssn->client.next_seq = TCP_GET_ACK(mbuf);

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(mbuf))) {
                ssn->server.next_seq += mbuf->payload_len;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.next_seq %" PRIu32 "",
                        ssn, ssn->server.next_seq);
            }

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, mbuf, reasm_m);
        }
    }
    else if (tcph->th_flags & TH_SYN)
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn (%p): SYN pkt on FinWait1", ssn);
        STREAM_SHUTDOWN_SYN_RESEND;
        return STREAMTCP_ERR;
    }
    else if (tcph->th_flags & TH_ACK)
    {
        if (PKT_IS_TOSERVER(mbuf)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_FIN1_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(mbuf) + mbuf->payload_len, ssn->client.next_win) ||
                        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
                         ssn->flags & STREAMTCP_FLAG_ASYNC)
                {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: seq %"PRIu32" in window, ssn->client.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(mbuf), ssn->client.next_win);

                    if (TCP_GET_SEQ(mbuf) == ssn->client.next_seq) {
                        StreamTcpPacketSetState(ssn, TCP_FIN_WAIT2);
                        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "ssn %p: state changed to TCP_FIN_WAIT2", ssn);
                    }
                } else {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(mbuf), ssn->client.next_seq);
                    STREAM_FIN1_ACK_WRONG_SEQ;
                    return STREAMTCP_ERR;
                }

                ssn->server.window = TCP_GET_WINDOW(mbuf) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(mbuf)))
                ssn->server.next_seq = TCP_GET_ACK(mbuf);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(mbuf))) {
                ssn->client.next_seq += mbuf->payload_len;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->client.next_seq %" PRIu32 "",
                        ssn, ssn->client.next_seq);
            }

        #if 0
            StreamTcpSackUpdatePacket(&ssn->server, p);
        #endif

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
        }
        else{/* implied to client */
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_FIN1_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(mbuf) + mbuf->payload_len, ssn->server.next_win) ||
                        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
                        (ssn->flags & STREAMTCP_FLAG_ASYNC))
                {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: seq %"PRIu32" in window, ssn->server.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(mbuf), ssn->server.next_win);

                    if (TCP_GET_SEQ(mbuf) == ssn->server.next_seq) {
                        StreamTcpPacketSetState(ssn, TCP_FIN_WAIT2);
                        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_FIN_WAIT2", ssn);
                    }
                } else {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(mbuf), ssn->server.next_seq);
                    STREAM_FIN1_ACK_WRONG_SEQ;
                    return STREAMTCP_ERR;
                }

                ssn->client.window = TCP_GET_WINDOW(mbuf) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(mbuf));

            /* Update the next_seq, in case if we have missed the client
                    packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(mbuf)))
                ssn->client.next_seq = TCP_GET_ACK(mbuf);

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(mbuf))) {
                ssn->server.next_seq += mbuf->payload_len;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: ssn->server.next_seq %" PRIu32 "",
                        ssn, ssn->server.next_seq);
            }

            //StreamTcpSackUpdatePacket(&ssn->client, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn,&ssn->server, mbuf, reasm_m);
        }
    }
    else
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn (%p): default case", ssn);
    }

    *reasm_m = mbuf;
    return STREAMTCP_OK;
}

uint32_t StreamTcpPacketStateCloseWait(mbuf_t *mbuf, TcpSession *ssn, mbuf_t **reasm_m)
{
    TCPHdr *tcph = (TCPHdr *)(mbuf->transport_header);

    if (ssn == NULL) {
        STREAM_SESSION_PARAM_ERR;
        return STREAMTCP_ERR;
    }

    if (PKT_IS_TOCLIENT(mbuf)) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));
    } else {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));
    }

    if (tcph->th_flags & TH_RST) {
    #if 0
        if (!StreamTcpValidateRst(ssn, p))
            return -1;
    #endif

        StreamTcpPacketSetState(ssn, TCP_CLOSED);
        ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received state changed to TCP_CLOSED", ssn);

        if (PKT_IS_TOSERVER(mbuf)) {
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(mbuf));

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
        } else {
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(mbuf));
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_SEQ(mbuf));

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, mbuf, reasm_m);
        }
    }
    else if (tcph->th_flags & TH_FIN) {
        if (PKT_IS_TOSERVER(mbuf)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (!retransmission) {
                if (SEQ_LT(TCP_GET_SEQ(mbuf), ssn->client.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(mbuf), (ssn->client.last_ack + ssn->client.window)))
                {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(mbuf), ssn->client.next_seq);
                    STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW;
                    return STREAMTCP_ERR;
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_CLOSEWAIT_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            /* don't update to LAST_ACK here as we want a toclient FIN for that */
            if (!retransmission)
                ssn->server.window = TCP_GET_WINDOW(mbuf) << ssn->server.wscale;

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(mbuf)))
                ssn->server.next_seq = TCP_GET_ACK(mbuf);


            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
        }
        else//to client
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (!retransmission) {
                if (SEQ_LT(TCP_GET_SEQ(mbuf), ssn->server.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(mbuf), (ssn->server.last_ack + ssn->server.window)))
                {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(mbuf), ssn->server.next_seq);
                    STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW;
                    return STREAMTCP_ERR;
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_CLOSEWAIT_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_LAST_ACK);
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_LAST_ACK", ssn);
                ssn->client.window = TCP_GET_WINDOW(mbuf) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(mbuf));

            /* Update the next_seq, in case if we have missed the client
                        packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(mbuf)))
                ssn->client.next_seq = TCP_GET_ACK(mbuf);


            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, mbuf, reasm_m);
        }
    }
    else if (tcph->th_flags & TH_SYN) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn (%p): SYN pkt on CloseWait", ssn);
        STREAM_SHUTDOWN_SYN_RESEND;
        return STREAMTCP_ERR;
    }
    else if (tcph->th_flags & TH_ACK) {
        if (PKT_IS_TOSERVER(mbuf)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (mbuf->payload_len > 0 && (SEQ_LEQ((TCP_GET_SEQ(mbuf) + mbuf->payload_len), ssn->client.last_ack))) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> retransmission", ssn);
                STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK;
                return STREAMTCP_ERR;

            } else if (SEQ_GT(TCP_GET_SEQ(mbuf), (ssn->client.last_ack + ssn->client.window))){
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(mbuf), ssn->client.next_seq);
                STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_CLOSEWAIT_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                ssn->server.window = TCP_GET_WINDOW(mbuf) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(mbuf)))
                ssn->server.next_seq = TCP_GET_ACK(mbuf);

            if (SEQ_EQ(TCP_GET_SEQ(mbuf),ssn->client.next_seq))
                ssn->client.next_seq += mbuf->payload_len;

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
        }
        else//to client
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (mbuf->payload_len > 0 && (SEQ_LEQ((TCP_GET_SEQ(mbuf) + mbuf->payload_len), ssn->server.last_ack))) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> retransmission", ssn);
                STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK;
                return STREAMTCP_ERR;

            } else if (SEQ_GT(TCP_GET_SEQ(mbuf), (ssn->server.last_ack + ssn->server.window))){
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(mbuf), ssn->server.next_seq);
                STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_CLOSEWAIT_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                ssn->client.window = TCP_GET_WINDOW(mbuf) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(mbuf));

            /* Update the next_seq, in case if we have missed the client
                        packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(mbuf)))
                ssn->client.next_seq = TCP_GET_ACK(mbuf);

            if (SEQ_EQ(TCP_GET_SEQ(mbuf),ssn->server.next_seq))
                ssn->server.next_seq += mbuf->payload_len;

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, mbuf, reasm_m);
        }
    }
    else
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: default case", ssn);
    }

    *reasm_m = mbuf;
    return STREAMTCP_OK;
}

/**
 *  \brief  Function to handle the TCP_LAST_ACK state. Upon arrival of ACK
 *          the connection goes to TCP_CLOSED state and stream memory is
 *          returned back to pool. The state is possible only for server host.
 */
uint32_t StreamTcpPacketStateLastAck(mbuf_t *mbuf, TcpSession *ssn, mbuf_t **reasm_m)
{
    TCPHdr *tcph = (TCPHdr *)(mbuf->transport_header);

    if (ssn == NULL) {
        STREAM_SESSION_PARAM_ERR;
        return STREAMTCP_ERR;
    }

    if (tcph->th_flags & TH_RST) {
    #if 0
        if (!StreamTcpValidateRst(ssn, p))
             return -1;
    #endif
         StreamTcpPacketSetState(ssn, TCP_CLOSED);
         ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
         ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
         LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received state changed to TCP_CLOSED", ssn);

         if (PKT_IS_TOSERVER(mbuf)) {
             StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));
             StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(mbuf));

             return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
         } else {
             StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(mbuf));
             StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_SEQ(mbuf));

             return StreamTcpReassembleHandleSegment(ssn, &ssn->server, mbuf, reasm_m);
         }
    }
    else if (tcph->th_flags & TH_FIN)
    {
        /** \todo  will sync with suricata*/
    }
    else if (tcph->th_flags & TH_SYN)
    {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn (%p): SYN pkt on LastAck", ssn);
        STREAM_SHUTDOWN_SYN_RESEND;
        return STREAMTCP_ERR;
    }
    else if (tcph->th_flags & TH_ACK)
    {
        if (PKT_IS_TOSERVER(mbuf))
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, mbuf->payload_len,
                    TCP_GET_SEQ(mbuf), TCP_GET_ACK(mbuf));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, mbuf)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (TCP_GET_SEQ(mbuf) != ssn->client.next_seq && TCP_GET_SEQ(mbuf) != ssn->client.next_seq + 1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(mbuf), ssn->client.next_seq);
                STREAM_LASTACK_ACK_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, mbuf) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_LASTACK_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState( ssn, TCP_CLOSED);
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_CLOSED", ssn);
                ssn->server.window = TCP_GET_WINDOW(mbuf) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(mbuf));

            /* Update the next_seq, in case if we have missed the client
                        packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(mbuf)))
                ssn->server.next_seq = TCP_GET_ACK(mbuf);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, mbuf, reasm_m);
        }
    }else {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: default case", ssn);
    }

    *reasm_m = mbuf;
    return STREAMTCP_OK;
}

/**
 *  \brief  Function to handle the TCP_CLOSING state. Upon arrival of ACK
 *          the connection goes to TCP_TIME_WAIT state. The state has been
 *          reached as both end application has been closed.
 */
static uint32_t StreamTcpPacketStateClosing(mbuf_t *m, TcpSession *ssn, mbuf_t **reasm_m)
{
    TCPHdr *tcph = (TCPHdr *)(m->transport_header);

    if (ssn == NULL) {
        STREAM_SESSION_PARAM_ERR;
        return STREAMTCP_ERR;
    }

    if (tcph->th_flags & TH_RST) {
    #if 0
        if (!StreamTcpValidateRst(ssn, p))
            return -1;
    #endif
        StreamTcpPacketSetState(ssn, TCP_CLOSED);
        ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received state changed to TCP_CLOSED",
                ssn);

        if (PKT_IS_TOSERVER(m)) {
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(m));
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(m));

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, m, reasm_m);
        } else {
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(m));
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_SEQ(m));

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, m, reasm_m);
        }
    } else if (tcph->th_flags & TH_SYN) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn (%p): SYN pkt on Closing", ssn);
        STREAM_SHUTDOWN_SYN_RESEND;
        return STREAMTCP_ERR;
    } else if (tcph->th_flags & TH_ACK) {
        if (PKT_IS_TOSERVER(m)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, m->payload_len,
                    TCP_GET_SEQ(m), TCP_GET_ACK(m));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, m)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (TCP_GET_SEQ(m) != ssn->client.next_seq) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(m), ssn->client.next_seq);
                STREAM_CLOSING_ACK_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, m) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_CLOSING_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_TIME_WAIT);
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(m) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(m));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(m)))
                ssn->server.next_seq = TCP_GET_ACK(m);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, m, reasm_m);
        } else { /* implied to client */
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, m->payload_len,
                    TCP_GET_SEQ(m), TCP_GET_ACK(m));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, m)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (TCP_GET_SEQ(m) != ssn->server.next_seq) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(m), ssn->server.next_seq);
                STREAM_CLOSING_ACK_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, m) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_CLOSING_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_TIME_WAIT);
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(m) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(m));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(m)))
                ssn->client.next_seq = TCP_GET_ACK(m);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nStreamTcpPacketStateClosing (%p): =+ next SEQ "
                "%" PRIu32 ", last ACK %" PRIu32 "", ssn,
                ssn->server.next_seq, ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, m, reasm_m);
        }
    } else {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: default case", ssn);
    }

    *reasm_m = m;
    return STREAMTCP_OK;
}

/**
 *  \brief  Function to handle the TCP_TIME_WAIT state. Upon arrival of ACK
 *          the connection goes to TCP_CLOSED state and stream memory is
 *          returned back to pool.
 */
static uint32_t StreamTcpPacketStateTimeWait(mbuf_t *m, TcpSession *ssn, mbuf_t **reasm_m)
{
    TCPHdr *tcph = (TCPHdr *)(m->transport_header);

    if (ssn == NULL) {
        STREAM_SESSION_PARAM_ERR;
        return STREAMTCP_ERR;
    }

    if (tcph->th_flags & TH_RST) {
    #if 0
        if (!StreamTcpValidateRst(ssn, m))
            return -1;
    #endif

        StreamTcpPacketSetState(ssn, TCP_CLOSED);
        ssn->server.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        ssn->client.flags |= STREAMTCP_STREAM_FLAG_CLOSE_INITIATED;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: Reset received state changed to TCP_CLOSED",
                ssn);

        if (PKT_IS_TOSERVER(m)) {
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(m));
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(m));


            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, m, reasm_m);
        } else {
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(m));
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_SEQ(m));

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, m, reasm_m);
        }
    } else if (tcph->th_flags & TH_FIN) {
        /** \todo  will sync with suricata*/
    } else if (tcph->th_flags & TH_SYN) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn (%p): SYN pkt on TimeWait", ssn);
        STREAM_SHUTDOWN_SYN_RESEND;
        return STREAMTCP_ERR;
    } else if (tcph->th_flags & TH_ACK) {
        if (PKT_IS_TOSERVER(m)) {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, m->payload_len,
                    TCP_GET_SEQ(m), TCP_GET_ACK(m));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, m)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (TCP_GET_SEQ(m) != ssn->client.next_seq && TCP_GET_SEQ(m) != ssn->client.next_seq+1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(m), ssn->client.next_seq);
                STREAM_TIMEWAIT_ACK_WRONG_SEQ;
                return STREAMTCP_ERR;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, m) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_TIMEWAIT_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_CLOSED);
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_CLOSED", ssn);

                ssn->server.window = TCP_GET_WINDOW(m) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(m));

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(m)))
                ssn->server.next_seq = TCP_GET_ACK(m);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->client, m, reasm_m);
        } else {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, m->payload_len,
                    TCP_GET_SEQ(m), TCP_GET_ACK(m));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, m)) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (TCP_GET_SEQ(m) != ssn->server.next_seq && TCP_GET_SEQ(m) != ssn->server.next_seq+1) {
                if (m->payload_len > 0 && TCP_GET_SEQ(m) == ssn->server.last_ack) {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> retransmission", ssn);
                    *reasm_m = m;
                    return STREAMTCP_OK;
                } else {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(m), ssn->server.next_seq);
                    STREAM_TIMEWAIT_ACK_WRONG_SEQ;
                    return STREAMTCP_ERR;
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, m) == -1) {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: rejecting because of invalid ack value", ssn);
                STREAM_TIMEWAIT_INVALID_ACK;
                return STREAMTCP_ERR;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(ssn, TCP_CLOSED);
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: state changed to TCP_CLOSED", ssn);

                ssn->client.window = TCP_GET_WINDOW(m) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(m));


            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(m)))
                ssn->client.next_seq = TCP_GET_ACK(m);

            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            return StreamTcpReassembleHandleSegment(ssn, &ssn->server, m, reasm_m);
        }
    } else {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nssn %p: default case", ssn);
    }

    *reasm_m = m;
    return STREAMTCP_OK;
}
/**
 *  \retval 1 packet is a keep alive ACK pkt
 *  \retval 0 packet is not a keep alive ACK pkt
 */
static int StreamTcpPacketIsKeepAliveACK(TcpSession *ssn, mbuf_t *m) {
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    TCPHdr *tcph = (TCPHdr *)(m->transport_header);

    /* should get a normal ACK to a Keep Alive */
    if (m->payload_len > 0)
        return 0;

    if ((tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (TCP_GET_WINDOW(m) == 0)
        return 0;

    if (PKT_IS_TOSERVER(m)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(m);
    ack = TCP_GET_ACK(m);

    pkt_win = TCP_GET_WINDOW(m) << ostream->wscale;
    if (pkt_win != ostream->window)
        return 0;

    if ((ostream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE) && ack == ostream->last_ack && seq == stream->next_seq) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\npacket is TCP keep-aliveACK");
        ostream->flags &= ~STREAMTCP_STREAM_FLAG_KEEPALIVE;
        return 1;
    }
    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nseq %u (%u), ack %u (%u) FLAG_KEEPALIVE: %s", seq, stream->next_seq, ack, ostream->last_ack,
            ostream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE ? "set" : "not set");
    return 0;
}

/**
 *  \retval 1 packet is a keep alive pkt
 *  \retval 0 packet is not a keep alive pkt
 */
static int StreamTcpPacketIsKeepAlive(TcpSession *ssn, mbuf_t *m) {
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;

    TCPHdr *tcph = (TCPHdr *)(m->transport_header);

    /*
       rfc 1122:
       An implementation SHOULD send a keep-alive segment with no
       data; however, it MAY be configurable to send a keep-alive
       segment containing one garbage octet, for compatibility with
       erroneous TCP implementations.
     */
    if (m->payload_len > 1)
        return 0;

    if ((tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0) {
        return 0;
    }

    if (PKT_IS_TOSERVER(m)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(m);
    ack = TCP_GET_ACK(m);

    if (ack == ostream->last_ack && seq == (stream->next_seq - 1)) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "packet is TCP keep-alive");
        stream->flags |= STREAMTCP_STREAM_FLAG_KEEPALIVE;
        return 1;
    }

    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "seq %u (%u), ack %u (%u)", seq,  (stream->next_seq - 1), ack, ostream->last_ack);
    return 0;
}

static void StreamTcpClearKeepAliveFlag(TcpSession *ssn, mbuf_t *m) {
    TcpStream *stream = NULL;

    if (PKT_IS_TOSERVER(m)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    if (stream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE) {
        stream->flags &= ~STREAMTCP_STREAM_FLAG_KEEPALIVE;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "FLAG_KEEPALIVE cleared");
    }
}
/**
 *  \retval 1 packet is a window update pkt
 *  \retval 0 packet is not a window update pkt
 */
static int StreamTcpPacketIsWindowUpdate(TcpSession *ssn, mbuf_t *m) {
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    TCPHdr *tcph = (TCPHdr *)(m->transport_header);

    if (ssn->state < TCP_ESTABLISHED)
        return 0;

    if (m->payload_len > 0)
        return 0;

    if ((tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (TCP_GET_WINDOW(m) == 0)
        return 0;

    if (PKT_IS_TOSERVER(m)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(m);
    ack = TCP_GET_ACK(m);

    pkt_win = TCP_GET_WINDOW(m) << ostream->wscale;
    if (pkt_win == ostream->window)
        return 0;

    if (ack == ostream->last_ack && seq == stream->next_seq) {
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\npacket is TCP window update");
        return 1;
    }
    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nseq %u (%u), ack %u (%u)", seq, stream->next_seq, ack, ostream->last_ack);
    return 0;
}

/**
 *  Try to detect packets doing bad window updates
 *
 *  See bug 1238.
 *
 *  Find packets that are unexpected, and shrink the window to the point
 *  where the packets we do expect are rejected for being out of window.
 *
 *  The logic we use here is:
 *  - packet seq > next_seq
 *  - packet acq > next_seq (packet acks unseen data)
 *  - packet shrinks window more than it's own data size
 *    (in case of no data, any shrinking is rejected)
 *
 *  Packets coming in after packet loss can look quite a bit like this.
 */
static int StreamTcpPacketIsBadWindowUpdate(TcpSession *ssn, mbuf_t *m)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    TCPHdr *tcph = (TCPHdr *)(m->transport_header);

    if (ssn->state < TCP_ESTABLISHED)
        return 0;

    if ((tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (PKT_IS_TOSERVER(m)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(m);
    ack = TCP_GET_ACK(m);

    pkt_win = TCP_GET_WINDOW(m) << ostream->wscale;

    if (pkt_win < ostream->window) {
        uint32_t diff = ostream->window - pkt_win;
        if (diff > m->payload_len &&
                SEQ_GT(ack, ostream->next_seq) &&
                SEQ_GT(seq, stream->next_seq))
        {
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "pkt_win %u, stream win %u, diff %u, dsize %u",
                pkt_win, ostream->window, diff, m->payload_len);
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "pkt_win %u, stream win %u",
                pkt_win, ostream->window);
            LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "seq %u ack %u ostream->next_seq %u stream->last_ack %u, diff %u (%u)",
                seq, ack, ostream->next_seq, stream->last_ack,
                ostream->next_seq - ostream->last_ack, stream->next_seq - stream->last_ack);

            STREAM_PKT_BAD_WINDOW_UPDATE;
            return 1;
        }

    }
    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "seq %u (%u), ack %u (%u)", seq, stream->next_seq, ack, ostream->last_ack);
    return 0;
}

/*
  * stream tcp enter point
  * input:   mbuf:   input mbuf
  * output: STREAMTCP_OK    --->   reasm_mbuf can go ahead, maybe reassemble successed
  *            STREAMTCP_ERR   --->   detect error, should be drop
  *            STREAMTCP_CACHE ---> cached, do next loop
  *
  */
uint32_t StreamTcpPacket(mbuf_t *mbuf, mbuf_t **reasm_m)
{
    TcpSession *ssn = (TcpSession *)((flow_item_t *)mbuf->flow)->protoctx;

    TCPHdr *tcph = (TCPHdr *)(mbuf->transport_header);

    /* update counters */
    if ((tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        STREAM_SYN_ACK_COUNT;
    }
    else if (tcph->th_flags & (TH_SYN)) {
        STREAM_SYN_COUNT;
    }
    if (tcph->th_flags & (TH_RST)){
        STREAM_RST_COUNT;
    }

    /* broken TCP http://ask.wireshark.org/questions/3183/acknowledgment-number-broken-tcp-the-acknowledge-field-is-nonzero-while-the-ack-flag-is-not-set */
    if (!(tcph->th_flags & TH_ACK) && TCP_GET_ACK(mbuf) != 0) {
        /*update conters*/
        STREAM_PKT_BROKEN_ACK;
    }

    if (ssn == NULL || ssn->state == TCP_NONE)
    {
        return StreamTcpPacketStateNone(mbuf, ssn, reasm_m);
    }
    else
    {
        /*
              *  check if the packet is in right direction, when we missed the
              *  SYN packet and picked up midstream session.
              */
        if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK)
            StreamTcpPacketSwitchDir(ssn, mbuf);

        if (StreamTcpPacketIsKeepAlive(ssn, mbuf) == 1) {
            *reasm_m = mbuf;
            return STREAMTCP_OK;
        }

        if (StreamTcpPacketIsKeepAliveACK(ssn, mbuf) == 1) {
            StreamTcpClearKeepAliveFlag(ssn, mbuf);
            *reasm_m = mbuf;
            return STREAMTCP_OK;
        }

        StreamTcpClearKeepAliveFlag(ssn, mbuf);

        /*
              * if packet is not a valid window update, check if it is perhaps
              * a bad window update that we should ignore (and alert on)
              */
    #if 1
        if (StreamTcpPacketIsWindowUpdate(ssn, mbuf) == 0)
        {
            if (StreamTcpPacketIsBadWindowUpdate(ssn, mbuf))
            {
                *reasm_m = mbuf;
                return STREAMTCP_OK;
            }
        }
    #endif

        switch (ssn->state) {
            case TCP_SYN_SENT:
            {
                return StreamTcpPacketStateSynSent(mbuf, ssn, reasm_m);
            }
            case TCP_SYN_RECV:
            {
                return StreamTcpPacketStateSynRecv(mbuf, ssn, reasm_m);
            }
            case TCP_ESTABLISHED:
            {
                return StreamTcpPacketStateEstablished(mbuf, ssn, reasm_m);
            }
            case TCP_CLOSE_WAIT:
            {
                return StreamTcpPacketStateCloseWait(mbuf, ssn, reasm_m);
                            }
            case TCP_FIN_WAIT1:
            {
                return StreamTcpPacketStateFinWait1(mbuf, ssn, reasm_m);
            }
            case TCP_FIN_WAIT2:
            {
                return StreamTcpPacketStateFinWait2(mbuf, ssn, reasm_m);
            }
            case TCP_LAST_ACK:
            {
                return StreamTcpPacketStateLastAck(mbuf, ssn, reasm_m);
            }
            case TCP_CLOSING:
            {
                return StreamTcpPacketStateClosing(mbuf, ssn, reasm_m);
            }
            case TCP_TIME_WAIT:
            {
                return StreamTcpPacketStateTimeWait(mbuf, ssn, reasm_m);
            }
            case TCP_CLOSED:
            {
               /* TCP session memory is not returned to pool until timeout.
                         * If in the mean time we receive any other session from
                         * the same client reusing same port then we switch back to
                         * tcp state none, but only on a valid SYN that is not a
                         * resend from our previous session.
                         *
                         * We also check it's not a SYN/ACK, all other SYN pkt
                         * validation is done at StreamTcpPacketStateNone();
                         */
                if (PKT_IS_TOSERVER(mbuf) && (tcph->th_flags & TH_SYN) &&
                    !(tcph->th_flags & TH_ACK) &&
                    !(SEQ_EQ(ssn->client.isn, TCP_GET_SEQ(mbuf))))
                {
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\nreusing closed TCP session");

                    /* return segments */
                    StreamTcpReturnStreamSegments(&ssn->client);
                    StreamTcpReturnStreamSegments(&ssn->server);
                #if 0
                    /* free SACK list */
                    StreamTcpSackFreeList(&ssn->client);
                    StreamTcpSackFreeList(&ssn->server);
                    /* reset the app layer state */
                    FlowCleanupAppLayer(p->flow);
                #endif
                    ssn->state = 0;
                    ssn->flags = 0;
                    ssn->client.flags = 0;
                    ssn->server.flags = 0;

                    /* set state the NONE, also pulls flow out of closed queue */
                    StreamTcpPacketSetState(ssn, TCP_NONE);
                #if 0
                    p->flow->alproto_ts = p->flow->alproto_tc = p->flow->alproto = ALPROTO_UNKNOWN;
                    p->flow->data_al_so_far[0] = p->flow->data_al_so_far[1] = 0;
                    ssn->data_first_seen_dir = 0;
                    p->flow->flags &= (~FLOW_TS_PM_ALPROTO_DETECT_DONE &
                                       ~FLOW_TS_PP_ALPROTO_DETECT_DONE &
                                       ~FLOW_TC_PM_ALPROTO_DETECT_DONE &
                                       ~FLOW_TC_PP_ALPROTO_DETECT_DONE);
                #endif
                    return StreamTcpPacketStateNone(mbuf, ssn, reasm_m);
                } else {//spurious retransmission
                    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\npacket received on closed state");
                }
                break;
            }
            default:
            {
                LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\npacket received on default state");
                break;
            }
        }

    }

    *reasm_m = mbuf;
    return STREAMTCP_OK;
}



int StreamTcp(mbuf_t *mbuf, mbuf_t **reasm_m)
{
    if(!PKT_IS_TCP(mbuf))
    {
        *reasm_m = mbuf;
        return STREAMTCP_OK;
    }

    LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "\n=================>enter streamtcp module\n");
    if(mbuf->flow == NULL)
    {
        *reasm_m = mbuf;
        LOGDBG(SEC_STREAMTCP_TRACK_DBG_BIT, "mbuf own flow node is null\n");
        return STREAMTCP_OK;
    }

    return StreamTcpPacket(mbuf, reasm_m);
}


uint32_t StreamTcpInit(void)
{
    uint32_t ret;

    ret = StreamTcpSessionInit();
    if(SEC_OK != ret)
        return SEC_NO;

    return SEC_OK;
}


