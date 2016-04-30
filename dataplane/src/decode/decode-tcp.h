#ifndef __DECODE_TCP_H__
#define __DECODE_TCP_H__


#define TCP_HEADER_LEN                       20
#define TCP_OPTLENMAX                        40
#define TCP_OPTMAX                           20 /* every opt is at least 2 bytes
                                                 * (type + len), except EOL and NOP */


typedef struct TCPHdr_
{
    uint16_t th_sport;  /**< source port */
    uint16_t th_dport;  /**< destination port */
    uint32_t th_seq;    /**< sequence number */
    uint32_t th_ack;    /**< acknowledgement number */
    uint8_t th_offx2;   /**< offset and reserved */
    uint8_t th_flags;   /**< pkt flags */
    uint16_t th_win;    /**< pkt window */
    uint16_t th_sum;    /**< checksum */
    uint16_t th_urp;    /**< urgent pointer */
} TCPHdr;

typedef struct TCPOpt_ {
    uint8_t type;
    uint8_t len;
    uint8_t *data;
} TCPOpt;





typedef struct TCPVars_
{
    //uint8_t tcp_opt_cnt;
    //TCPOpt tcp_opts[TCP_OPTMAX];
    TCPOpt tcp_opts[1];

    /* ptrs to commonly used and needed opts */
    //TCPOpt *ts;
    //TCPOpt *sack;
    //TCPOpt *sackok;
    TCPOpt *ws;
    //TCPOpt *mss;
} TCPVars;


/* tcp option codes */
#define TCP_OPT_EOL                          0x00
#define TCP_OPT_NOP                          0x01
#define TCP_OPT_MSS                          0x02
#define TCP_OPT_WS                           0x03
#define TCP_OPT_SACKOK                       0x04
#define TCP_OPT_SACK                         0x05
#define TCP_OPT_TS                           0x08

#define TCP_OPT_SACKOK_LEN                   2
#define TCP_OPT_WS_LEN                       3
#define TCP_OPT_TS_LEN                       10
#define TCP_OPT_MSS_LEN                      4
#define TCP_OPT_SACK_MIN_LEN                 10 /* hdr 2, 1 pair 8 = 10 */
#define TCP_OPT_SACK_MAX_LEN                 34 /* hdr 2, 4 pair 32= 34 */

/** Max valid wscale value. */
#define TCP_WSCALE_MAX                       14

#define TCP_OPTS                             tcpvars.tcp_opts
#define TCP_OPTS_CNT                         tcpvars.tcp_opt_cnt


/* TCP flags */

#define TH_FIN                               0x01
#define TH_SYN                               0x02
#define TH_RST                               0x04
#define TH_PUSH                              0x08
#define TH_ACK                               0x10
#define TH_URG                               0x20

#define TCP_GET_RAW_OFFSET(tcph)             (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_GET_RAW_SRC_PORT(tcph)           ((tcph)->th_sport)
#define TCP_GET_RAW_DST_PORT(tcph)           ((tcph)->th_dport)


#define TCP_GET_RAW_SEQ(tcph)                ((tcph)->th_seq)
#define TCP_GET_RAW_ACK(tcph)                ((tcph)->th_ack)
#define TCP_GET_RAW_WINDOW(tcph)             ((tcph)->th_win)

#define TCP_IS_SYN(p)   (((TCPHdr *)((p)->transport_header))->th_flags & TH_SYN )

#define TCP_GET_OFFSET(p)                    TCP_GET_RAW_OFFSET((TCPHdr *)((p)->transport_header))
#define TCP_GET_HLEN(p)                      (TCP_GET_OFFSET((p)) << 2)
#define TCP_GET_SRC_PORT(p)                  TCP_GET_RAW_SRC_PORT((TCPHdr *)((p)->transport_header))
#define TCP_GET_DST_PORT(p)                  TCP_GET_RAW_DST_PORT((TCPHdr *)((p)->transport_header))


#define TCP_GET_SEQ(p)                       TCP_GET_RAW_SEQ((TCPHdr *)((p)->transport_header))
#define TCP_GET_ACK(p)                       TCP_GET_RAW_ACK((TCPHdr *)((p)->transport_header))
#define TCP_GET_WINDOW(p)                    TCP_GET_RAW_WINDOW((TCPHdr *)((p)->transport_header))


#define TCP_GET_WSCALE(p)                    ((p)->tcpvars.ws ? (((*(uint8_t *)(p)->tcpvars.ws->data) <= TCP_WSCALE_MAX) ? (*(uint8_t *)((p)->tcpvars.ws->data)) : 0) : 0)


#define TCP_SET_SEQ(p, v)     (((TCPHdr *)((p)->transport_header))->th_seq = v)

#define PKT_IS_TCP(m)       (((m)->proto == PROTO_TCP))


#endif
