#ifndef __OCT_RXTX_H__
#define __OCT_RXTX_H__

#include <oct-common.h>
#include <mbuf.h>
#include <oct-port.h>
#include <oct-api.h>

#define OCT_PKO_TX_DESC_NUM 64

#define OCT_TX_DESC_NAME "oct-tx-desc"


#define FROMPORT  0
#define FROMLINUX 1

typedef struct
{
    uint8_t mem_ref;
    void   *mb;
}oct_pko_pend_tx_done_t;

typedef struct
{
    uint16_t consumer;
    uint16_t producer;
    uint16_t tx_entries;
    oct_pko_pend_tx_done_t pend_tx_done[OCT_PKO_TX_DESC_NUM];
}tx_done_t;


typedef struct
{
    tx_done_t tx_done[OCT_PHY_PORT_MAX];
}oct_softx_stat_t;



typedef union {
    uint64_t        u64;
    struct {
        uint64_t    resvd : 28;
        uint64_t    ptr   : 36;   /* Pointer of byte for TX-DONE */
    }s;
}cvmx_pko_command_word2_t;




static inline void
oct_packet_free(cvmx_wqe_t * wq, int wqepool)
{
    cvmx_helper_free_packet_data(wq);
    oct_fpa_free(wq, wqepool, 0);
}


extern uint8_t fw_table[];
static inline uint8_t
oct_tx_port_get(uint8_t inp)
{
    return fw_table[inp];
}



extern uint32_t oct_tx_entries[];
extern uint32_t oct_directfw;
extern uint32_t oct_directfw_sleeptime;

extern uint8_t fw_table[];


extern int oct_rxtx_init(void);
extern int oct_rxtx_get(void);
extern void oct_tx_done_check();
extern void oct_tx_process_sw(mbuf_t *mbuf, uint8_t outport);
extern void oct_tx_process_hw(mbuf_t *mbuf, uint32_t outport);
extern uint32_t oct_pow_se2linux(mbuf_t *m);
extern void *oct_rx_process_work(cvmx_wqe_t *wq, uint8_t src);
extern void oct_rxtx_Release();
extern void oct_directfw_set();
extern void oct_tx_process_hw_work(cvmx_wqe_t *work, uint32_t outport);

#endif
