#include "oct-rxtx.h"
#include <decode-statistic.h>
#include <mbuf.h>
#include <sec-debug.h>
#include <oct-port.h>
#include "oct-time.h"
#include <oct-api.h>
#include <decode.h>
#include <oct-init.h>



uint8_t fw_table[OCT_PHY_PORT_MAX] = {OCT_PHY_PORT_FIRST,
                                        OCT_PHY_PORT_FIRST,
                                        OCT_PHY_PORT_FOURTH,
                                        OCT_PHY_PORT_THIRD };



uint32_t oct_tx_entries[CPU_HW_RUNNING_MAX] = {0};
oct_softx_stat_t *oct_stx[CPU_HW_RUNNING_MAX];

uint32_t oct_directfw = 1;
uint32_t oct_directfw_sleeptime = 0;

extern void Frag_defrag_sendfrags(mbuf_t *mb);


void oct_directfw_set()
{
    uint32_t port;
    oct_directfw = srv_dp_sync->dp_directfw_able;
    oct_directfw_sleeptime = srv_dp_sync->dp_directfw_sleep_time;
    if(oct_directfw)
    {
        for(port = OCT_PHY_PORT_FIRST; port < OCT_PHY_PORT_MAX; port++)
        {
            cvmx_pip_port_tag_cfg_t tag_config;
            /*config group*/
            tag_config.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(port));
            tag_config.s.grp = FROM_INPUT_PORT_GROUP;
            if( running_core_num == 4)
            {
                /*config tuple of hash value*/
                tag_config.cn70xx.ip4_src_flag = 0;
                tag_config.cn70xx.ip4_dst_flag = 0;
                tag_config.cn70xx.ip4_sprt_flag = 0;
                tag_config.cn70xx.ip4_dprt_flag = 0;
                tag_config.cn70xx.ip4_pctl_flag = 0;

                tag_config.cn70xx.grptag = 0;
                tag_config.cn70xx.grptagmask = 0;
                tag_config.cn70xx.grptagbase = 0;
            }

            cvmx_write_csr(CVMX_PIP_PRT_TAGX(port), tag_config.u64);

            cvmx_wait_usec(1000);
        }
    }
    else
    {
        for(port = OCT_PHY_PORT_FIRST; port < OCT_PHY_PORT_MAX; port++)
        {
            cvmx_pip_port_tag_cfg_t tag_config;
            /*config group*/
            tag_config.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(port));
            tag_config.s.grp = FROM_INPUT_PORT_GROUP;
            if( running_core_num == 4)
            {
                /*config tuple of hash value*/
                tag_config.cn70xx.ip4_src_flag = 1;
                tag_config.cn70xx.ip4_dst_flag = 1;
                tag_config.cn70xx.ip4_sprt_flag = 1;
                tag_config.cn70xx.ip4_dprt_flag = 1;
                tag_config.cn70xx.ip4_pctl_flag = 1;

                tag_config.cn70xx.grptag = 1;
                tag_config.cn70xx.grptagmask = 0xc;
                tag_config.cn70xx.grptagbase = 1;
            }

            cvmx_write_csr(CVMX_PIP_PRT_TAGX(port), tag_config.u64);

            cvmx_wait_usec(1000);
        }
    }

}



uint32_t oct_pow_se2linux(mbuf_t *m)
{
    cvmx_wqe_t *work = NULL;
	uint8_t input = 0;
	uint8_t linux_group = 0;

    /* Get a work queue entry */
    work = cvmx_fpa_alloc(CVMX_FPA_WQE_POOL);
    if(NULL == work)
    {
        return SEC_NO;
    }

    memset(work, 0, sizeof(cvmx_wqe_t));

    work->packet_ptr.u64 = m->packet_ptr.u64;
    work->word2.s.bufs = 1;

    input = m->input_port;

	if(input == 0)
	{
		linux_group = POW0_LINUX_GROUP;
	}
	else if (input == 1)
	{
		linux_group = POW1_LINUX_GROUP;
	}
	else if (input == 2)
	{
		linux_group = POW2_LINUX_GROUP;
	}
	else if (input == 3)
	{
		linux_group = POW3_LINUX_GROUP;
	}
	else
	{
		return SEC_NO;
	}

    cvmx_wqe_set_len(work, m->pkt_totallen);
    cvmx_wqe_set_port(work, m->input_port);
    cvmx_wqe_set_grp(work, linux_group);

    cvmx_pow_work_submit(work, 0, 0, 0, linux_group);

    MBUF_FREE(m);

    return SEC_OK;
}



/*
 *  alloc a mbuf which can be used to describe the packet
 *  if work is error , return NULL
 *  then free wqe, reurn mbuf
 */
void *
oct_rx_process_work(cvmx_wqe_t *wq, uint8_t src)
{
    void *pkt_virt;
    mbuf_t *m;

    if (wq->word2.s.rcv_error || oct_wqe_get_bufs(wq) > 1){
        /*
              *  Work has error, so drop
              *  and now do not support jumbo packet
              */
        oct_packet_free(wq, wqe_pool);
        if(FROMLINUX == src)
        {
            STAT_RECV_FROMLINUX_ERR;
        }
        else
        {
            STAT_RECV_FROMHWPORT_ERR;
        }

        return NULL;
    }

    pkt_virt = (void *) cvmx_phys_to_ptr(wq->packet_ptr.s.addr);
    if(NULL == pkt_virt)
    {
        STAT_RECV_ADDR_ERR;
        return NULL;
    }

    LOGDBG(SEC_PACKET_DUMP, "Received %u byte packet.\n", oct_wqe_get_len(wq));
    LOGDBG(SEC_PACKET_DUMP, "Processing packet\n");
    if(srv_dp_sync->dp_debugprint & SEC_PACKET_DUMP)
    {
        cvmx_helper_dump_packet(wq);
    }

    m = (mbuf_t *)MBUF_ALLOC();

    memset((void *)m, 0, sizeof(mbuf_t));

    m->magic_flag = MBUF_MAGIC_NUM;
    PKTBUF_SET_HW(m);

    m->packet_ptr.u64 = wq->packet_ptr.u64;

    m->input_port = oct_wqe_get_port(wq);

    m->pkt_totallen = oct_wqe_get_len(wq);
    m->pkt_ptr = pkt_virt;

    m->tag = cvmx_wqe_get_tag(wq);

    m->timestamp = OCT_TIME_SECONDS_SINCE1970;

    oct_fpa_free(wq, wqe_pool, 0);

    if(FROMPORT == src)
    {
        STAT_RECV_PC_ADD;
        STAT_RECV_PB_ADD(m->pkt_totallen);
    }

    if(FROMLINUX == src)
    {
        STAT_RECV_FROMLINUX_OK;
    }
    else
    {
        STAT_RECV_FROMHWPORT_OK;
    }

    return (void *)m;
}


void oct_tx_done_check()
{
    int port;
    uint16_t consumer;
    uint16_t producer;
    oct_pko_pend_tx_done_t *pend_tx_done;
    oct_softx_stat_t *oct_stx_local = oct_stx[LOCAL_CPU_ID];

    for( port = 0; port < OCT_PHY_PORT_MAX; port++ )
    {
        if(oct_stx_local->tx_done[port].tx_entries)
        {
            consumer = oct_stx_local->tx_done[port].consumer;
            producer = oct_stx_local->tx_done[port].producer;

            while(consumer != producer)
            {
                pend_tx_done = &(oct_stx_local->tx_done[port].pend_tx_done[consumer]);
                if( 0xFF == pend_tx_done->mem_ref ) {
                    break;
                }

                /*Free the packet*/
                PACKET_DESTROY_ALL(pend_tx_done->mb);

                consumer = (consumer + 1) & (OCT_PKO_TX_DESC_NUM - 1);
                oct_stx_local->tx_done[port].tx_entries--;
                oct_tx_entries[LOCAL_CPU_ID]--;
            }
            oct_stx_local->tx_done[port].consumer = consumer;
        }
    }

    return;
}



static inline uint8_t *
oct_pend_tx_done_add(tx_done_t *tdt, void *mb)
{
    uint8_t *mem_ref = NULL;
    uint16_t producer = tdt->producer;

    mem_ref = &tdt->pend_tx_done[producer].mem_ref;

    *mem_ref = 0xFF;
    tdt->pend_tx_done[producer].mb = mb;

    producer = (producer + 1) & (OCT_PKO_TX_DESC_NUM - 1);

    tdt->tx_entries++;
    oct_tx_entries[LOCAL_CPU_ID]++;
    tdt->producer = producer;

    return mem_ref;
}


static inline void
oct_pend_tx_done_remove(tx_done_t *tdt)
{
    tdt->producer = (tdt->producer - 1) & (OCT_PKO_TX_DESC_NUM - 1);
    tdt->tx_entries--;
    oct_tx_entries[LOCAL_CPU_ID]--;
    return;
}



void oct_tx_process_sw(mbuf_t *mbuf, uint8_t outport)
{
    uint64_t queue;
    cvmx_pko_return_value_t send_status;

    uint8_t *dont_free_cookie = NULL;

    queue = cvmx_pko_get_base_queue(outport);

    cvmx_pko_send_packet_prepare(outport, queue, CVMX_PKO_LOCK_CMD_QUEUE);

    tx_done_t *tx_done = &(oct_stx[LOCAL_CPU_ID]->tx_done[outport]);
    if(tx_done->tx_entries < (OCT_PKO_TX_DESC_NUM - 1))
    {
        dont_free_cookie = oct_pend_tx_done_add(tx_done, (void *)mbuf);
    }
    else
    {
        PACKET_DESTROY_ALL(mbuf);
        STAT_TX_SW_DESC_ERR;
        return;
    }
    /*command word0*/
    cvmx_pko_command_word0_t pko_command;
    pko_command.u64 = 0;

    pko_command.s.segs = 1;
    pko_command.s.total_bytes = mbuf->pkt_totallen;

    pko_command.s.rsp = 1;
    pko_command.s.dontfree = 1;

    /*command word1*/
    cvmx_buf_ptr_t packet;
    packet.u64 = 0;
    packet.s.size = mbuf->pkt_totallen;
    packet.s.addr = (uint64_t)mbuf->pkt_ptr;

    /*command word2*/
    cvmx_pko_command_word2_t tx_ptr_word;
    tx_ptr_word.u64 = 0;
    tx_ptr_word.s.ptr = (uint64_t)cvmx_ptr_to_phys(dont_free_cookie);

    /* Send the packet */
    send_status = cvmx_pko_send_packet_finish3(outport, queue, pko_command, packet, tx_ptr_word.u64, CVMX_PKO_LOCK_CMD_QUEUE);
    if(send_status != CVMX_PKO_SUCCESS)
    {
        if(dont_free_cookie)
        {
            oct_pend_tx_done_remove(tx_done);
        }

        PACKET_DESTROY_ALL(mbuf);
        STAT_TX_SW_SEND_ERR;
        return;
    }
    else
    {
        STAT_TX_SEND_OVER;
    }

}




void oct_tx_process_hw(mbuf_t *mbuf, uint32_t outport)
{
    uint64_t queue;

    /* Build a PKO pointer to this packet */
    cvmx_pko_return_value_t send_status;
    cvmx_pko_command_word0_t pko_command;

    queue = cvmx_pko_get_base_queue(outport);

    cvmx_pko_send_packet_prepare(outport, queue, CVMX_PKO_LOCK_CMD_QUEUE);

    pko_command.u64 = 0;
    pko_command.s.segs = 1;
    pko_command.s.total_bytes = mbuf->pkt_totallen;

    /* Send the packet */
    send_status = cvmx_pko_send_packet_finish(outport, queue, pko_command, mbuf->packet_ptr, CVMX_PKO_LOCK_CMD_QUEUE);
    if (send_status != CVMX_PKO_SUCCESS)
    {
        STAT_TX_HW_SEND_ERR;
        PACKET_DESTROY_DATA(mbuf);
    }
    else
    {
        STAT_TX_SEND_OVER;
    }
    MBUF_FREE(mbuf);
}


void oct_tx_process_hw_work(cvmx_wqe_t *work, uint32_t outport)
{
	uint64_t queue = cvmx_pko_get_base_queue(outport);

	cvmx_pko_send_packet_prepare(outport, queue, CVMX_PKO_LOCK_CMD_QUEUE);

    /* Build a PKO pointer to this packet */
    cvmx_pko_command_word0_t pko_command;
    pko_command.u64 = 0;
    pko_command.s.segs = work->word2.s.bufs;
    pko_command.s.total_bytes = cvmx_wqe_get_len(work);

    /* Send the packet */
    cvmx_pko_return_value_t send_status = cvmx_pko_send_packet_finish(outport, queue, pko_command, work->packet_ptr, CVMX_PKO_LOCK_CMD_QUEUE);
    if (send_status != CVMX_PKO_SUCCESS)
    {
        printf("Failed to send packet using cvmx_pko_send_packet2\n");
        cvmx_helper_free_packet_data(work);
		STAT_TX_HW_SEND_ERR;
    }
	else
	{
		STAT_TX_SEND_OVER;
	}

    cvmx_fpa_free(work, wqe_pool, 0);
}






int oct_rxtx_init(void)
{
    int i;

    void *ptr = cvmx_bootmem_alloc_named(sizeof(oct_softx_stat_t) * CPU_HW_RUNNING_MAX,
                                        CACHE_LINE_SIZE,
                                        OCT_TX_DESC_NAME);
    if(NULL == ptr)
    {
        return SEC_NO;
    }

    memset(ptr, 0, sizeof(oct_softx_stat_t) * CPU_HW_RUNNING_MAX);

    for( i = 0; i < CPU_HW_RUNNING_MAX; i++ )
    {
        oct_stx[i] = (oct_softx_stat_t *)((uint8_t *)ptr + sizeof(oct_softx_stat_t) * i);
    }

    return SEC_OK;
}



void oct_rxtx_Release()
{
    int rc;
    rc = cvmx_bootmem_free_named(OCT_TX_DESC_NAME);
    printf("%s free rc=%d\n", OCT_TX_DESC_NAME, rc);
}

int oct_rxtx_get(void)
{
    int i;
    void *ptr;
    const cvmx_bootmem_named_block_desc_t *block_desc = cvmx_bootmem_find_named_block(OCT_TX_DESC_NAME);
    if (block_desc)
    {
        ptr = cvmx_phys_to_ptr(block_desc->base_addr);
    }
    else
    {
        return SEC_NO;
    }

    for( i = 0; i < CPU_HW_RUNNING_MAX; i++ )
    {
        oct_stx[i] = (oct_softx_stat_t *)((uint8_t *)ptr + sizeof(oct_softx_stat_t) * i);
    }

    return SEC_OK;
}

