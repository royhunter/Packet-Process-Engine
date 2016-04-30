#include <mbuf.h>
#include <decode.h>
#include <decode-ipv4.h>
#include <sec-common.h>
#include <oct-init.h>
#include "flow.h"
#include "tluhash.h"
#include "decode-statistic.h"
#include "stream-tcp.h"
#include "output.h"
#include "acl_rule.h"
#include "dp_acl.h"
#include "dp_log.h"
#include "dp_attack.h"
#include "dp_portscan.h"




extern uint32_t l7_deliver(mbuf_t *m);
extern void l7_flow_release(flow_item_t *f);
#define SELF_TEST



uint32_t syn_check = 1;


uint64_t new_flow[CPU_HW_RUNNING_MAX] = {0, 0, 0, 0};
uint64_t del_flow[CPU_HW_RUNNING_MAX] = {0, 0, 0, 0};


flow_table_info_t *flow_table[CPU_HW_RUNNING_MAX];

static inline flow_item_t *flow_item_alloc()
{
    Mem_Slice_Ctrl_B *mscb;
    void *buf = mem_pool_fpa_slice_alloc(FPA_POOL_ID_FLOW_NODE);
    if(NULL == buf)
        return NULL;

    mscb = (Mem_Slice_Ctrl_B *)buf;
    mscb->magic = MEM_POOL_MAGIC_NUM;
    mscb->pool_id = FPA_POOL_ID_FLOW_NODE;

    return (flow_item_t *)((uint8_t *)buf + sizeof(Mem_Slice_Ctrl_B));
}

static inline void flow_item_free(flow_item_t *f)
{
    Mem_Slice_Ctrl_B *mscb = (Mem_Slice_Ctrl_B *)((uint8_t *)f - sizeof(Mem_Slice_Ctrl_B));
    if(MEM_POOL_MAGIC_NUM != mscb->magic)
    {
        LOGDBG(SEC_FLOW_DBG_BIT, "magic num err %d\n", mscb->magic);
        return;
    }
    if(FPA_POOL_ID_FLOW_NODE != mscb->pool_id)
    {
        LOGDBG(SEC_FLOW_DBG_BIT, "pool id err %d\n", mscb->pool_id);
        return;
    }

    mem_pool_fpa_slice_free((void *)mscb, FPA_POOL_ID_FLOW_NODE);

    return;
}


static void FlowInsert(flow_bucket_t *fb, flow_item_t *fi)
{
    hlist_add_head(&fi->list, &fb->hash);
}



static inline uint32_t flowhashfn(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint8_t prot)
{
    return flow_hashfn(prot, saddr, daddr, sport, dport) & FLOW_BUCKET_MASK;
}

static uint32_t FlowMatch(flow_item_t *f, mbuf_t *mbuf)
{
    return ((f->ipv4.sip   == mbuf->ipv4.sip
            && f->ipv4.dip == mbuf->ipv4.dip
            && f->sport    == mbuf->sport
            && f->dport    == mbuf->dport
            && f->protocol == mbuf->proto)
        || (f->ipv4.sip    == mbuf->ipv4.dip
            && f->ipv4.dip == mbuf->ipv4.sip
            && f->sport    == mbuf->dport
            && f->dport    == mbuf->sport
            && f->protocol == mbuf->proto));
}


static inline flow_item_t *FlowFind(flow_bucket_t *fb, mbuf_t *mbuf, unsigned int hash)
{
    flow_item_t *f;
    struct hlist_node *n;

    LOGDBG(SEC_FLOW_DBG_BIT, "============>enter FlowFind\n");

    hlist_for_each_entry(f, n, &fb->hash, list)
    {
        if(FlowMatch(f, mbuf))
        {
        #ifdef SEC_FLOW_DEBUG
            LOGDBG("FlowMatch is ok\n");
        #endif
            FLOW_UPDATE_TIMESTAMP(f);
            return f;
        }
    }

    LOGDBG(SEC_FLOW_DBG_BIT, "FlowMatch is fail\n");

    return NULL;
}

flow_item_t *FlowAdd(flow_bucket_t *fb, unsigned int hash, mbuf_t *mbuf)
{
    LOGDBG(SEC_FLOW_DBG_BIT, "==========>enter FlowAdd\n");

    flow_item_t *newf = flow_item_alloc();
    if(NULL == newf)
    {
        STAT_FLOW_NODE_NOMEM;
        return NULL;
    }

    memset((void *)newf, 0, FLOW_ITEM_SIZE);

    /*TODO: init flow node with necessary info*/
    newf->ipv4.sip = mbuf->ipv4.sip;
    newf->ipv4.dip = mbuf->ipv4.dip;
    newf->sport    = mbuf->sport;
    newf->dport    = mbuf->dport;
    newf->protocol = mbuf->proto;
    newf->input_port = mbuf->input_port;
    FLOW_UPDATE_TIMESTAMP(newf);

    FlowInsert(fb, newf);
    new_flow[LOCAL_CPU_ID]++;


    if(mbuf->flow_log)
    {
        /*TODO FLOW CREATE LOG*/
    }

    if(TCP_IS_SYN(mbuf))
    {
        DP_Attack_SynCountMonitor(mbuf);
    }

    return newf;

}



/*update flow node info*/
static inline void FlowUpdate(flow_item_t *f, mbuf_t *m)
{

    if(m->sport == f->sport)
    {
        f->pktcnts2d++;
        f->bytecnts2d += m->pkt_totallen;
    }
    else
    {
        f->pktcntd2s++;
        f->bytecntd2s += m->pkt_totallen;
    }

    return;
}


flow_item_t *FlowGetFlowFromHash(mbuf_t *mbuf)
{
    unsigned int hash;
    uint32_t ret = 0;
    flow_item_t * flow;
    flow_bucket_t *base;
    flow_bucket_t *fb;

    hash = flowhashfn(mbuf->ipv4.sip, mbuf->ipv4.dip, mbuf->sport, mbuf->dport, mbuf->proto);

    base = (flow_bucket_t *)flow_table[LOCAL_CPU_ID]->bucket_base_ptr;
    fb = &base[hash];

    LOGDBG(SEC_FLOW_DBG_BIT, "hash value is %d\n", hash);

    flow = FlowFind(fb, mbuf, hash);
    if(NULL != flow)    /*find and return*/
    {
        STAT_ACL_FW;
        return flow;
    }
    else                /*not find, first pkt, create a new node and insert it*/
    {
        if(syn_check)//if syn_check enable, only first syn packet can create flow
        {
            if(PKT_IS_TCP(mbuf))
            {
                if(!TCP_IS_SYN(mbuf))
                {
                    STAT_FLOW_TCP_NO_SYN_FIRST;
                    return NULL;
                }
            }
        }
        ret = PortScan_Detect(mbuf);
        if(ret != PORTSCAN_OK)
        {
            if(PORTSCAN_DETECTED == ret)
            {
                LOGDBG(SEC_ATTACK_DBG_BIT, "port scan attack\n");
			    //send_alert_data_firewall(mbuf, 1, APP_TYPE_PORTSCAN);
            }

            if(portscan_action == 0)/*ACTION IS DROP*/
            {
                STAT_ATTACK_PORTSCAN_DROP;
                return NULL;

            }
        }

        if(ACL_RULE_ACTION_DROP == DP_Acl_Lookup(mbuf))//first packet, look up acl
        {
            STAT_ACL_DROP;
            DP_Log_Func(mbuf);
            return NULL;
        }
        else
        {
            STAT_ACL_FW;
        }

        return FlowAdd(fb, hash, mbuf);
    }
}


int FlowGetPacketDirection(flow_item_t *f, const mbuf_t *m)
{
    if (m->proto == PROTO_TCP || m->proto == PROTO_UDP)
    {
        if (!(CMP_PORT(m->sport,m->dport))) {
            /* update flags and counters */
            if (CMP_PORT(f->sport,m->sport)) {
                return TOSERVER;
            } else {
                return TOCLIENT;
            }
        } else {
            if (CMP_ADDR(&f->ipv4.sip,&m->ipv4.sip)) {
                return TOSERVER;
            } else {
                return TOCLIENT;
            }
        }
    }

    return TOSERVER;  //default to toserver
}

void FlowHandlePacket(mbuf_t *m)
{
    LOGDBG(SEC_FLOW_DBG_BIT, "=========>enter FlowHandlePacket\n");

    flow_item_t *f;

    f = FlowGetFlowFromHash(m);  /*return a locked flow item*/
    if(NULL == f)
    {
        /*flow failed, destroy packet*/
        output_drop_proc(m);
        STAT_FLOW_PROC_FAIL;
        return;
    }


    if(FLOW_ACTION_DROP == f->action)
    {
        output_drop_proc(m);
        STAT_FLOW_PROC_DROP;
        return;
    }

    if (FlowGetPacketDirection(f, m) == TOSERVER)
    {
        m->flags |= PKT_TO_SERVER;
    }
    else
    {
        m->flags |= PKT_TO_CLIENT;
    }

    /*TODO:  update info in the flow*/
    FlowUpdate(f, m);

    m->flow = (void *)f;
    m->flags |= PKT_HAS_FLOW;

    STAT_FLOW_PROC_OK;

    if(stream_tcp_track_enable && PKT_IS_TCP(m))
    {
        mbuf_t *reasm_m;
        uint32_t ret;
        ret = StreamTcp(m, &reasm_m);
        if(STREAMTCP_ERR == ret) {
            LOGDBG(SEC_STREAMTCP_DBG_BIT, "stream tcp packet track failed\n");
            output_drop_proc(m);
            return;
        } else if (STREAMTCP_CACHE == ret) {
            LOGDBG(SEC_STREAMTCP_DBG_BIT, "\nstream tcp packet track cached\n");
            return;
        }
        else if(STREAMTCP_REASM_BEFORE == ret) {
            LOGDBG(SEC_STREAMTCP_DBG_BIT, "\nstream tcp packet track ok and reasm before\n");
            PKT_SET_REASM_BEFORE(reasm_m);// spurious retransmission
        }
        else if (STREAMTCP_REASM_OVERLAP == ret) {
            LOGDBG(SEC_STREAMTCP_DBG_BIT, "\nstream tcp packet track ok and reasm overlap\n");
            PKT_SET_REASM_OVERLAP(reasm_m);
        }
        else if (STREAMTCP_OK == ret) {
            LOGDBG(SEC_STREAMTCP_DBG_BIT, "\nstream tcp packet track ok\n");
        }

        mbuf_t *next_mbuf = NULL;
        m = reasm_m;
        for(; m != NULL; m = next_mbuf)
        {
            next_mbuf = m->tcp_seg_reassem;

            LOGDBG(SEC_STREAMTCP_DBG_BIT, "after StreamTcp module:");

            if(PKT_IS_STREAMTCP_REASM(m))
            {
                LOGDBG(SEC_STREAMTCP_DBG_BIT, "packet is reasm\n");
            }
            else
            {
                LOGDBG(SEC_STREAMTCP_DBG_BIT, "packet is not reasm\n");
            }

            if(PKT_IS_TOSERVER(m))
            {
                LOGDBG(SEC_STREAMTCP_DBG_BIT,"packet is client------->server\n");
            }
            else
            {
                LOGDBG(SEC_STREAMTCP_DBG_BIT,"packet is server------->client\n");
            }

            LOGDBG(SEC_STREAMTCP_DBG_BIT, "seq is %u, payload_len is %d, next seq is %u\n", TCP_GET_SEQ(m), m->payload_len, TCP_GET_SEQ(m) + m->payload_len);
        #ifdef SELF_TEST
            output_fw_proc(m);
            //output_drop_proc(m);
        #else
            uint32_t act = SEC_DROP;
            act = l7_deliver(m);
            output_l7_follow_proc(m, act);
        #endif
        }

    }
    else
    {
    #ifdef SELF_TEST
        output_fw_proc(m);
        //output_drop_proc(m);
    #else
        uint32_t act = SEC_DROP;
        act = l7_deliver(m);
        output_l7_follow_proc(m, act);

    #endif
    }

    return;
}


uint32_t FlowTimeOut(flow_item_t *f, uint64_t current_cycle)
{
#if 0
    if(cvmx_atomic_get32(&f->use_cnt) > 0)
    {
        return 0;
    }
#endif

    if(FLOW_IS_PERSISTERN(f))
    {
        return 0;
    }

    if((current_cycle > f->cycle) && ((current_cycle - f->cycle) > FLOW_MAX_TIMEOUT))
    {
        return 1;
    }

    return 0;
}

void FlowAgeResRelease(flow_item_t *f)
{
    /*TODO: session ageing res release which attached flow node*/
    StreamTcp_Flow_ResRelease(f);
    l7_flow_release(f);
    flow_item_free(f);
}


void FlowAgeTimeoutCB(Oct_Timer_Threat *o, void *param)
{
    int i;
    uint64_t current_cycle;

    flow_bucket_t *base;
    flow_bucket_t *fb;
    flow_item_t *f;
    flow_item_t *tf;
    struct hlist_node *n;
    struct hlist_node *t;
    struct hlist_head timeout;

    base = (flow_bucket_t *)flow_table[LOCAL_CPU_ID]->bucket_base_ptr;

    current_cycle = cvmx_get_cycle();

    for(i = 0; i < FLOW_BUCKET_NUM; i++)
    {
        INIT_HLIST_HEAD(&timeout);

        fb = &base[i];

        hlist_for_each_entry_safe(f, t, n, &fb->hash, list)
        {
            if(FlowTimeOut(f, current_cycle))
            {
                hlist_del(&f->list);

                LOGDBG(SEC_FLOW_DBG_BIT, "delete one flow node 0x%p\n", f);

                del_flow[LOCAL_CPU_ID]++;
                hlist_add_head(&f->list, &timeout);
            }
        }

        hlist_for_each_entry_safe(tf, t, n, &timeout, list)
        {
            hlist_del(&tf->list);
            FlowAgeResRelease(tf);
        }

    }

    return;
}



int FlowInit(void)
{
    int i = 0;

    flow_bucket_t *base = NULL;
    char buf[128] = { 0 };
    flow_table_info_t *flow_table_info = NULL;

    flow_item_size_judge();

    sprintf(buf, "Flow_Hash_Table_%d", LOCAL_CPU_ID);

    flow_table_info = (flow_table_info_t *)cvmx_bootmem_alloc_named((sizeof(flow_table_info_t) + FLOW_BUCKET_NUM * FLOW_BUCKET_SIZE), CACHE_LINE_SIZE, buf);
    if(NULL == flow_table_info)
    {
        printf("flow init: no memory size is 0x%lx\n", (sizeof(flow_table_info_t) + FLOW_BUCKET_NUM * FLOW_BUCKET_SIZE));
        return SEC_NO;
    }
    memset(flow_table_info, 0, (sizeof(flow_table_info_t) + FLOW_BUCKET_NUM * FLOW_BUCKET_SIZE));
    flow_table[LOCAL_CPU_ID] = flow_table_info;

    flow_table_info->bucket_num = FLOW_BUCKET_NUM;
    flow_table_info->bucket_size = FLOW_BUCKET_SIZE;

    flow_table_info->item_num = FLOW_ITEM_NUM;
    flow_table_info->item_size = FLOW_ITEM_SIZE;

    flow_table_info->bucket_base_ptr = (void *)((uint8_t *)flow_table_info + sizeof(flow_table_info_t));

    base = (flow_bucket_t *)flow_table_info->bucket_base_ptr;

    for(i = 0; i < FLOW_BUCKET_NUM; i++)
    {
        INIT_HLIST_HEAD(&base[i].hash);
    }

    if(OCT_Timer_Create(0xFFFFFF, 0, 2, LOCAL_CPU_ID, FlowAgeTimeoutCB, NULL, 0, 1000))/*1s*/
    {
        LOGDBG(SEC_FLOW_DBG_BIT, "timer create fail\n");
        return SEC_NO;
    }

    LOGDBG(SEC_FLOW_DBG_BIT, "flow age timer create ok\n");

    return SEC_OK;
}


void FlowRelease()
{
    int rc;
    int i;
    char buf[128] = { 0 };
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        sprintf(buf, "Flow_Hash_Table_%d", i);
        rc = cvmx_bootmem_free_named(buf);
        printf("%s free rc=%d\n", buf, rc);
        memset(buf, 0, 128);
    }
}







