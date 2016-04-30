

#include <sec-common.h>
#include <oct-common.h>
#include "oct-init.h"
#include "oct-port.h"
#include "oct-api.h"
#include "oct-sched.h"
#include "decode-statistic.h"
#include "oct-rxtx.h"
#include "decode-defrag.h"


#include "shm.h"

#include "mem_pool.h"


extern void DP_Acl_Rule_Release(void);
extern void StreamTcpSessionRelease();
extern void FlowRelease();
extern void PortScan_Module_Release(); 

/* This is the Octeon hardware port number to intercept. Packets coming
    in this port are intercepted by linux-filter and processed. Packets
    received from the ethernet POW0 device are sent out this port */

/* wqe pool */
int wqe_pool = -1;

uint32_t running_core_num = 0;
uint32_t running_dp_mask = 0;


uint64_t oct_cpu_rate;

cvmx_sysinfo_t *sysinfo;



#define SYS_CPU_DIR "/sys/devices/system/cpu/cpu%u"
#define CORE_ID_FILE "topology/core_id"




int OCT_UserApp_Init()
{
    cvmx_skip_app_config_set();
    cvmx_user_app_init();
    sysinfo = cvmx_sysinfo_get();

    return SEC_OK;
}


void OCT_RX_Group_Init()
{
    /* Wait for global hardware init to complete */
    //cvmx_coremask_barrier_sync(&sysinfo->core_mask);

    /* Setup scratch registers used to prefetch output queue buffers for packet output */
    cvmx_pko_initialize_local();

    /* Accept any packet except for the ones destined to the Linux group */
    if(running_core_num == 2)
    {
        cvmx_pow_set_group_mask(cvmx_get_core_num(),
                            (1<<FROM_INPUT_PORT_GROUP)|(1<<FROM_LINUX_GROUP) | (1<<LOCAL_CPU_ID));
    }
    else if(running_core_num == 4)
    {
        if(LOCAL_CPU_ID != 3)
        {
            cvmx_pow_set_group_mask(LOCAL_CPU_ID,
                            (1<<FROM_INPUT_PORT_GROUP)|(1<<FROM_LINUX_GROUP) | (1<<LOCAL_CPU_ID));
        }
        else
        {
            cvmx_pow_set_group_mask(LOCAL_CPU_ID,
                            (1<<FROM_INPUT_PORT_GROUP)|(1<<FROM_LINUX_GROUP) | (1<<LOCAL_CPU_ID) | (1<<PACKET_GROUP_4));
        }
    }
    else
    {
        printf("not support core num %d\n", running_core_num);
        exit(0);
    }


    /* Wait for hardware init to complete */
    //cvmx_coremask_barrier_sync(&sysinfo->core_mask);

    return;
}


int OCT_Intercept_Port_Init()
{
    uint32_t port;

    printf("\n\nLoad the Linux ethernet driver with:\n"
           "\t $ modprobe octeon-ethernet\n"
           "\t $ modprobe octeon-pow-ethernet receive_group=1 broadcast_groups=4 ptp_rx_group=%d ptp_tx_group=%d\n",
           TO_LINUX_GROUP, FROM_LINUX_GROUP);

    printf("Waiting for ethernet module to complete initialization...\n\n\n");
    cvmx_ipd_ctl_status_t ipd_reg;
    do
    {
        ipd_reg.u64 = cvmx_read_csr(CVMX_IPD_CTL_STATUS);
    } while (!ipd_reg.s.ipd_en);

/* Wait a second for things to really get started. */
    if (cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM)
    cvmx_wait_usec(1000000);

#ifdef CVMX_PKO_USE_FAU_FOR_OUTPUT_QUEUES
    #error Linux-filter cannot be built with CVMX_PKO_USE_FAU_FOR_OUTPUT_QUEUES
#endif

    __cvmx_helper_init_port_valid();

    __cvmx_import_app_config_from_named_block(CVMX_APP_CONFIG);

    __cvmx_helper_init_port_config_data_local();

    wqe_pool = cvmx_fpa_get_wqe_pool();


    /* Change the group for only the port we're interested in */
    /*now we focus on four phy ports, QSGMII port0-3*/
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

#if 0
    cvmx_pip_port_tag_cfg_t tag_config0;
    tag_config0.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(OCT_PHY_PORT_FIRST));
    tag_config0.s.grp = FROM_INPUT_PORT_GROUP;
    cvmx_write_csr(CVMX_PIP_PRT_TAGX(OCT_PHY_PORT_FIRST), tag_config0.u64);

    cvmx_wait_usec(1000);

    cvmx_pip_port_tag_cfg_t tag_config1;
    tag_config1.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(OCT_PHY_PORT_SECOND));
    tag_config1.s.grp = FROM_INPUT_PORT_GROUP;
    cvmx_write_csr(CVMX_PIP_PRT_TAGX((OCT_PHY_PORT_SECOND)), tag_config1.u64);

    cvmx_wait_usec(1000);

    cvmx_pip_port_tag_cfg_t tag_config2;
    tag_config2.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(OCT_PHY_PORT_THIRD));
    tag_config2.s.grp = FROM_INPUT_PORT_GROUP;
    cvmx_write_csr(CVMX_PIP_PRT_TAGX(OCT_PHY_PORT_THIRD), tag_config2.u64);

    cvmx_wait_usec(1000);

    cvmx_pip_port_tag_cfg_t tag_config3;
    tag_config3.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(OCT_PHY_PORT_FOURTH));
    tag_config3.s.grp = FROM_INPUT_PORT_GROUP;
    cvmx_write_csr(CVMX_PIP_PRT_TAGX(OCT_PHY_PORT_FOURTH), tag_config3.u64);
#endif

    /* We need to call cvmx_cmd_queue_initialize() to get the pointer to
        the named block. The queues are already setup by the ethernet
        driver, so we don't actually need to setup a queue. Pass some
        invalid parameters to cause the queue setup to fail */
    cvmx_cmd_queue_initialize(0, 0, -1, 0);
    printf("Waiting for packets from port %d, %d, %d, %d... \n",
        OCT_PHY_PORT_FIRST,
        OCT_PHY_PORT_SECOND,
        OCT_PHY_PORT_THIRD,
        OCT_PHY_PORT_FOURTH);

    return SEC_OK;
}



int oct_tim_setup(uint64_t tick, uint64_t max_ticks)
{
    uint64_t timer_id;
    int error = -1;
    uint64_t tim_clock_hz = cvmx_clock_get_rate(CVMX_CLOCK_TIM);
    uint64_t hw_tick_ns;
    uint64_t hw_tick_ns_allowed;
    uint64_t tick_ns = 1000 * tick;
    int i;
    uint32_t temp;
    int timer_thr = 1024;
    int timer_pool = (int)cvmx_fpa_get_timer_pool();
    uint64_t timer_pool_size = cvmx_fpa_get_timer_pool_block_size();

    /* for the simulator */
    if (tim_clock_hz == 0)
        tim_clock_hz = 800000000;

    if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
        cvmx_tim_fr_rn_tt_t fr_tt;
        fr_tt.u64 = cvmx_read_csr(CVMX_TIM_FR_RN_TT);
        timer_thr = fr_tt.s.fr_rn_tt;
    }

    hw_tick_ns = timer_thr * 1000000000ull / tim_clock_hz;
    /*
     * Double the minimal allowed tick to 2 * HW tick.  tick between
     * (hw_tick_ns, 2*hw_tick_ns) will set config_ring1.s.interval
     * to zero, or 1024 cycles. This is not enough time for the timer unit
     * to fetch the bucket data, Resulting in timer ring error interrupt
     * be always generated. Avoid such setting in software.
     */
    hw_tick_ns_allowed = hw_tick_ns * 2;

    /* Make sure the timers are stopped */
    cvmx_tim_stop();

    /* Reinitialize out timer state */
    memset(&cvmx_tim, 0, sizeof(cvmx_tim));

    if (tick_ns < hw_tick_ns_allowed) {
        cvmx_dprintf("ERROR: cvmx_tim_setup: Requested tick %" PRIu64 "(ns) is smaller than"
                 " the minimal ticks allowed by hardware %" PRIu64 "(ns)\n", tick_ns, hw_tick_ns_allowed);
        return error;
    } else if (tick_ns > 4194304 * hw_tick_ns) {
        cvmx_dprintf("ERROR: cvmx_tim_setup: Requested tick %" PRIu64 "(ns) is greater than" " the max ticks %" PRIu64 "(ns)\n", tick_ns, hw_tick_ns);
        return error;
    }

    for (i = 2; i < 20; i++) {
        if (tick_ns < (hw_tick_ns << i))
            break;
    }

    cvmx_tim.max_ticks = (uint32_t) max_ticks;
    cvmx_tim.bucket_shift = (uint32_t) (i - 1 + 10);//10 means 1<<10(1024(one interval))
    cvmx_tim.tick_cycles = tick * tim_clock_hz / 1000000;


    temp = (max_ticks * cvmx_tim.tick_cycles) >> cvmx_tim.bucket_shift;

    //cvmx_dprintf(" temp %d, i = %d,cycle %d,hw_tick_ns_allowed %d\n",temp, i,cvmx_tim.tick_cycles,hw_tick_ns_allowed);

    /* round up to nearest power of 2 */
    temp -= 1;
    temp = temp | (temp >> 1);
    temp = temp | (temp >> 2);
    temp = temp | (temp >> 4);
    temp = temp | (temp >> 8);
    temp = temp | (temp >> 16);
    cvmx_tim.num_buckets = temp + 1;

    /* ensure input params fall into permitted ranges */
    if ((cvmx_tim.num_buckets < 3) || cvmx_tim.num_buckets > 1048576) {
        cvmx_dprintf("ERROR: cvmx_tim_setup: num_buckets out of range\n");
        return error;
    }

    cvmx_dprintf("num_buckets %d\n",cvmx_tim.num_buckets);

    /* Allocate the timer buckets from hardware addressable memory */
    cvmx_tim.bucket = cvmx_bootmem_alloc_named(CVMX_TIM_NUM_TIMERS * cvmx_tim.num_buckets * sizeof(cvmx_tim_bucket_entry_t), CACHE_LINE_SIZE, "oct-cvmx-tim");
    if (cvmx_tim.bucket == NULL) {
        cvmx_dprintf("ERROR: cvmx_tim_setup: allocation problem\n");
        return error;
    }
    memset(cvmx_tim.bucket, 0, CVMX_TIM_NUM_TIMERS * cvmx_tim.num_buckets * sizeof(cvmx_tim_bucket_entry_t));

    cvmx_tim.start_time = 0;

    /*Initialize FPA pool for timer buffers*/
#ifndef CVMX_BUILD_FOR_LINUX_KERNEL
    cvmx_fpa_global_initialize();
    //cvmx_dprintf("timer_config.timer_pool.buffer_count 0x%x, timer_pool %d,timer_pool_size %d\n",
    //timer_config.timer_pool.buffer_count,timer_pool,timer_pool_size);
    if(timer_config.timer_pool.buffer_count != 0)
        __cvmx_helper_initialize_fpa_pool(timer_pool, timer_pool_size,
            timer_config.timer_pool.buffer_count, "Timer Buffers");
#endif
    /* Loop through all timers */
    for (timer_id = 0; timer_id < CVMX_TIM_NUM_TIMERS; timer_id++) {
        int interval = ((1 << (cvmx_tim.bucket_shift - 10)) - 1);
        cvmx_tim_bucket_entry_t *bucket = cvmx_tim.bucket + timer_id * cvmx_tim.num_buckets;
        if (OCTEON_IS_MODEL(OCTEON_CN68XX)) {
            cvmx_tim_ringx_ctl0_t ring_ctl0;
            cvmx_tim_ringx_ctl1_t ring_ctl1;
            cvmx_tim_ringx_ctl2_t ring_ctl2;
            cvmx_tim_reg_flags_t reg_flags;

            /* Tell the hardware where about the bucket array */
            ring_ctl2.u64 = 0;
            ring_ctl2.cn68xx.csize = timer_pool_size / 8;
            ring_ctl2.cn68xx.base = cvmx_ptr_to_phys(bucket) >> 5;
            cvmx_write_csr(CVMX_TIM_RINGX_CTL2(timer_id), ring_ctl2.u64);

            reg_flags.u64 = cvmx_read_csr(CVMX_TIM_REG_FLAGS);
            ring_ctl1.u64 = 0;
            ring_ctl1.s.cpool = ((reg_flags.s.ena_dfb == 0) ? timer_pool : 0);
            ring_ctl1.s.bsize = cvmx_tim.num_buckets - 1;
            cvmx_write_csr(CVMX_TIM_RINGX_CTL1(timer_id), ring_ctl1.u64);

            ring_ctl0.u64 = 0;
            ring_ctl0.cn68xx.timercount = interval + timer_id * interval / CVMX_TIM_NUM_TIMERS;
            ring_ctl0.cn68xx.ena = 1;
            ring_ctl0.cn68xx.intc = 1;
            ring_ctl0.cn68xx.interval = interval;
            cvmx_write_csr(CVMX_TIM_RINGX_CTL0(timer_id), ring_ctl0.u64);
            cvmx_read_csr(CVMX_TIM_RINGX_CTL0(timer_id));
        } else {
            cvmx_tim_mem_ring0_t config_ring0;
            cvmx_tim_mem_ring1_t config_ring1;
            /* Tell the hardware where about the bucket array */
            config_ring0.u64 = 0;
            config_ring0.s.first_bucket = cvmx_ptr_to_phys(bucket) >> 5;
            config_ring0.s.num_buckets = cvmx_tim.num_buckets - 1;
            config_ring0.s.ring = timer_id;
            cvmx_write_csr(CVMX_TIM_MEM_RING0, config_ring0.u64);

            /* Tell the hardware the size of each chunk block in pointers */
            config_ring1.u64 = 0;
            config_ring1.s.enable = 1;
            config_ring1.s.pool = timer_pool;
            config_ring1.s.words_per_chunk = timer_pool_size / 8;
            config_ring1.s.interval = interval;
            config_ring1.s.ring = timer_id;
            cvmx_write_csr(CVMX_TIM_MEM_RING1, config_ring1.u64);
            cvmx_dprintf("interval %d\n", interval);
        }
    }

    return 0;
}




int OCT_Timer_Init()
{
    int status;

    //status = cvmx_tim_setup(1000 , 5000);
    status = oct_tim_setup(1000, 5000);
    if (status != 0) {
        return SEC_NO;
    }
    cvmx_tim_start();

    return SEC_OK;
}

int OCT_Timer_Create(uint32_t tag, cvmx_pow_tag_type_t tag_type, uint64_t qos, uint64_t grp, timer_thread_fn fn,
                                void *param, uint32_t param_len, uint16_t tick)
{
    cvmx_wqe_t *wqe_p;
    cvmx_tim_status_t result;
    Oct_Timer_Threat *o;

    if( grp >= 16 || param_len > 96 - sizeof(Oct_Timer_Threat))
    {
        return SEC_NO;
    }

    wqe_p = cvmx_fpa_alloc(CVMX_FPA_WQE_POOL);
    if (wqe_p == NULL)
    {
        return SEC_NO;
    }

    memset(wqe_p, 0, sizeof(cvmx_wqe_t));

    cvmx_wqe_set_unused8(wqe_p, TIMER_FLAG_OF_WORK);
    cvmx_wqe_set_tag(wqe_p, tag);
    cvmx_wqe_set_tt(wqe_p, tag_type);
    cvmx_wqe_set_qos(wqe_p, qos);
    cvmx_wqe_set_grp(wqe_p, grp);

    o = (Oct_Timer_Threat *)wqe_p->packet_data;
    o->magic = TIMER_THREAD_MAGIC;
    o->fn = fn;
    o->param = (void *)o+sizeof(Oct_Timer_Threat);
    o->tick = tick;

    result = cvmx_tim_add_entry(wqe_p, o->tick, NULL);

    CVMX_SYNCW;
    return result;
}

void OCT_Timer_Thread_Process(cvmx_wqe_t *wq)
{
    Oct_Timer_Threat *o;
    o = (Oct_Timer_Threat *)wq->packet_data;
    if( TIMER_THREAD_MAGIC != o->magic || TIMER_FLAG_OF_WORK != oct_wqe_get_unused8(wq))
    {
        printf("this is not a valid tim work\n");
        abort();
        return;
    }

    if (o->fn != NULL)
    {
        o->fn(o, o->param);
    }

    cvmx_tim_add_entry(wq, o->tick, NULL);
    CVMX_SYNCW;

    return;
}
static inline int _snprintf(char *buffer, int buflen, const char *format, ...)
{
	int len;
	va_list ap;

	if (buffer == NULL && buflen != 0)
		goto einval_error;
	if (format == NULL) {
		if (buflen > 0)
			buffer[0] = '\0';
		goto einval_error;
	}

	va_start(ap, format);
	len = vsnprintf(buffer, buflen, format, ap);
	va_end(ap);
	if (len >= buflen && buflen > 0)
		buffer[buflen - 1] = '\0';

	return len;

einval_error:
	errno = EINVAL;
	return -1;
}

static int
cpu_detected(unsigned lcore_id)
{
	char path[128];
	int len = _snprintf(path, sizeof(path), SYS_CPU_DIR"/"CORE_ID_FILE, lcore_id);
	if (len <= 0 || (unsigned)len >= sizeof(path))
		return 0;
	if (access(path, F_OK) != 0)
		return 0;

	return 1;
}


void mt_cpu_init()
{
    uint32_t count = 0;
    uint32_t lcore_id = 0;
    printf("mt cpu init!\n");

    for(lcore_id = 0; lcore_id < CPU_HW_RUNNING_MAX; lcore_id++)
    {
        if(cpu_detected(lcore_id))
        {
            count++;
        }
    }

    running_core_num = count;
	//running_core_num = 2;
    for(lcore_id = 1; lcore_id < running_core_num; lcore_id++)
    {
        running_dp_mask |= 1 << lcore_id;
    }
}


int OCT_CPU_Init()
{
    oct_cpu_rate = cvmx_clock_get_rate(CVMX_CLOCK_CORE);

    mt_cpu_init();

    return SEC_OK;
}

SRV_DP_SYNC *srv_dp_sync;


int srv_sync_dp_init()
{
    int fd;

    fd = shm_open(SHM_SRV_DP_SYNC_NAME, O_RDWR, 0);
    if (fd < 0)
    {
        printf("Failed to setup CVMX_SHARED(shm_open)\n");
        return SEC_NO;
    }

    ftruncate(fd, sizeof(SRV_DP_SYNC));

    void *ptr = mmap(NULL, sizeof(SRV_DP_SYNC), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == NULL)
    {
        printf("Failed to setup rule list (mmap copy)");
        return SEC_NO;
    }

    srv_dp_sync = (SRV_DP_SYNC *)ptr;

    if(srv_dp_sync->magic != SRV_DP_SYNC_MAGIC)
    {
        printf("srv dp sync magic error\n");
        return SEC_NO;
    }

    return SEC_OK;
}


void dp_sync_srv()
{
    printf("waiting for srv init\n");
    while(!srv_dp_sync->srv_initdone);
    printf("srv init done....\n");

    printf("waiting for srv notify\n");
    while(!srv_dp_sync->srv_notify_dp);
    printf("srv notify dp is true...\n");

    srv_dp_sync->dp_ack = 1;
    printf("dp give a ack to srv...\n");
}


void dp_sync_dp()
{
    srv_dp_sync->dp_sync_dp |= 1 << LOCAL_CPU_ID;


    while(srv_dp_sync->dp_sync_dp != running_dp_mask)
    {
        usleep(1);
    }

}

void OCT_Intercept_Port_Release()
{
    uint32_t port;

    cvmx_ipd_ctl_status_t ipd_reg;
    do
    {
        ipd_reg.u64 = cvmx_read_csr(CVMX_IPD_CTL_STATUS);
    } while (!ipd_reg.s.ipd_en);

/* Wait a second for things to really get started. */
    if (cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM)
    cvmx_wait_usec(1000000);

#ifdef CVMX_PKO_USE_FAU_FOR_OUTPUT_QUEUES
    #error Linux-filter cannot be built with CVMX_PKO_USE_FAU_FOR_OUTPUT_QUEUES
#endif

    __cvmx_helper_init_port_valid();

    __cvmx_import_app_config_from_named_block(CVMX_APP_CONFIG);

    __cvmx_helper_init_port_config_data_local();

    wqe_pool = cvmx_fpa_get_wqe_pool();


    /* Change the group for only the port we're interested in */
    /*now we focus on four phy ports, QSGMII port0-3*/
    for(port = OCT_PHY_PORT_FIRST; port < OCT_PHY_PORT_MAX; port++)
    {
        cvmx_pip_port_tag_cfg_t tag_config;
        /*config group*/
        tag_config.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(port));
        tag_config.s.grp = PACKET_TO_KERNEL_GROUP;
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


    /* We need to call cvmx_cmd_queue_initialize() to get the pointer to
        the named block. The queues are already setup by the ethernet
        driver, so we don't actually need to setup a queue. Pass some
        invalid parameters to cause the queue setup to fail */
    cvmx_cmd_queue_initialize(0, 0, -1, 0);
    printf("oct intercept port release\n");

}

void OCT_Timer_Release()
{
    int rc;

    cvmx_tim_shutdown();

    rc = cvmx_bootmem_free_named("oct-cvmx-tim");
    printf("%s free rc=%d\n", "oct-cvmx-tim", rc);

}


void OCT_RX_Group_Release()
{
    uint32_t grp;
    cvmx_wqe_t *work;
    int wait = 0;

    /* Accept any packet except for the ones destined to the Linux group */
    if(running_core_num == 2)
    {
        cvmx_pow_set_group_mask(LOCAL_CPU_ID,
                            (1<<FROM_INPUT_PORT_GROUP) | (1<<FROM_LINUX_GROUP) | (1<<LOCAL_CPU_ID));
    }
    else if(running_core_num == 4)
    {
        cvmx_pow_set_group_mask(LOCAL_CPU_ID,
                            (1<<FROM_INPUT_PORT_GROUP) | (1<<FROM_LINUX_GROUP) | (1<<PACKET_GROUP_1) | (1<<PACKET_GROUP_2) | (1<<PACKET_GROUP_3) | (1<<PACKET_GROUP_4));
    }
    else
    {
        printf("not support core num %d\n", running_core_num);
        exit(0);
    }

    while(1)
    {
        work = oct_pow_work_request_sync_nocheck(CVMX_POW_WAIT);
        if (NULL != work)
        {
            grp = (uint32_t)oct_wqe_get_grp(work);

            if ( FROM_INPUT_PORT_GROUP == grp || PACKET_GROUP_1 == grp || PACKET_GROUP_2 == grp || PACKET_GROUP_3 == grp || PACKET_GROUP_4 == grp)
            {
                if( oct_wqe_get_unused8(work) == 0)
                {
                    oct_packet_free(work, wqe_pool);
                }
                else if (oct_wqe_get_unused8(work) == TIMER_FLAG_OF_WORK )
                {
                    cvmx_fpa_free(work, CVMX_FPA_WQE_POOL, 0);
                }
            }
			else if ( FROM_LINUX_GROUP == grp )
			{
				oct_packet_free(work, wqe_pool);
			}
            else
            {
                printf("work group error %d\n", grp);
                printf("Received %u byte packet.\n", oct_wqe_get_len(work));
                printf("Processing packet\n");
                cvmx_helper_dump_packet(work);
                oct_packet_free(work, wqe_pool);
            }
        }
        else
        {
            if(wait == 0)
            {
                wait = 1;
			    usleep(1);
                continue;
            }
            else
            {
                break;
            }
        }
    }


    /*TODO restore group of core 1,2,3*/
    if(running_core_num == 2)
    {
        cvmx_pow_set_group_mask(1, 0);
    }
    else if(running_core_num == 4)
    {
        cvmx_pow_set_group_mask(1, 0);
        cvmx_pow_set_group_mask(2, 0);
        cvmx_pow_set_group_mask(3, 0);
    }
    else
    {
        printf("not support core num %d\n", running_core_num);
        exit(0);
    }

    return;
}


void resource_clean()
{
    OCT_UserApp_Init();

    OCT_CPU_Init();

    OCT_Intercept_Port_Release();

    OCT_RX_Group_Release();

    OCT_Timer_Release();

    Mem_Pool_Release();

    oct_seched_Release();

    oct_rxtx_Release();

    Decode_PktStat_Release();

    StreamTcpSessionRelease();

    FragModule_Release();

    DP_Acl_Rule_Release();

    PortScan_Module_Release();

    FlowRelease();

}





