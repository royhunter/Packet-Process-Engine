#ifndef __OCT_INIT_H__
#define __OCT_INIT_H__

#include <oct-common.h>
#include "shm.h"


#define PACKET_TO_KERNEL_GROUP 15


/* This define is the POW group packet destine to the Linux kernel should
    use. This must match the ethernet driver's pow_receive_group parameter */
#define TO_LINUX_GROUP          14

/*pow group match eth group
  *  pow0 <----> eth0   <---> group 14
  *  pow1 <----> eth1   <---> group 12
  *  pow2 <----> eth2   <---> group 11
  *  pow3 <----> eth3   <---> group 10
  */
#define POW0_LINUX_GROUP        14       //pow0
#define POW1_LINUX_GROUP        12       //pow1
#define POW2_LINUX_GROUP        11       //pow2
#define POW3_LINUX_GROUP        10       //pow3



/* This define is the POW group packet from the Linux kernel use. This must
    match the ethernet driver's pow_send_group parameter */
#define FROM_LINUX_GROUP        13



/* This define is the POW group this program uses for packet interception.
    Packets from intercept_port are routed to this POW group instead of the
    normal ethernet pow_receive_group */
#define FROM_INPUT_PORT_GROUP   0

/* For one core, we support 1 group of packet coming in
  *    core 1 <----->group 0
  *
  * For four cores, we support 4 groups of packet coming in
  *  core 1  <----> group 1
  *  core 2  <----> group 2
  *  core 3  <----> group 3,4
  */
#define PACKET_GROUP_1    1
#define PACKET_GROUP_2    2
#define PACKET_GROUP_3    3
#define PACKET_GROUP_4    4






#define TIMER_FLAG_OF_WORK    0x11
#define TIMER_THREAD_MAGIC    0xabab

typedef struct Oct_Timer_Thread_t Oct_Timer_Threat;

typedef void (*timer_thread_fn)(Oct_Timer_Threat *, void *);


struct Oct_Timer_Thread_t
{
    uint32_t magic;
    uint16_t free;
    uint16_t tick;
    timer_thread_fn fn;
    void *param;
};



extern SRV_DP_SYNC *srv_dp_sync;



extern CVMX_SHARED int intercept_port;

/* wqe pool */
extern int wqe_pool;

extern uint64_t oct_cpu_rate;

extern uint32_t running_core_num;

extern int OCT_CPU_Init();
extern int OCT_UserApp_Init();
extern void OCT_RX_Group_Init();
extern int OCT_Intercept_Port_Init();
extern void resource_clean();
extern int OCT_Timer_Init();
extern int OCT_Timer_Create(uint32_t tag, cvmx_pow_tag_type_t tag_type, uint64_t qos, uint64_t grp, timer_thread_fn fn,
                                void *param, uint32_t param_len, uint16_t tick);
extern void OCT_Timer_Thread_Process(cvmx_wqe_t *wq);
extern void dp_sync_srv();
extern int srv_sync_dp_init();
extern void dp_sync_dp();

#endif
