#ifndef __OCT_ARCH_H__
#define __OCT_ARCH_H__



#include <cvmx-coremask.h>

#define LOCAL_CPU_ID  cvmx_get_core_num()


#define CPU_DP_THREAD_MASTER  1


#define CPU_HW_RUNNING_MAX    4




#define IS_DP_MASTER_THREAD  (LOCAL_CPU_ID == CPU_DP_THREAD_MASTER)



#endif
