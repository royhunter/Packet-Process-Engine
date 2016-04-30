#ifndef __SEC_DEBUG_H__
#define __SEC_DEBUG_H__

#include <sys/time.h>

#include <shm.h>


#define SEC_L7_DCERPC_DEBUG

#define SEC_DEBUG_PRINT

extern SRV_DP_SYNC *srv_dp_sync;;

#ifdef SEC_DEBUG_PRINT
#define LOGDBG(mask,str...)   \
{                     \
    if(srv_dp_sync->dp_debugprint & mask)    \
    {                 \
        printf(str);  \
    }                 \
}
#else
#define LOGDBG(mask, str...)
#endif

/* Begin: below add by fengqb 2014/12/18 */
#define SCEnter(...)
#define SCReturnUInt(x)                 return x
#define SCReturnInt(x)                  return x


// Debug Mask
#define DEBUG_NONE        0x0
#define DEBUG_APP_LAYER   0x00000001
#define DEBUG_WHITE_LIST  0x00000002
#define DEBUG_FLOWDATA    0x00000004
#define DEBUG_ALERT_JSON  0x00000004
#define DEBUG_DETECT_PROC 0x00000008
#define DEBUG_IPONLY_PROC 0x00000010
#define DEBUG_APP_DCERPC  0x00000020
#define DEBUG_LIB_NDROPC  0x00000040

#define DEBUG_ALL         0xFFFFFFFF

#define MAX_LOG_INFO 2048
void DebugPrint(int mask, const char* file, int line, const char* func, ...);

#define DEBUG_PRINT(mask, ...) do {  \
    DebugPrint(mask, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} while (0)

/* End. by fengqb */

#endif
