#ifndef __SEC_COMMON_H__
#define __SEC_COMMON_H__


#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>



#include "sec-debug.h"

#define SEC_OK  0
#define SEC_NO  1



#define SEC_FW    0
#define SEC_DROP  1
#define SEC_CACHE 2







/* Begin: below add by fengqb 2014/12/19 */

/* Engine stage/status*/
enum {
    SEC_FW_INIT = 0,
    SEC_FW_RUNTIME,
    SEC_FW_DEINIT
};

/* End. by fengqb */

#endif