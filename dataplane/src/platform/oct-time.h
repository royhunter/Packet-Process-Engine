#ifndef __OCT_TIME_H__
#define __OCT_TIME_H__


#include <sec-common.h>

extern uint64_t global_time;
extern uint64_t seconds_since1970;


#define OCT_TIME_SECONDS_SINCE1970 seconds_since1970

extern void oct_time_update();



#endif
