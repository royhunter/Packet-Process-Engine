#ifndef __COMMON__H__
#define __COMMON__H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>


#define DEBUG_PRINT

extern int debugprint;

#ifdef DEBUG_PRINT
#define LOG(str...)   \
{                     \
    if(debugprint)    \
    {                 \
        printf(str);  \
    }                 \
}
#else
#define LOG(str...)
#endif


#define OK 1
#define ERR 0

#define MAX_FILE_NAME 32
#define MAX_CMD_BUFFER_SIZE 256

typedef struct _time_info
{
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
}time_info;

typedef struct 
{
    uint32_t ip;
}ipv4_addr;


typedef struct
{
    uint64_t ip_high;
    uint64_t ip_low;
}ipv6_addr;






#ifdef __cplusplus
}
#endif


#endif
