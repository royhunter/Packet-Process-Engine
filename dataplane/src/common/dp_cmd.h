#ifndef __DP_CMD_H__
#define __DP_CMD_H__

#include <oct-common.h>
#include <rpc-common.h>
#include <oct-init.h>
#include <oct-rxtx.h>

#include <sos_malloc.h>
#include <mem_pool.h>
#include <sec-debug.h>

extern sos_mem_pool_region_t *sos_mem_pool;
extern void oct_rx_process_command(cvmx_wqe_t *wq);
extern void DP_Msg_Process_Thread_Init();
extern void DP_NetStat_Monitor_Init();
extern void Decode_unsupport_proto_handle(mbuf_t *mbuf);


#endif
