#include <mbuf.h>
#include <oct-rxtx.h>
#include <sec-debug.h>

#include <flow.h>


uint32_t l7_deliver(mbuf_t *m)
{
#ifdef SEC_L7_DEBUG
   printf("===============>l7 enter\n");
#endif

    oct_tx_process_mbuf(m);

    return 0;
}


void l7_flow_release(flow_item_t *f)
{
	return;
}

