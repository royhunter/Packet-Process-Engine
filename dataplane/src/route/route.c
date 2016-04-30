#include "route.h"
#include "oct-rxtx.h"


void Route_Process(mbuf_t *mb)
{

    //PACKET_DESTROY_ALL(mb);

 /*
   * fw to port
   * oct_tx_process_mbuf_toport(mb, 0);
   */

    oct_tx_process_hw(mb, 0);
    return;
}




