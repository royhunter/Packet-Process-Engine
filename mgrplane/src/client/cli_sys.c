#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "cparser.h"
#include "cparser_token.h"


#include "common.h"
#include "message.h"
#include "cli_trans.h"




cparser_result_t
cparser_cmd_show_interface_id(cparser_context_t *context, uint32_t *id)
{
    assert(context);
    assert(id);

    char command[20] = { 0 };

    if(*id > 3)
    {
        printf("interface %d is not exist!\n", *id);
        return CPARSER_NOT_OK;
    }

    printf("Interface %d rx(pkts):\n", *id);
    printf("----------------------------------------------------\n");
    sprintf(command, "oct-linux-csr GMX0_RX%d_STATS_PKTS\n", *id);
    system(command);
    printf("----------------------------------------------------\n");
    printf("Interface %d rx(bytes):\n", *id);
    printf("----------------------------------------------------\n");
    memset(command, 0, sizeof(command));
    sprintf(command, "oct-linux-csr GMX0_RX%d_STATS_OCTS\n", *id);
    system(command);
    printf("----------------------------------------------------\n");
    printf("\n");
    printf("\n");
    printf("Interface %d tx(pkts):\n", *id);
    printf("----------------------------------------------------\n");
    memset(command, 0, sizeof(command));
    sprintf(command, "oct-linux-csr GMX0_TX%d_STAT3\n", *id);
    system(command);
    printf("----------------------------------------------------\n");
    printf("Interface %d tx(bytes):\n", *id);
    printf("----------------------------------------------------\n");
    memset(command, 0, sizeof(command));
    sprintf(command, "oct-linux-csr GMX0_TX%d_STAT2\n", *id);
    system(command);
    printf("----------------------------------------------------\n");

    return CPARSER_OK;
}



cparser_result_t
cparser_cmd_show_fpa(cparser_context_t *context)
{
    assert(context);
    int i;
    char command[20] = { 0 };

    for(i = 0; i < 8; i++)
    {
        printf("fap %d:\n", i);
        memset(command, 0, sizeof(command));
        printf("----------------------------------------------------\n");
        sprintf(command, "oct-linux-csr FPA_QUE%d_AVAILABLE\n", i);
        system(command);
        printf("----------------------------------------------------\n");
        printf("\n");
    }

    return CPARSER_OK;
}



