#include "message.h"


int debugprint = 0;


struct msg_header_info_s cmd_msg_headers[MAX_COMMAND_TYPE + 1];
struct msg_pack_handle_s cmd_msg_handles[MAX_COMMAND_TYPE + 1];
struct cmd_process_handle_s cmd_process_handles[MAX_COMMAND_TYPE + 1];

/*
  * get data block length
  */
static int __get_data_block_length(int block_type, int *block_length_p)
{
    switch (block_type) {
    case BLOCK_TYPE_START:
        *block_length_p = 0;
        break;
    case BLOCK_IPV4_FIVE_TUPLE:
        *block_length_p = sizeof(RCP_BLOCK_IPV4_FIVE_TUPLE);
        break;
    case BLOCK_ACL_RULE_TUPLE:
        *block_length_p = sizeof(RCP_BLOCK_ACL_RULE_TUPLE);
        break;
    case BLOCK_RESULT_CODE:
        *block_length_p = sizeof(CLI_RESULT);
        break;
    case BLOCK_ACL_RULE_ID:
        *block_length_p = sizeof(RCP_BLOCK_ACL_RULE_ID);
        break;
    case BLOCK_ACL_DEF_ACT_ID:
        *block_length_p = sizeof(RCP_BLOCK_ACL_DEF_ACTION);
        break;
    case BLOCK_DBG_PRINT_ID:
        *block_length_p = sizeof(RCP_BLOCK_DBG_PRINT);
        break;
    case BLOCK_TCPSTREAM_TRACK:
        *block_length_p = sizeof(RCP_BLOCK_TCPSTREAM_TRACK_ABLE);
        break;
    case BLOCK_TCPSTREAM_REASM:
        *block_length_p = sizeof(RCP_BLOCK_TCPSTREAM_REASM_ABLE);
        break;
    case BLOCK_SYNCHECK_ID:
        *block_length_p = sizeof(RCP_BLOCK_TCPSTREAM_SYNCHECK_ABLE);
        break;
    case BLOCK_DEFRAG_MAX_ID:
        *block_length_p = sizeof(RCP_BLOCK_DEFRAG_MAX);
        break;
    case BLOCK_UNSUPPORTACTION_ID:
        *block_length_p = sizeof(RCP_BLOCK_UNSUPPORT_PROTO_ACTION);
        break;
    case BLOCK_DIRECTFW_ABLE_ID:
        *block_length_p = sizeof(RCP_BLOCK_DIRECTFW_ABLE);
        break;
    case BLOCK_PORTSCAN_ID:
        *block_length_p = sizeof(RCP_BLOCK_PORTSCAN_ABLE);
        break;
    case BLOCK_PORTSCAN_ACTION_ID:
        *block_length_p = sizeof(RCP_BLOCK_PORTSCAN_ACTION);
        break;
    case BLOCK_ATTACK_DEFEND_TIME_ID:
        *block_length_p = sizeof(RCP_BLOCK_DEFEND_TIME);
        break;
    case BLOCK_PORTSCAN_FREQ_ID:
        *block_length_p = sizeof(RCP_BLOCK_PORTSCAN_FREQ);
        break;
    case BLOCK_SYNFLOOD_START_ID:
        *block_length_p = sizeof(RCP_BLOCK_SYNFLOOD_START);
        break;
    case BLOCK_MODBUS_ABLE_ID:
        *block_length_p = sizeof(RCP_BLOCK_MODBUS_ABLE);
        break;
    case BLOCK_MODBUS_VALUE_ID:
        *block_length_p = sizeof(RCP_BLOCK_MODBUS_VALUE);
        break;
    default:
        *block_length_p = 0;
        break;
    }

    if(*block_length_p > 0)
        return 0;
    else
        return 1;
}


static int __cmd_is_valid(cmd_type_t cmd)
{
    if (cmd < MAX_COMMAND_TYPE)
        return 0;

    else {
        LOG("cmd=%d is invalid\n", cmd);
        return 1;
    }
}

/*
  * parse the message header and get the cmd type
  */
int get_cmd_type(cmd_type_t * cmd_p, MESSAGE_HEAD * header_p)
{
    uint32_t i;
    int found = 0;

    for (i = 0; i < sizeof(cmd_msg_headers) / sizeof(cmd_msg_headers[0]); i++) {
        if (header_p->flag == cmd_msg_headers[i].flag &&
            header_p->msg_type == cmd_msg_headers[i].msg_type &&
            header_p->msg_code == cmd_msg_headers[i].msg_code &&
            header_p->blocktype == cmd_msg_headers[i].msg_block_type) {

            *cmd_p = i;

            found = 1;

            LOG("i=%d,msg_type=0x%x,msg_code=0x%x,blocktype=0x%x\n", i, header_p->msg_type, header_p->msg_code, header_p->blocktype);

            break;

        }
    }
    if (found == 1)
        return 0;

    else
        return 1;
}


/*
  * Function:   fill the message header
  */
int encap_msg_header(cmd_type_t cmd, struct rcp_msg_params_s *param_p, MESSAGE_HEAD * header_p)
{
    int block_length;
    header_p->flag = cmd_msg_headers[cmd].flag;
    header_p->msg_type = cmd_msg_headers[cmd].msg_type;

    header_p->msg_code = cmd_msg_headers[cmd].msg_code;

    header_p->blocktype = cmd_msg_headers[cmd].msg_block_type;

    header_p->msg_id = param_p->msg_id;
    header_p->more_flag = param_p->more_flag;
    header_p->data_block_num = param_p->nparam;
    __get_data_block_length(header_p->blocktype, &block_length);

    /* number of 4 bytes */
    header_p->length = ((header_p->data_block_num) * block_length + sizeof(MESSAGE_HEAD)) >> 2;
    return 0;
}

int pack_acl_rule_id(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_ACL_RULE_ID);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].AclRuleId), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}

int pack_acl_def_act(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_ACL_DEF_ACTION);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].AclDefAct), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}


int pack_dbg_print(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_DBG_PRINT);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}

int pack_tcpstream_track(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_TCPSTREAM_TRACK_ABLE);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}


int pack_directfw_able(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_DIRECTFW_ABLE);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}


int pack_portscan(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_PORTSCAN_ABLE);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}


int pack_modbus_able(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_MODBUS_ABLE);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}


int pack_modbus_value(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_MODBUS_VALUE);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}



int pack_tcpstream_reasm(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_TCPSTREAM_REASM_ABLE);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}


int pack_syncheck_reasm(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_TCPSTREAM_SYNCHECK_ABLE);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}


int pack_defrag_max(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_DEFRAG_MAX);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}

int pack_unsupport_action(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_UNSUPPORT_PROTO_ACTION);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}

int pack_portscan_action(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_PORTSCAN_ACTION);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}

int pack_attack_defend_time(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_DEFEND_TIME);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}


int pack_portscan_freq(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_PORTSCAN_FREQ);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}


int pack_synflood_start(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_SYNFLOOD_START);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].DbgPrint), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}


int pack_acl_rule(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    int block_index;
    int block_length;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;

    LOG("cmd=%d, nparam=%d\n", cmd, lpara_p->nparam);

    /* copy the data block to sbuf */
    block_length = sizeof(RCP_BLOCK_ACL_RULE_TUPLE);
    LOG("blocklength is %d\n", block_length);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].AclRuleTuple), block_length);
        ptr += block_length;
        *len_p += block_length;
    }

    return 0;
}

int pack_result_code(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    int block_index;
    int block_length;
    char *ptr = (char *)sbuf;
    MESSAGE_HEAD msg_header;

    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    encap_msg_header(cmd, lpara_p, &msg_header);
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;
    block_length = sizeof(RCP_BLOCK_RESULT);
    for (block_index = 0; block_index < lpara_p->nparam; block_index++) {
        memcpy(ptr, &(lpara_p->params_list.params[block_index].ResultCode), block_length);
        ptr += block_length;
        *len_p += block_length;
    }
    return 0;
}


int pack_null(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    /* fill the message header */
    encap_msg_header(cmd, lpara_p, &msg_header);

    /* copy the header to sbuf */
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;
    return 0;
}



int pack_show_info(cmd_type_t cmd, void *para_p, void *sbuf, int *len_p)
{
    int rv;
    char *ptr = (char *)sbuf;
    MESSAGE_HEAD msg_header;
    struct rcp_msg_params_s *lpara_p = (struct rcp_msg_params_s *)para_p;
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    encap_msg_header(cmd, lpara_p, &msg_header);
    LOG("info len is %d\n", lpara_p->info_len);
    msg_header.length = (uint32_t) ((MESSAGE_HEADER_LENGTH + lpara_p->info_len) >> 2);
    LOG("info len is %d, len is %d\n", lpara_p->info_len, msg_header.length);
    memcpy(ptr, &msg_header, MESSAGE_HEADER_LENGTH);
    *len_p = MESSAGE_HEADER_LENGTH;
    ptr += MESSAGE_HEADER_LENGTH;
    LOG("cmd=%d, info_len=%d\n", cmd, lpara_p->info_len);
    memcpy(ptr, lpara_p->params_list.info_buf, lpara_p->info_len);
    ptr += lpara_p->info_len;
    *len_p += lpara_p->info_len;
    return 0;
}

/*
  * Function:       genarate the packet from parameters
  */
int param_to_pkt(cmd_type_t cmd, void *from, uint8_t *sbuf, int *sn_p, void *param_p)
{
    int rv;
    MESSAGE_HEAD *msg_header = (MESSAGE_HEAD *) from;
    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;

    /* first check the cmd */
    rv = __cmd_is_valid(cmd);
    if (rv) {
        LOG("cmd=%d is not valid\n", cmd);
        return rv;
    }

    /* make sure the msg id of responese is the same as the request */
    rcp_param_p->msg_id = msg_header->msg_id;

    /* then pack the rcp header and rcp data block */
    cmd_msg_handles[cmd].pack(cmd, param_p, sbuf, sn_p);
    return 0;
}





int mgmt_process_cmd(uint8_t * from, uint32_t length, uint32_t fd)
{
    int rv;
    cmd_type_t cmd = -1;
    MESSAGE_HEAD *msg_header = (MESSAGE_HEAD *) from;
    get_cmd_type(&cmd, msg_header);
    LOG("cmd=%d\n", cmd);
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    if (cmd_process_handles[cmd].handle == NULL) {
        LOG("Error:cmd=%d has not register process handle\n", cmd);
        return 1;
    }

    /* process the command */
    cmd_process_handles[cmd].handle(from, length, fd);
    return 0;
}


/*
  * register the command msg pack handle
  */
int register_msg_pack_handle(cmd_type_t cmd, msg_pack_handle_t pack_handle)
{
    int rv;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;
    cmd_msg_handles[cmd].cmd = cmd;
    cmd_msg_handles[cmd].pack = pack_handle;
    return 0;
}


/*
  * register the command process handle
  */
int register_cmd_process_handle(cmd_type_t cmd, cmd_proc_handle_t cmd_handle)
{
    int rv;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if(rv)
        return rv;

    cmd_process_handles[cmd].cmd = cmd;
    cmd_process_handles[cmd].handle = cmd_handle;
    return 0;
}

/*
  * Initialize the msg pack handles
  */
int init_msg_pack_handle(void)
{
    memset(cmd_msg_handles, 0, sizeof(struct msg_pack_handle_s) * (MAX_COMMAND_TYPE + 1));

    register_msg_pack_handle(TEST_COMMAND, pack_null);
    register_msg_pack_handle(TEST_COMMAND_ACK, pack_show_info);

    register_msg_pack_handle(SHOW_DP_BUILD_TIME, pack_null);
    register_msg_pack_handle(SHOW_DP_BUILD_TIME_ACK, pack_show_info);

    register_msg_pack_handle(SHOW_DP_PKT_STAT, pack_null);
    register_msg_pack_handle(SHOW_DP_PKT_STAT_ACK, pack_show_info);

    register_msg_pack_handle(SHOW_MEM_POOL, pack_null);
    register_msg_pack_handle(SHOW_MEM_POOL_ACK, pack_show_info);

    register_msg_pack_handle(SHOW_ACL_RULE, pack_null);
    register_msg_pack_handle(SHOW_ACL_RULE_ACK, pack_show_info);

    register_msg_pack_handle(ADD_ACL_RULE, pack_acl_rule);
    register_msg_pack_handle(ADD_ACL_RULE_ACK, pack_result_code);

    register_msg_pack_handle(DEL_ACL_RULE, pack_acl_rule);
    register_msg_pack_handle(DEL_ACL_RULE_ACK, pack_result_code);

    register_msg_pack_handle(DEL_ACL_RULE_ID, pack_acl_rule_id);
    register_msg_pack_handle(DEL_ACL_RULE_ID_ACK, pack_result_code);

    register_msg_pack_handle(DEL_ACL_RULE_ALL, pack_null);
    register_msg_pack_handle(DEL_ACL_RULE_ALL_ACK, pack_result_code);

    register_msg_pack_handle(COMMIT_ACL_RULE, pack_null);
    register_msg_pack_handle(COMMIT_ACL_RULE_ACK, pack_show_info);

    register_msg_pack_handle(SET_ACL_DEF_ACT, pack_acl_def_act);
    register_msg_pack_handle(SET_ACL_DEF_ACT_ACK, pack_show_info);

    register_msg_pack_handle(SHOW_ACL_DEF_ACT, pack_null);
    register_msg_pack_handle(SHOW_ACL_DEF_ACT_ACK, pack_show_info);

    register_msg_pack_handle(CLEAR_DP_PKT_STAT, pack_null);
    register_msg_pack_handle(CLEAR_DP_PKT_STAT_ACK, pack_show_info);

    register_msg_pack_handle(SHOW_FW_FLOW_STAT, pack_null);
    register_msg_pack_handle(SHOW_FW_FLOW_STAT_ACK, pack_show_info);

    register_msg_pack_handle(CLEAR_FW_FLOW_STAT, pack_null);
    register_msg_pack_handle(CLEAR_FW_FLOW_STAT_ACK, pack_show_info);

    register_msg_pack_handle(SET_DBG_PRINT, pack_dbg_print);
    register_msg_pack_handle(SET_DBG_PRINT_ACK, pack_show_info);

    register_msg_pack_handle(CLEAR_DBG_PRINT, pack_null);
    register_msg_pack_handle(CLEAR_DBG_PRINT_ACK, pack_show_info);

    register_msg_pack_handle(SHOW_TCPSTREAM_STAT, pack_null);
    register_msg_pack_handle(SHOW_TCPSTREAM_STAT_ACK, pack_show_info);

    register_msg_pack_handle(CLEAR_TCPSTREAM_STAT, pack_null);
    register_msg_pack_handle(CLEAR_TCPSTREAM_STAT_ACK, pack_show_info);

    register_msg_pack_handle(SET_TCPSTREAM_TRACK_ABLE, pack_tcpstream_track);
    register_msg_pack_handle(SET_TCPSTREAM_TRACK_ABLE_ACK, pack_show_info);

    register_msg_pack_handle(SET_TCPSTREAM_REASM_ABLE, pack_tcpstream_reasm);
    register_msg_pack_handle(SET_TCPSTREAM_REASM_ABLE_ACK, pack_show_info);

    register_msg_pack_handle(SET_SYNCHECK_ABLE, pack_syncheck_reasm);
    register_msg_pack_handle(SET_SYNCHECK_ABLE_ACK, pack_show_info);

    register_msg_pack_handle(SET_DEFRAG_MAX, pack_defrag_max);
    register_msg_pack_handle(SET_DEFRAG_MAX_ACK, pack_show_info);

    register_msg_pack_handle(SHOW_ATTACK_STAT, pack_null);
    register_msg_pack_handle(SHOW_ATTACK_STAT_ACK, pack_show_info);

    register_msg_pack_handle(SET_UNSUPPORT_PROTO_ACTION,pack_unsupport_action);
    register_msg_pack_handle(SET_UNSUPPORT_PROTO_ACTION_ACK,pack_show_info);

    register_msg_pack_handle(SET_DIRECT_FW, pack_directfw_able);
    register_msg_pack_handle(SET_DIRECT_FW_ACK, pack_show_info);

    register_msg_pack_handle(SHOW_FW_CONFIG, pack_null);
    register_msg_pack_handle(SHOW_FW_CONFIG_ACK, pack_show_info);

    register_msg_pack_handle(SET_PORTSCAN_ABLE, pack_portscan);
    register_msg_pack_handle(SET_PORTSCAN_ABLE_ACK, pack_show_info);

    register_msg_pack_handle(SET_PORTSCAN_ACTION,pack_portscan_action);
    register_msg_pack_handle(SET_PORTSCAN_ACTION_ACK,pack_show_info);

    register_msg_pack_handle(SET_ATTACK_DEFEND_TIME,pack_attack_defend_time);
    register_msg_pack_handle(SET_ATTACK_DEFEND_TIME_ACK,pack_show_info);

    register_msg_pack_handle(SET_PORTSCAN_FREQ,pack_portscan_freq);
    register_msg_pack_handle(SET_PORTSCAN_FREQ_ACK,pack_show_info);

    register_msg_pack_handle(SET_SYNFLOOD_START,pack_synflood_start);
    register_msg_pack_handle(SET_SYNFLOOD_START_ACK,pack_show_info);

    register_msg_pack_handle(SET_MODBUS_ABLE, pack_modbus_able);
    register_msg_pack_handle(SET_MODBUS_ABLE_ACK, pack_show_info);

    register_msg_pack_handle(SET_MODBUS_VALUE,pack_modbus_value);
    register_msg_pack_handle(SET_MODBUS_VALUE_ACK,pack_show_info);

    return 0;
}
/*
  * register the command msg header info
  */
int register_msg_header(uint8_t flag, cmd_type_t cmd, uint8_t msg_type, uint16_t msg_code, uint8_t msg_block_type)
{
    int rv;

    /* make sure the cmd type is valid */
    rv = __cmd_is_valid(cmd);
    if (rv)
        return rv;

    cmd_msg_headers[cmd].flag = flag;
    cmd_msg_headers[cmd].cmd = cmd;
    cmd_msg_headers[cmd].msg_type = msg_type;
    cmd_msg_headers[cmd].msg_code = msg_code;
    cmd_msg_headers[cmd].msg_block_type = msg_block_type;

    return 0;
}

/*
  * Initialize the msg header info
  */
int init_msg_header(void)
{
    memset(cmd_msg_headers, 0, sizeof(struct msg_header_info_s) * (MAX_COMMAND_TYPE + 1));

    register_msg_header(MSG_VALID_FLAG, TEST_COMMAND, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_TEST_COMMAND, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, TEST_COMMAND_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_TEST_COMMAND_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SHOW_DP_BUILD_TIME, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_DP_BUILD_TIME, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, SHOW_DP_BUILD_TIME_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_DP_BUILD_TIME_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SHOW_DP_PKT_STAT, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_DP_PKT_STAT, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, SHOW_DP_PKT_STAT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_DP_PKT_STAT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SHOW_MEM_POOL, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_MEM_POOL, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, SHOW_MEM_POOL_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_MEM_POOL_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SHOW_ACL_RULE, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_ACL_RULE, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, SHOW_ACL_RULE_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_ACL_RULE_ACK, BLOCK_RESULT_CODE);

    register_msg_header(MSG_VALID_FLAG, ADD_ACL_RULE, MSG_TYPE_CLI_OCTEON, MSG_CODE_ADD_ACL_RULE, BLOCK_ACL_RULE_TUPLE);
    register_msg_header(MSG_VALID_FLAG, ADD_ACL_RULE_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_ADD_ACL_RULE_ACK, BLOCK_RESULT_CODE);

    register_msg_header(MSG_VALID_FLAG, DEL_ACL_RULE, MSG_TYPE_CLI_OCTEON, MSG_CODE_DEL_ACL_RULE, BLOCK_ACL_RULE_TUPLE);
    register_msg_header(MSG_VALID_FLAG, DEL_ACL_RULE_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_DEL_ACL_RULE_ACK, BLOCK_RESULT_CODE);

    register_msg_header(MSG_VALID_FLAG, DEL_ACL_RULE_ID, MSG_TYPE_CLI_OCTEON, MSG_CODE_DEL_ACL_RULE_ID, BLOCK_ACL_RULE_ID);
    register_msg_header(MSG_VALID_FLAG, DEL_ACL_RULE_ID_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_DEL_ACL_RULE_ID_ACK, BLOCK_RESULT_CODE);

    register_msg_header(MSG_VALID_FLAG, DEL_ACL_RULE_ALL, MSG_TYPE_CLI_OCTEON, MSG_CODE_DEL_ACL_RULE_ALL, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, DEL_ACL_RULE_ALL_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_DEL_ACL_RULE_ALL_ACK, BLOCK_RESULT_CODE);

    register_msg_header(MSG_VALID_FLAG, COMMIT_ACL_RULE, MSG_TYPE_CLI_OCTEON, MSG_CODE_COMMIT_ACL_RULE, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, COMMIT_ACL_RULE_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_COMMIT_ACL_RULE_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_ACL_DEF_ACT, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_ACL_DEF_ACT, BLOCK_ACL_DEF_ACT_ID);
    register_msg_header(MSG_VALID_FLAG, SET_ACL_DEF_ACT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_ACL_DEF_ACT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SHOW_ACL_DEF_ACT, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_ACL_DEF_ACT, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, SHOW_ACL_DEF_ACT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_ACL_DEF_ACT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, CLEAR_DP_PKT_STAT, MSG_TYPE_CLI_OCTEON, MSG_CODE_CLEAR_DP_PKT_STAT, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, CLEAR_DP_PKT_STAT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_CLEAR_DP_PKT_STAT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, CLEAR_DP_PKT_STAT, MSG_TYPE_CLI_OCTEON, MSG_CODE_CLEAR_DP_PKT_STAT, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, CLEAR_DP_PKT_STAT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_CLEAR_DP_PKT_STAT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SHOW_FW_FLOW_STAT, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_FW_FLOW_STAT, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, SHOW_FW_FLOW_STAT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_FW_FLOW_STAT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, CLEAR_FW_FLOW_STAT, MSG_TYPE_CLI_OCTEON, MSG_CODE_CLEAR_FW_FLOW_STAT, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, CLEAR_FW_FLOW_STAT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_CLEAR_FW_FLOW_STAT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_DBG_PRINT, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_DBG_PRINT, BLOCK_DBG_PRINT_ID);
    register_msg_header(MSG_VALID_FLAG, SET_DBG_PRINT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_DBG_PRINT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, CLEAR_DBG_PRINT, MSG_TYPE_CLI_OCTEON, MSG_CODE_CLEAR_DBG_PRINT, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, CLEAR_DBG_PRINT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_CLEAR_DBG_PRINT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SHOW_TCPSTREAM_STAT, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_TCPSTREAM_STAT, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, SHOW_TCPSTREAM_STAT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_TCPSTREAM_STAT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, CLEAR_TCPSTREAM_STAT, MSG_TYPE_CLI_OCTEON, MSG_CODE_CLEAR_TCPSTREAM_STAT, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, CLEAR_TCPSTREAM_STAT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_CLEAR_TCPSTREAM_STAT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_TCPSTREAM_TRACK_ABLE, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_TCPSTREAM_TRACK, BLOCK_TCPSTREAM_TRACK);
    register_msg_header(MSG_VALID_FLAG, SET_TCPSTREAM_TRACK_ABLE_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_TCPSTREAM_TRACK_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_TCPSTREAM_REASM_ABLE, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_TCPSTREAM_REASM, BLOCK_TCPSTREAM_REASM);
    register_msg_header(MSG_VALID_FLAG, SET_TCPSTREAM_REASM_ABLE_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_TCPSTREAM_REASM_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_SYNCHECK_ABLE, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_SYNCHECK_ABLE, BLOCK_SYNCHECK_ID);
    register_msg_header(MSG_VALID_FLAG, SET_SYNCHECK_ABLE_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_SYNCHECK_ABLE_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_DEFRAG_MAX, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_DEFRAG_MAX, BLOCK_SYNCHECK_ID);
    register_msg_header(MSG_VALID_FLAG, SET_DEFRAG_MAX_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_DEFRAG_MAX_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SHOW_ATTACK_STAT, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_ATTACK_STAT, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, SHOW_ATTACK_STAT_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_ATTACK_STAT_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_UNSUPPORT_PROTO_ACTION, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_UNSUPPORT_PROTO_ACTION, BLOCK_UNSUPPORTACTION_ID);
    register_msg_header(MSG_VALID_FLAG, SET_UNSUPPORT_PROTO_ACTION_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_UNSUPPORT_PROTO_ACTION_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_DIRECT_FW, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_DIRECTFW_ABLE, BLOCK_DIRECTFW_ABLE_ID);
    register_msg_header(MSG_VALID_FLAG, SET_DIRECT_FW_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_DIRECTFW_ABLE_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SHOW_FW_CONFIG, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_FW_CONFIG, BLOCK_TYPE_START);
    register_msg_header(MSG_VALID_FLAG, SHOW_FW_CONFIG_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SHOW_FW_CONFIG_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_PORTSCAN_ABLE, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_PORTSCAN_ABLE, BLOCK_PORTSCAN_ID);
    register_msg_header(MSG_VALID_FLAG, SET_PORTSCAN_ABLE_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_PORTSCAN_ABLE_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_PORTSCAN_ACTION, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_PORTSCAN_ACTION, BLOCK_PORTSCAN_ACTION_ID);
    register_msg_header(MSG_VALID_FLAG, SET_PORTSCAN_ACTION_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_PORTSCAN_ACTION_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_ATTACK_DEFEND_TIME, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_ATTACK_DEFEND_TIME, BLOCK_ATTACK_DEFEND_TIME_ID);
    register_msg_header(MSG_VALID_FLAG, SET_ATTACK_DEFEND_TIME_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_ATTACK_DEFEND_TIME_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_PORTSCAN_FREQ, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_PORTSCAN_FREQ, BLOCK_PORTSCAN_FREQ_ID);
    register_msg_header(MSG_VALID_FLAG, SET_PORTSCAN_FREQ_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_PORTSCAN_FREQ_ACK, BLOCK_TYPE_START);

    register_msg_header(MSG_VALID_FLAG, SET_SYNFLOOD_START, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_SYNFLOOD_START, BLOCK_SYNFLOOD_START_ID);
    register_msg_header(MSG_VALID_FLAG, SET_SYNFLOOD_START_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_SYNFLOOD_START_ACK, BLOCK_TYPE_START);


    register_msg_header(MSG_VALID_FLAG, SET_MODBUS_ABLE, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_MODBUS_ABLE, BLOCK_MODBUS_ABLE_ID);
    register_msg_header(MSG_VALID_FLAG, SET_MODBUS_ABLE_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_MODBUS_ABLE_ACK, BLOCK_TYPE_START);


    register_msg_header(MSG_VALID_FLAG, SET_MODBUS_VALUE, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_MODBUS_VALUE, BLOCK_MODBUS_VALUE_ID);
    register_msg_header(MSG_VALID_FLAG, SET_MODBUS_VALUE_ACK, MSG_TYPE_CLI_OCTEON, MSG_CODE_SET_MODBUS_VALUE_ACK, BLOCK_TYPE_START);

    return 0;
}





