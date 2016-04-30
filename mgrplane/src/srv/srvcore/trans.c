#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include "trans.h"
#include "message.h"

#include "pow.h"




fd_set rfds;
int maxfd = 0;
int listenfd = -1;
SOCK_MAP sock_map[SOCK_MAX];
int g_client_connect_num = 0;
int current_sock_fd = 0;



static void sock_map_init(void)
{
    int32_t i = 0;

    for (i = 0; i < SOCK_MAX; i++) {
        sock_map[i].status = INVALID;
        sock_map[i].conn_num = 0;
        sock_map[i].account_id = -1;
        memset((void *)&sock_map[i].addr, 0, sizeof(struct sockaddr_in));
    }
}

void add_fd(SOCK_TYPE_T sock_type, int fd, struct sockaddr_in *addr)
{
    sock_map[fd].sock_type = sock_type;
    if (sock_type == TCP_CLIENT) {
        sock_map[fd].status = CONNETED;
        sock_map[fd].conn_num = 0;
    } else {
        sock_map[fd].status = OPERATIONAL;
    }
    sock_map[fd].account_id = -1;

    if (addr) {
        memcpy(&sock_map[fd].addr, addr, sizeof(struct sockaddr_in));
    }
    FD_SET(fd, &rfds);

    maxfd = (maxfd - fd) >= 0 ? maxfd : fd;

    LOG("max fd %d\n", maxfd);
}



void del_fd(int fd)
{
    int i = 0;

    memset(&sock_map[fd], 0, sizeof(SOCK_MAP));
    sock_map[fd].status = INVALID;
    FD_CLR(fd, &rfds);

    if (fd == maxfd) {
        maxfd = 0;
        for (i = 0; i < SOCK_MAX; i++) {
            if (sock_map[i].status != INVALID && maxfd < i) {
                maxfd = i;
            }

        }

    }
    g_client_connect_num--;
}

int recv_tcp_client_packet(int32_t fd, uint8_t * rbuf, uint32_t * rlen_p)
{
    MESSAGE_HEAD *m_head;
    int32_t len;
    int32_t total_len;
    int32_t data_len;

    *rlen_p = 0;
    LOG("begin recv....\n");
    /* first receive the rcp header */
    len = recv(fd, rbuf, MESSAGE_HEADER_LENGTH, 0);
    if (len != MESSAGE_HEADER_LENGTH) {
        LOG("tcpclient socket %d receive rcp header failed\n", fd);
        return 1;
    }
    LOG("recv data len: %d\n", len);


    *rlen_p = MESSAGE_HEADER_LENGTH;
    m_head = (MESSAGE_HEAD *) rbuf;

    total_len = (m_head->length) << 2;
    data_len = total_len - MESSAGE_HEADER_LENGTH;
    LOG("total_len is %d, data_len is %d\n",total_len, data_len);

    /* get the data block */
    if (data_len) {
        len = recv(fd, rbuf + MESSAGE_HEADER_LENGTH, data_len, 0);
        if (len != data_len) {
            LOG("tcpclient socket %d receive rcp data block failed,data_len=%d,total_len=%d\n", fd, data_len, total_len);
            *rlen_p += len;
            return 1;
        }
    }

    *rlen_p += data_len;

    return 0;
}

int tcp_client_message_handle(uint8_t * from, uint32_t length, uint32_t fd)
{
    MESSAGE_HEAD *m_head;
    uint16_t m_code;

    LOG("in tcp_client_message_handle\n");
    m_head = (MESSAGE_HEAD *) from;
    m_code = m_head->msg_code;

    LOG("cli msg code 0x%x, data_block_num %d\n", m_code, m_head->data_block_num);

    mgmt_process_cmd(from, length, fd);

    return 0;
}


int tcp_server_socket_create(void)
{
    struct sockaddr_in server_addr;
    int opt = 1;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == listenfd)
    {
        LOG("cann't create a socket for listen\n");
        return -1;
    }

    memset((void *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERV_CLI_PORT);

    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(int));

    if (-1 == bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        LOG("bind error\n");
        return -1;
    }

    listen(listenfd, 10);

    return listenfd;
}

void cleanup_all(int signo)
{
    int32_t i = 0;

    for (i = 0; i < SOCK_MAX; i++) {
        if (sock_map[i].status != INVALID) {
            close(i);
        }
    }

    exit(-1);
}



int server_init(void)
{
    int fd = -1;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, cleanup_all);

    FD_ZERO(&rfds);

    sock_map_init();


    /* initialize the rcp message handle */
    init_msg_pack_handle();
    init_msg_header();
    init_cmd_process_handle();


    fd = tcp_server_socket_create();
    add_fd(TCP_SERVER, fd, NULL);

#if 0
    if(pow_init() < 0)
    {
        printf("pow init failed\n");
        exit(1);
    }
#endif

    return 0;
}







void server_run(void)
{
    fd_set trfds;
    int retval, ret, i;
    int conn_fd;
    struct sockaddr_in addr;
    struct timeval tv;
    uint8_t buf_r[BUFSIZE];
    uint32_t length;

    while(1)
    {
        trfds = rfds;
        tv.tv_sec = 0;
        tv.tv_usec = 500;

        retval = select(maxfd + 1, &trfds, NULL, NULL, &tv);
        if(-1 == retval)
        {
            LOG("select error\n");
        }
        else if(0 == retval)
        {
            /*timeout*/
        }
        else
        {
            /* process tcp client request */
            if (FD_ISSET(listenfd, &trfds))
            {
                LOG("connect input\n");
                memset((void *)&addr, 0, sizeof(addr));
                length = sizeof(addr);
                conn_fd = accept(listenfd, (struct sockaddr *)&addr, &length);
                if(conn_fd > 0)
                {
                    add_fd(TCP_CLIENT, conn_fd, &addr);
                    g_client_connect_num++;
                    LOG("new client %d connected whose ip=%s port=%d\n",
                            conn_fd, inet_ntoa(addr.sin_addr), addr.sin_port);
                    current_sock_fd = conn_fd;
                }
            }

            for (i = 3; i < SOCK_MAX; i++)
            {
                if (sock_map[i].status == INVALID)
                {
                    continue;
                }
                if (FD_ISSET(i, &trfds))
                {

                    LOG("socket %d has data,type=%d\n", i, sock_map[i].sock_type);
                    switch (sock_map[i].sock_type)
                    {
                        /* process tcp request */
                        case TCP_CLIENT:
                        {
                            ret = recv_tcp_client_packet(i, buf_r, &length);
                            current_sock_fd = i;
                            if (ret == 0)
                            {
                                //dump_packet(buf_r, length);
                                ret = tcp_client_message_handle(buf_r, length, i);
                            } else
                                LOG("tcpserver socket recv length is less\n" );
                            break;
                        }
                        default:
                        {
                            LOG("select unknow socket type = %d\n", sock_map[i].sock_type);
                            break;
                        }
                    }
                    /*
                          *  if some rcpclient close the connect, clean up some resource
                          */
                    if (length <= 0) {
                        if (sock_map[i].sock_type == TCP_CLIENT)
                        {
                            close(i);
                            del_fd(i);
                            LOG("%d socket del\n", i);
                        }
                    }
                }
            }
        }
    }
}



int send_rcp_res(cmd_type_t cmd_ack, uint8_t * from, uint8_t *sbuf, uint32_t fd, void *param_p, char more_flag)
{
    int sn;
    int rv;
    struct rcp_msg_params_s *rcp_param_p = (struct rcp_msg_params_s *)param_p;
    int align_show;

    rcp_param_p->more_flag = more_flag;

    if ((align_show = rcp_param_p->info_len % 4) != 0) {
        rcp_param_p->info_len += 4 - align_show;
    }

    /* genarate pakcket from the parameters */
    memset(sbuf, 0, MAX_BUF);
    rv = param_to_pkt(cmd_ack, from, sbuf, &sn, param_p);
    if (rv) {
        LOG("Error:cmd=%d, more_flag=%d, sn=%d\n", cmd_ack, more_flag, sn);
        return rv;
    }

    send(fd, sbuf, sn, 0);

    memset(rcp_param_p, 0, sizeof(struct rcp_msg_params_s));

    return 0;
}


