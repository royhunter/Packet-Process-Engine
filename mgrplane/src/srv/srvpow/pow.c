#include "pow.h"
#include "rpc-common.h"


comm_info_t comm_pow;



static int32_t __get_ifindex( const char *device )
{
    int32_t sock;
    struct ifreq ifr;

    sock = socket( AF_INET,SOCK_DGRAM, 0 );
    if ( sock < 0 ){
        //perror( "socket" );
        return ( 0 );
    }
    memset( ( char * )&ifr, 0, sizeof( ifr ) );
    strcpy( ifr.ifr_name, device );
    if ( ioctl( sock, SIOCGIFINDEX, ( char * )&ifr ) < 0 ){
        //perror( "ioctl" );
    }
    close( sock );
    return ifr.ifr_ifindex;
}

static int32_t __get_macaddr( char *device,char *mac )
{
    int32_t sock;
    struct ifreq ifr;

    strncpy( ifr.ifr_name, device, IFNAMSIZ );
    memset( mac, 0x00, 6 );
    sock = socket( AF_INET, SOCK_DGRAM, 0 );
    if ( sock < 0 ){
        //perror( "socket" );
        return ( 0 );
    }
    if ( ioctl( sock, SIOCGIFHWADDR, ( caddr_t )&ifr ) < 0 ){
        close( sock );
        return -1;
    }
    memcpy( mac, ifr.ifr_hwaddr.sa_data, 6 );
    close( sock );
    return 0;
}



int32_t pow_send_fn( comm_info_t *info, void *data, uint32_t size )
{
    int32_t len;
    struct sockaddr_ll sll;

    bzero(&sll, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, info->pow.mac, 6);
    sll.sll_ifindex = info->pow.ifindex;
    len = sendto( info->pow.fd, data, size, 0, (struct sockaddr *)&sll, sizeof( sll ) );
    //printf("send len is %d, %d\n", len, errno);
    //printf("errno  %d is: %s\n", errno, strerror(errno));

    if ( len == -1 ){

        return -1;
    }

    if ( len < (int32_t)size ){
        return -1;
    } else {
        return 0;
    }
}

int32_t pow_recv_fn ( comm_info_t *info, void *data, uint32_t *size )
{
    uint8_t *_data;
    int32_t len;

    _data = malloc(MAX_RECV_LEN);
    if(_data == NULL){
        //printf("malloc error\n");
        return -1;
    }
    memset(_data,0,MAX_RECV_LEN);
    len = recvfrom( info->pow.fd, _data, *size, 0, NULL, NULL);
    //printf("recv len is %d, %d\n", len, errno);
    //printf("errno  %d is: %s\n", errno, strerror(errno));
    memcpy(data, _data+14, len-14);
    free(_data);

    if ( len < 0 ){
        return len;
    } else {
        *size = len - 14;
        return 0;
    }
}



int32_t pow_open_fn( comm_info_t *info)
{
    int32_t psfd;
    int32_t ifindex = 0;
    uint16_t eth_type = 0;

    if ( ( ifindex = __get_ifindex( "pow0" ) ) <= 0 ) {
        return ( -1 );
    }

    eth_type = ETH_P;

    __get_macaddr( "pow0", (char*)info->pow.mac );

    if ( ( psfd = socket( AF_PACKET, SOCK_RAW, htons( eth_type  ) ) ) < 0 ){
        return psfd;
    }
    info->pow.fd = psfd;
    info->pow.ifindex = ifindex;
    return 0;
}


int32_t pow_close_fn( comm_info_t *info )
{
    if( info->pow.fd > 0 ){
        close( info->pow.fd );
    }
    return 0;
}



int pow_init(void)
{
    memset((void *)&comm_pow, 0, sizeof(comm_info_t));

    return pow_open_fn(&comm_pow);

}






