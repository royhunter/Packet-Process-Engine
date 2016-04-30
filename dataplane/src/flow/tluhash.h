#ifndef __TLUHASH_H__
#define __TLUHASH_H__

#include <stdint.h>


static inline uint32_t TluHash(uint32_t u1,uint32_t u2)
{
    uint32_t a,b,c;
    a = u2 + 0x9e3779b9;
    b = u1 + 0x9e3779b9;
    c = 0;
    a = a - b; a = a - c; a = a ^ (c >> 13);
    b = b - c; b = b - a; b = b ^ (a << 8);
    c = c - a; c = c - b; c = c ^ (b >> 13);
    a = a - b; a = a - c; a = a ^ (c >> 12);
    b = b - c; b = b - a; b = b ^ (a << 16);
    c = c - a; c = c - b; c = c ^ (b >> 5);
    a = a - b; a = a - c; a = a ^ (c >> 3);
    b = b - c; b = b - a; b = b ^ (a << 10);
    c = c - a; c = c - b; c = c ^ (b >> 15);
    return (c);
}


static inline uint32_t flow_hashfn(uint8_t ucPro,uint32_t ulSrcIp,uint32_t ulDstIp,uint16_t usSrcPort,uint16_t usDstPort)
{
    uint32_t s_hash, d_hash, p_hash;

    s_hash = TluHash(ulSrcIp,usSrcPort);
    d_hash = TluHash(ulDstIp,usDstPort);
    p_hash = TluHash(ucPro, 0);

    return s_hash^d_hash^p_hash;
}






#endif
