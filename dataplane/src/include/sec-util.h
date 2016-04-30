#ifndef __SEC_UTIL_H__
#define __SEC_UTIL_H__


#define CACHE_LINE_SIZE 128
#define CACHE_LINE_MASK (CACHE_LINE_SIZE-1) /**< Cache line mask. */

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif


#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)])) 
#endif


#define prefetch(address) CVMX_PREFETCH(address, 0)


#ifndef offsetof
#define offsetof(type, field)  ((size_t) &( ((type *)0)->field) )
#endif



/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({          \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type,member) );})




#define CACHE_ALIGNED __attribute__((__aligned__(CACHE_LINE_SIZE)))



#endif
