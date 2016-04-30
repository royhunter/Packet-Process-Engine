#ifndef __RWLOCK_H__
#define __RWLOCK_H__





typedef struct {
    volatile unsigned int lock;
}rwlock_t;



static inline void rwlock_init(rwlock_t *rw)
{
    rw->lock = 0;
}



static inline void read_lock(rwlock_t *rw)
{
    unsigned int tmp;

    __asm__ __volatile__(
		"	.set	noreorder	# read_lock	\n"
		"1:	ll	    %1, %2  		        \n"
		"	bltz	%1, 1b			        \n"
		"	addu	%1, 1			        \n"
		"	sc	    %1, %0			        \n"
		"	beqzl	%1, 1b			        \n"
		"	nop						        \n"
		"	.set	reorder					\n"
		"	sync	                        \n"
		: "=m" (rw->lock), "=&r" (tmp)
		: "m" (rw->lock)
		: "memory");

}

static inline void read_unlock(rwlock_t *rw)
{
    unsigned int tmp;

    __asm__ __volatile__(
        "  sync                                 \n"
		"1:	ll	    %1, %2		# read_unlock	\n"
		"	sub	    %1, 1					    \n"
		"	sc	    %1, %0					    \n"
		"	beqzl	%1, 1b					    \n"
		: "=m" (rw->lock), "=&r" (tmp)
		: "m" (rw->lock)
		: "memory");
}

static inline int read_trylock(rwlock_t *rw)
{
    unsigned int tmp;
	int ret;

    __asm__ __volatile__(
		"	.set	noreorder	# read_trylock	\n"
		"	li	%2, 0					        \n"
		"1:	ll	%1, %3					        \n"
		"	bltz	%1, 2f					    \n"
		"	addu	%1, 1					    \n"
		"	sc	%1, %0					        \n"
		"	.set	reorder					    \n"
		"	beqzl	%1, 1b					    \n"
		"	nop 						        \n"
		"   sync                                \n"
		"	li	%2, 1					        \n"
		"2:							            \n"
		: "=m" (rw->lock), "=&r" (tmp), "=&r" (ret)
		: "m" (rw->lock)
		: "memory");

    return ret;
}


static inline void write_lock(rwlock_t *rw)
{
    unsigned int tmp;

    __asm__ __volatile__(
		"	.set	noreorder	  # write_lock	\n"
		"1:	ll	%1, %2					        \n"
		"	bnez	%1, 1b					    \n"
		"	lui	%1, 0x8000				        \n"
		"	sc	%1, %0					        \n"
		"	beqzl	%1, 1b					    \n"
		"	nop						            \n"
		"	.set	reorder					    \n"
		: "=m" (rw->lock), "=&r" (tmp)
		: "m" (rw->lock)
		: "memory");
}

static inline void write_unlock(rwlock_t *rw)
{
    __asm__ __volatile__(
    	"				   # write_unlock	\n"
    	" sw	$0, %0					    \n"
    	: "=m" (rw->lock)
    	: "m" (rw->lock)
    	: "memory");
}


static inline int write_trylock(rwlock_t *rw)
{
    unsigned int tmp;
	int ret;

    __asm__ __volatile__(
		"	.set	noreorder	# write_trylock	\n"
		"	li	%2, 0					        \n"
		"1:	ll	%1, %3					        \n"
		"	bnez	%1, 2f				    	\n"
		"	lui	%1, 0x8000				        \n"
		"	sc	%1, %0					        \n"
		"	beqzl	%1, 1b				    	\n"
		"	nop						            \n"
		"   sync                                \n"
		"	li	%2, 1					        \n"
		"	.set	reorder					    \n"
		"2:							            \n"
		"   sync                                \n"
		: "=m" (rw->lock), "=&r" (tmp), "=&r" (ret)
		: "m" (rw->lock)
		: "memory");

    return ret;
}





#endif
