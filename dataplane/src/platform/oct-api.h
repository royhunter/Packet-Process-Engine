#ifndef __OCT_API_H__
#define __OCT_API_H__

#include <oct-common.h>








/*
  *    Port and optimize from cvmx_wqe_get_port()/cvmx_wqe.h
  */
static inline int oct_wqe_get_port(cvmx_wqe_t *work)
{
    return work->word1.cn38xx.ipprt;
}


/*
  *   Port and optimize from cvmx_wqe_get_len()/cvmx_wqe.h
  */
static inline int oct_wqe_get_len(cvmx_wqe_t *work)
{
    return work->word1.cn38xx.len;
}

/*
  *   Port and optimize from cvmx_wqe_get_bufs()/cvmx_wqe.h
  */
static inline int oct_wqe_get_bufs(cvmx_wqe_t *work)
{
	return work->word2.s.bufs;
}

/*
  *   Port and optimize from cvmx_wqe_get_grp()/cvmx_wqe.h
  */
static inline int oct_wqe_get_grp(cvmx_wqe_t *work)
{
    return work->word1.cn38xx.grp;
}

/*
  *   Port and optimize from cvmx_wqe_get_unused8()/cvmx_wqe.h
  */
static inline int oct_wqe_get_unused8(cvmx_wqe_t *work)
{
    return work->word0.pip.cn38xx.unused;
}



/*
  *   Port and optimize from cvmx_fpa_free()/cvmx_fpa.h
  */
static inline void oct_fpa_free(void *ptr, uint64_t pool,
				 uint64_t num_cache_lines)
{
	cvmx_addr_t newptr;


	newptr.u64 = cvmx_ptr_to_phys(ptr);
	newptr.sfilldidspace.didspace =
		CVMX_ADDR_DIDSPACE(CVMX_FULL_DID(CVMX_OCT_DID_FPA, pool));
	/* Make sure that any previous writes to memory go out before we free
	 * this buffer.  This also serves as a barrier to prevent GCC from
	 * reordering operations to after the free.
	 */
	CVMX_SYNCWS;
	/* value written is number of cache lines not written back */
	cvmx_write_io(newptr.u64, num_cache_lines);
}




/*
  *   Port and optimize from cvmx_pow_work_request_sync_nocheck()/cvmx_pow.h
  */
static inline cvmx_wqe_t *oct_pow_work_request_sync_nocheck(cvmx_pow_wait_t wait)
{
	cvmx_pow_load_addr_t ptr;
	cvmx_pow_tag_load_resp_t result;

	ptr.u64 = 0;
	ptr.swork.mem_region = CVMX_IO_SEG;
	ptr.swork.is_io = 1;
	ptr.swork.did = CVMX_OCT_DID_TAG_SWTAG;
	ptr.swork.wait = wait;

	result.u64 = cvmx_read_csr(ptr.u64);

	if (result.s_work.no_work)
		return NULL;
	else
		return (cvmx_wqe_t *) cvmx_phys_to_ptr(result.s_work.addr);
}




#endif
