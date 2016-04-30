#define _GNU_SOURCE
#include <oct-sched.h>
#include <sched.h>
#include <pthread.h>

#include <oct-common.h>
#include <sec-common.h>
#include <oct-thread.h>




static pthread_t pthr_id[CPU_HW_RUNNING_MAX];
static pthread_attr_t pthr_attr[CPU_HW_RUNNING_MAX];



uint32_t oct_dp_pthread_create(void *(*start_routine)(void *),
                uint32_t hw_thread_id)
{

    int rc=0;
    cpu_set_t mask;

    if( hw_thread_id >= CPU_HW_RUNNING_MAX)
    {
        printf("thread id error\n");
        return SEC_NO;
    }

    rc = pthread_attr_init(&pthr_attr[hw_thread_id]);
    if (rc) {
        printf("pthread_create attr init ERROR\n");
        return SEC_NO;
    }

    CPU_ZERO(&mask);
    CPU_SET(hw_thread_id, &mask);

    rc = pthread_attr_setaffinity_np(&pthr_attr[hw_thread_id], sizeof(cpu_set_t), &mask);
    if (rc) {
        printf("pthread_create bind cpu ERROR\n");
        return SEC_NO;
    }

    rc = pthread_create(&pthr_id[hw_thread_id], &pthr_attr[hw_thread_id],
                        start_routine, (void *)(uint64_t)hw_thread_id);
    if (rc) {
        printf("pthread_create ERROR\n");
        return SEC_NO;
    }

    return SEC_OK;

}




