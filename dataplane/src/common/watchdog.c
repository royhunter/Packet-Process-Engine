#define _GNU_SOURCE
#include <oct-sched.h>
#include <sched.h>
#include <pthread.h>


extern void DP_Attack_Info_Update();

int wd_is_watchdog_registered(int cpuid)
{
    return (sched_tbl->data[cpuid].watchdog_enabled);
}


void wd_disable_watchdog(void)
{
    sched_tbl->watchdog_disabled = 1;
}


void wd_enable_watchdog(void)
{
    sched_tbl->watchdog_disabled = 0;
}


static uint32_t wd_is_watchdog_disabled(void)
{
    return sched_tbl->watchdog_disabled;
}


void wd_set_watchdog_timeout(uint32_t sec)
{
    if(sec < WD_WATCHDOG_TIMEOUT)
    {
        sec = WD_WATCHDOG_TIMEOUT;
    }

    sched_tbl->watchdog_retry = sec/WD_WATCHDOG_CHECK_INTERVAL;
}

void wd_check_watchdog()
{
    int i;
    int watchdog_fired = 0;

    if(wd_is_watchdog_disabled())
    {
        return;
    }

    for (i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        if(!wd_is_watchdog_registered(i))
        {
            continue;
        }

        if(sched_tbl->data[i].watchdog_ok > sched_tbl->watchdog_retry)
        {
            watchdog_fired = 1;
        }
        ++sched_tbl->data[i].watchdog_ok;
    }

    if( watchdog_fired)
    {
        abort();
    }
}



static pthread_t wd_watchdog_thread;


static void *wd_watchdog_func(void *arg)
{
    int rc;
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
#if 0
    int j;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    printf("Set returned by pthread_getaffinity_np() contained:\n");
    for (j = 0; j < 2; j++)
        if (CPU_ISSET(j, &cpuset))
            printf("    CPU %d\n", j);
#endif
    if(pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0)
    {
        printf("wd_watchdog set thread affinity failed\n");
    }

    printf("wd_watchdog set thread affinity OK\n");

#if 0
    pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    printf("Set returned by pthread_getaffinity_np() contained:\n");
    for (j = 0; j < 2; j++)
        if (CPU_ISSET(j, &cpuset))
            printf("    CPU %d\n", j);
#endif

    printf("pid is %d\n", getpid());
    cvmx_linux_enable_xkphys_access(0);

    while(1)
    {
        rc = sleep(WD_WATCHDOG_CHECK_INTERVAL);

        if(0 == rc)
        {
            wd_check_watchdog(NULL);
            DP_Attack_Info_Update();
        }

    }

    return NULL;
}

void wd_watchdog_init(void)
{
    wd_enable_watchdog();

    wd_set_watchdog_timeout(WD_WATCHDOG_TIMEOUT);

    pthread_create(&wd_watchdog_thread, NULL, wd_watchdog_func, NULL);
    return;
}
