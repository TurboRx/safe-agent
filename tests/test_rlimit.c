#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <stdio.h>
#include <sys/resource.h>

int main(void)
{
    printf("=== Running Resource Limits (rlimit) Tests ===\n");

    struct sandbox_rlimits limits = {
        .max_mem_mb = 0,
        .max_cpu_sec = 60,
        .max_procs = 0,
        .max_files = 256,
    };

#if !defined(__SANITIZE_ADDRESS__)
    /* security boundary: address sanitizer reserves 16tb shadow memory and conflicts with low rlimit_as */
    limits.max_mem_mb = 512;
#endif

    int res = sandbox_rlimits_apply(&limits);
    assert(res == 0);

#if !defined(__SANITIZE_ADDRESS__)
    struct rlimit rl_mem;
    int res_mem = getrlimit(RLIMIT_AS, &rl_mem);
    assert(res_mem == 0);
    assert(rl_mem.rlim_cur == 512UL * 1024UL * 1024UL);
    printf("PASS: RLIMIT_AS successfully verified\n");
#else
    printf("SKIP: RLIMIT_AS skipped under AddressSanitizer shadow memory mapping\n");
#endif

    struct rlimit rl;
    int res_cpu = getrlimit(RLIMIT_CPU, &rl);
    assert(res_cpu == 0);
    assert(rl.rlim_cur == 60);
    printf("PASS: RLIMIT_CPU successfully verified\n");

    int res_nofile = getrlimit(RLIMIT_NOFILE, &rl);
    assert(res_nofile == 0);
    assert(rl.rlim_cur == 256);
    printf("PASS: RLIMIT_NOFILE successfully verified\n");

    printf("All resource limits tests passed successfully.\n");
    return 0;
}
