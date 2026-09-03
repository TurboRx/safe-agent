#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    printf("=== Running Environment Sanitization Tests ===\n");

    setenv("SECRET_TOKEN", "supersecret123", 1);
    setenv("PRESERVE_ME", "keepvalue", 1);
    setenv("OLD_PATH", "/custom/path", 1);

    char *keep[] = { "PRESERVE_ME" };
    char *set_vars[] = { "INJECTED_VAR=hello_world" };

    int res = sandbox_env_apply(true, keep, 1, set_vars, 1);
    assert(res == 0);

    assert(getenv("SECRET_TOKEN") == NULL);
    printf("PASS: SECRET_TOKEN stripped by clean-env\n");

    assert(getenv("PRESERVE_ME") != NULL);
    assert(strcmp(getenv("PRESERVE_ME"), "keepvalue") == 0);
    printf("PASS: PRESERVE_ME preserved by keep-env\n");

    assert(getenv("INJECTED_VAR") != NULL);
    assert(strcmp(getenv("INJECTED_VAR"), "hello_world") == 0);
    printf("PASS: INJECTED_VAR successfully set\n");

    assert(getenv("PATH") != NULL);
    assert(strcmp(getenv("PATH"), "/usr/bin:/bin") == 0);
    printf("PASS: Default baseline PATH restored\n");

    printf("All environment sanitization tests passed.\n");
    return 0;
}
