#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sandbox_env_apply(bool clean_env,
                      char *const *keep_keys,
                      size_t keep_count,
                      char *const *set_pairs,
                      size_t set_count)
{
    if (!clean_env && set_count == 0) {
        return 0;
    }

    if (clean_env) {
        /* security boundary: save keep-env values before clearing environ */
        char **saved_keys = NULL;
        char **saved_vals = NULL;
        size_t saved_count = 0;

        if (keep_count > 0) {
            saved_keys = calloc(keep_count, sizeof(char *));
            saved_vals = calloc(keep_count, sizeof(char *));
            if (!saved_keys || !saved_vals) {
                fprintf(stderr, "safe-agent: failed to allocate memory for environment tracking\n");
                free(saved_keys);
                free(saved_vals);
                return -1;
            }

            for (size_t i = 0; i < keep_count; i++) {
                const char *val = getenv(keep_keys[i]);
                if (val) {
                    saved_keys[saved_count] = keep_keys[i];
                    saved_vals[saved_count] = strdup(val);
                    if (!saved_vals[saved_count]) {
                        fprintf(stderr, "safe-agent: failed to duplicate environment value\n");
                        for (size_t j = 0; j < saved_count; j++) {
                            free(saved_vals[j]);
                        }
                        free(saved_keys);
                        free(saved_vals);
                        return -1;
                    }
                    saved_count++;
                }
            }
        }

        clearenv();

        /* security boundary: provide deterministic baseline path if not preserved */
        bool path_restored = false;
        for (size_t i = 0; i < saved_count; i++) {
            if (setenv(saved_keys[i], saved_vals[i], 1) < 0) {
                fprintf(stderr, "safe-agent: failed to restore environment variable '%s': %s\n",
                        saved_keys[i], strerror(errno));
            }
            if (strcmp(saved_keys[i], "PATH") == 0) {
                path_restored = true;
            }
            free(saved_vals[i]);
        }
        free(saved_keys);
        free(saved_vals);

        if (!path_restored) {
            setenv("PATH", "/usr/bin:/bin", 1);
        }
    }

    for (size_t i = 0; i < set_count; i++) {
        const char *eq = strchr(set_pairs[i], '=');
        if (!eq || eq == set_pairs[i]) {
            fprintf(stderr, "safe-agent: invalid environment assignment '%s'\n", set_pairs[i]);
            return -1;
        }

        size_t key_len = (size_t)(eq - set_pairs[i]);
        char key_buf[256];
        char *key = key_buf;
        if (key_len >= sizeof(key_buf)) {
            key = malloc(key_len + 1);
            if (!key) {
                fprintf(stderr, "safe-agent: out of memory for env key\n");
                return -1;
            }
        }
        memcpy(key, set_pairs[i], key_len);
        key[key_len] = '\0';

        if (setenv(key, eq + 1, 1) < 0) {
            fprintf(stderr, "safe-agent: failed to set environment variable '%s': %s\n",
                    key, strerror(errno));
            if (key != key_buf) {
                free(key);
            }
            return -1;
        }

        if (key != key_buf) {
            free(key);
        }
    }

    return 0;
}
