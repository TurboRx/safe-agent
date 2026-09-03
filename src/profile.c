#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sandbox_profile_expand(int argc, char **argv, int *out_argc, char ***out_argv)
{
    if (argc < 2 || !argv) {
        *out_argc = argc;
        *out_argv = argv;
        return 0;
    }

    const char *profile_path = NULL;
    int profile_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            break;
        }
        if (strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc || strncmp(argv[i + 1], "--", 2) == 0) {
                fprintf(stderr, "safe-agent: error: --profile requires a path argument\n");
                return -1;
            }
            if (argv[i + 1][0] == '\0') {
                fprintf(stderr, "safe-agent: error: --profile path must not be empty\n");
                return -1;
            }
            profile_path = argv[i + 1];
            profile_idx = i;
            break;
        }
    }

    if (!profile_path) {
        *out_argc = argc;
        *out_argv = argv;
        return 0;
    }

    FILE *f = fopen(profile_path, "r");
    if (!f) {
        fprintf(stderr, "safe-agent: failed to open profile file '%s': %s\n",
                profile_path, strerror(errno));
        return -1;
    }

    size_t cap = (size_t)argc + 32;
    char **new_argv = malloc(cap * sizeof(char *));
    if (!new_argv) {
        fprintf(stderr, "safe-agent: out of memory expanding profile\n");
        fclose(f);
        return -1;
    }

    size_t new_argc = 0;
    new_argv[new_argc++] = argv[0];

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        char *cr = strchr(p, '\r');
        if (cr) *cr = '\0';

        char *eq = strchr(p, '=');
        char *flag = NULL;
        char *val = NULL;

        if (eq) {
            *eq = '\0';
            val = strdup(eq + 1);
            if (!val) {
                fclose(f);
                for (size_t k = 1; k < new_argc; k++) free(new_argv[k]);
                free(new_argv);
                return -1;
            }
        }

        size_t flen = strlen(p) + 3;
        flag = malloc(flen);
        if (!flag) {
            free(val);
            fclose(f);
            for (size_t k = 1; k < new_argc; k++) free(new_argv[k]);
            free(new_argv);
            return -1;
        }
        snprintf(flag, flen, "--%s", p);

        if (new_argc + 2 >= cap) {
            cap *= 2;
            char **tmp = realloc(new_argv, cap * sizeof(char *));
            if (!tmp) {
                free(flag);
                free(val);
                fclose(f);
                for (size_t k = 1; k < new_argc; k++) free(new_argv[k]);
                free(new_argv);
                return -1;
            }
            new_argv = tmp;
        }

        new_argv[new_argc++] = flag;
        if (val) {
            new_argv[new_argc++] = val;
        }
    }

    fclose(f);

    /* append remaining original argv excluding the consumed --profile and path */
    for (int i = 1; i < argc; i++) {
        if (i == profile_idx) {
            i++;
            continue;
        }
        if (new_argc + 1 >= cap) {
            cap *= 2;
            char **tmp = realloc(new_argv, cap * sizeof(char *));
            if (!tmp) {
                for (size_t k = 1; k < new_argc; k++) free(new_argv[k]);
                free(new_argv);
                return -1;
            }
            new_argv = tmp;
        }
        new_argv[new_argc++] = argv[i];
    }
    new_argv[new_argc] = NULL;

    *out_argc = (int)new_argc;
    *out_argv = new_argv;
    return 1;
}

void sandbox_profile_free(int expanded_argc, char **expanded_argv, char **orig_argv)
{
    if (expanded_argv && expanded_argv != orig_argv) {
        for (int i = 1; i < expanded_argc; i++) {
            /* free only duplicated strings originating from the profile file */
            bool is_orig = false;
            for (char **orig = orig_argv; *orig; orig++) {
                if (expanded_argv[i] == *orig) {
                    is_orig = true;
                    break;
                }
            }
            if (!is_orig) {
                free(expanded_argv[i]);
            }
        }
        free(expanded_argv);
    }
}
