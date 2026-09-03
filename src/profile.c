#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static bool cli_has_flag(int argc, char **argv, const char *flag)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            break;
        }
        if (strcmp(argv[i], flag) == 0) {
            return true;
        }
    }
    return false;
}

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
            if (profile_path) {
                fprintf(stderr, "safe-agent: error: duplicate --profile option\n");
                return -1;
            }
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
            i++;
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
        char *key = p;
        char *val = NULL;

        if (eq) {
            *eq = '\0';
            char *key_end = eq - 1;
            while (key_end >= key && (*key_end == ' ' || *key_end == '\t')) {
                *key_end = '\0';
                key_end--;
            }

            char *val_start = eq + 1;
            while (*val_start == ' ' || *val_start == '\t') val_start++;
            char *val_end = val_start + strlen(val_start) - 1;
            while (val_end >= val_start && (*val_end == ' ' || *val_end == '\t')) {
                *val_end = '\0';
                val_end--;
            }
            if (*val_start != '\0') {
                val = val_start;
            }
        } else {
            char *key_end = key + strlen(key) - 1;
            while (key_end >= key && (*key_end == ' ' || *key_end == '\t')) {
                *key_end = '\0';
                key_end--;
            }
        }

        if (*key == '\0') continue;

        bool is_bool_flag = (strcmp(key, "block-net") == 0 ||
                             strcmp(key, "drop-net") == 0 ||
                             strcmp(key, "new-pid") == 0 ||
                             strcmp(key, "block-tiocsti") == 0 ||
                             strcmp(key, "harden-sys") == 0 ||
                             strcmp(key, "clean-env") == 0);

        if (is_bool_flag) {
            if (val && (strcasecmp(val, "false") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "no") == 0)) {
                continue;
            }
            val = NULL;
        } else {
            bool is_singleton = (strcmp(key, "timeout") == 0 ||
                                 strcmp(key, "max-output") == 0 ||
                                 strcmp(key, "max-mem") == 0 ||
                                 strcmp(key, "max-cpu") == 0 ||
                                 strcmp(key, "max-procs") == 0 ||
                                 strcmp(key, "max-files") == 0 ||
                                 strcmp(key, "audit-log") == 0 ||
                                 strcmp(key, "cgroup") == 0);
            if (is_singleton) {
                char flag_buf[64];
                snprintf(flag_buf, sizeof(flag_buf), "--%s", key);
                if (cli_has_flag(argc, argv, flag_buf)) {
                    continue;
                }
            }
        }

        char *val_dup = NULL;
        if (val) {
            val_dup = strdup(val);
            if (!val_dup) {
                fclose(f);
                for (size_t k = 1; k < new_argc; k++) free(new_argv[k]);
                free(new_argv);
                return -1;
            }
        }

        size_t flen = strlen(key) + 3;
        char *flag = malloc(flen);
        if (!flag) {
            free(val_dup);
            fclose(f);
            for (size_t k = 1; k < new_argc; k++) free(new_argv[k]);
            free(new_argv);
            return -1;
        }
        snprintf(flag, flen, "--%s", key);

        if (new_argc + 2 >= cap) {
            cap *= 2;
            char **tmp = realloc(new_argv, cap * sizeof(char *));
            if (!tmp) {
                free(flag);
                free(val_dup);
                fclose(f);
                for (size_t k = 1; k < new_argc; k++) free(new_argv[k]);
                free(new_argv);
                return -1;
            }
            new_argv = tmp;
        }

        new_argv[new_argc++] = flag;
        if (val_dup) {
            new_argv[new_argc++] = val_dup;
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
