/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * opensandbox-launcher is the pre-exec hardening prelude (OSEP-0018 §4).
 *
 * execd execs it as the child's argv[0]; it applies the privilege floor in
 * the child between fork and exec, then execve(2)s the real user command:
 *
 *   1. unset execd's credential env vars
 *   2. prctl(PR_SET_KEEPCAPS)                 (keep caps across the uid change)
 *   3. drop every bounding-set cap not kept   (needs CAP_SETPCAP)
 *   4. prctl(PR_SET_NO_NEW_PRIVS)
 *   5. setgroups + setgid + setuid            (identity drop)
 *   6. capset permitted/effective to the kept caps; PR_CAP_AMBIENT_RAISE each
 *   7. seccomp BPF filter (SECCOMP_MODE_FILTER) — LAST, so it never blocks
 *      the launcher's own setup syscalls above
 *   8. execve(user argv)
 *
 * The order is pinned by Linux semantics (see the OSEP). Every step is
 * best-effort and fail-open: a missing prerequisite is logged to stderr and
 * skipped, never fatal — matching execd's degradation contract. The policy is
 * read from an inherited descriptor; any malformed policy exits without
 * executing the workload.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define POLICY_MAGIC 0x4f534258u /* "OSBX" */
#define POLICY_VERSION 1u

#define FLAG_UID_DROP 0x1u
#define FLAG_CAP_DROP 0x2u

#define LAUNCH_FAILURE 125
#define EXEC_FAILURE 126

/* Keep in sync with policyHeader in hardening_linux.go. */
struct policy_header {
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
    uint32_t uid;
    uint32_t gid;
    uint32_t n_keepcaps;
    uint32_t n_env;
    uint32_t seccomp_len;
};

#define MAX_CAPS 64

static void log_err(const char *msg, int err)
{
    fprintf(stderr, "opensandbox-launcher: %s: %s\n", msg, strerror(err));
}

static void fail(int fd, const char *msg)
{
    if (fd >= 0)
        (void)close(fd);
    fprintf(stderr, "opensandbox-launcher: %s\n", msg);
    _exit(LAUNCH_FAILURE);
}

/* Read exactly n bytes from fd, retrying on EINTR and short reads. */
static int read_exact(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t left = n;

    while (left > 0) {
        ssize_t got = read(fd, p, left);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0)
            return -1; /* EOF before the expected length */
        p += got;
        left -= (size_t)got;
    }
    return 0;
}

/* Capability ABI v3: two data blocks covering caps 0..63. */
struct cap_header {
    uint32_t version;
    int pid;
};

struct cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

static int capset_all(uint32_t kept)
{
    struct cap_header header;
    struct cap_data data[2];

    memset(&header, 0, sizeof(header));
    memset(data, 0, sizeof(data));
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    data[0].effective = kept;
    data[0].permitted = kept;
    data[0].inheritable = kept;
    data[1].effective = 0;
    data[1].permitted = 0;
    data[1].inheritable = 0;
    return syscall(SYS_capset, &header, data);
}

static int raise_ambient(uint32_t cap)
{
    return prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (unsigned long)cap, 0, 0);
}

int main(int argc, char **argv)
{
    int policy_fd;
    struct policy_header hdr;
    uint32_t keepcaps[MAX_CAPS];
    char *env_names[MAX_CAPS];
    int n_env;
    size_t env_budget;
    struct sock_filter *filter = NULL;
    struct sock_fprog prog;

    if (argc < 4 || strcmp(argv[2], "--") != 0)
        fail(-1, "usage: opensandbox-launcher <policy-fd> -- <argv...>");

    {
        char *end = NULL;
        long parsed;

        errno = 0;
        parsed = strtol(argv[1], &end, 10);
        if (errno != 0 || end == argv[1] || *end != '\0' ||
            parsed < 3 || parsed > INT32_MAX)
            fail(-1, "invalid policy descriptor");
        policy_fd = (int)parsed;
    }

    if (fcntl(policy_fd, F_GETFD) < 0)
        fail(policy_fd, "policy descriptor is not open");

    if (read_exact(policy_fd, &hdr, sizeof(hdr)) != 0)
        fail(policy_fd, "truncated policy header");
    if (hdr.magic != POLICY_MAGIC || hdr.version != POLICY_VERSION)
        fail(policy_fd, "invalid policy header");

    if (hdr.n_keepcaps > MAX_CAPS)
        fail(policy_fd, "too many kept capabilities");
    if (hdr.n_env > MAX_CAPS)
        fail(policy_fd, "too many environment names");
    if (hdr.seccomp_len % sizeof(struct sock_filter) != 0)
        fail(policy_fd, "seccomp filter length is not a multiple of sock_filter");

    if (hdr.n_keepcaps > 0 &&
        read_exact(policy_fd, keepcaps, hdr.n_keepcaps * sizeof(uint32_t)) != 0)
        fail(policy_fd, "truncated capability list");

    /* Env names are NUL-terminated strings packed back to back. Bound the
     * total budget so a malicious policy cannot exhaust the stack. */
    env_budget = hdr.n_env * 64u;
    if (env_budget > 4096u)
        fail(policy_fd, "environment names exceed the policy budget");
    n_env = 0;
    while (n_env < (int)hdr.n_env) {
        static char env_buf[4096];
        size_t off = 0;

        while (off + 1 < sizeof(env_buf)) {
            if (read(policy_fd, &env_buf[off], 1) != 1)
                fail(policy_fd, "truncated environment name");
            if (env_buf[off] == '\0')
                break;
            off++;
        }
        if (off + 1 >= sizeof(env_buf) && env_buf[off] != '\0')
            fail(policy_fd, "environment name too long");
        env_buf[off] = '\0';
        env_names[n_env++] = strdup(env_buf);
        if (env_names[n_env - 1] == NULL)
            fail(policy_fd, "out of memory for environment name");
    }

    if (hdr.seccomp_len > 0) {
        filter = (struct sock_filter *)malloc(hdr.seccomp_len);
        if (filter == NULL)
            fail(policy_fd, "out of memory for seccomp filter");
        if (read_exact(policy_fd, filter, hdr.seccomp_len) != 0)
            fail(policy_fd, "truncated seccomp filter");
    }

    if (close(policy_fd) != 0)
        _exit(LAUNCH_FAILURE);

    /* 1. Strip execd's credential/config env from the workload. */
    for (int i = 0; i < n_env; i++) {
        unsetenv(env_names[i]);
        free(env_names[i]);
    }

    if (hdr.flags & FLAG_CAP_DROP) {
        int caps_dropped = 0;

        /* 2. Keep caps across the identity change (step 5 clears them). */
        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0)
            log_err("PR_SET_KEEPCAPS", errno);

        /* 3. Trim the bounding set while CAP_SETPCAP is still held. */
        for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
            int keep = 0;

            for (uint32_t k = 0; k < hdr.n_keepcaps; k++) {
                if ((uint32_t)cap == keepcaps[k]) {
                    keep = 1;
                    break;
                }
            }
            if (!keep && prctl(PR_CAPBSET_DROP, (unsigned long)cap, 0, 0, 0) == 0)
                caps_dropped++;
            else if (!keep && errno != EPERM && errno != EINVAL)
                log_err("PR_CAPBSET_DROP", errno);
        }
        (void)caps_dropped;
    }

    /* 4. No new privileges: nothing below can regain what the launcher drops. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        log_err("PR_SET_NO_NEW_PRIVS", errno);

    if (hdr.flags & FLAG_UID_DROP) {
        /* 5. Identity change. Same-uid re-apply succeeds; a foreign target
         * without privileges fails and is skipped (fail-open). */
        (void)setgroups(0, NULL);
        if (setgid((gid_t)hdr.gid) != 0)
            log_err("setgid", errno);
        if (setuid((uid_t)hdr.uid) != 0)
            log_err("setuid", errno);
    }

    if (hdr.flags & FLAG_CAP_DROP) {
        /* 6. Final cap sets + ambient raise so kept caps survive execve. */
        uint32_t kept = 0;

        for (uint32_t k = 0; k < hdr.n_keepcaps; k++)
            kept |= (1u << keepcaps[k]);
        if (capset_all(kept) != 0)
            log_err("capset", errno);
        for (uint32_t k = 0; k < hdr.n_keepcaps; k++) {
            if (raise_ambient(keepcaps[k]) != 0)
                log_err("PR_CAP_AMBIENT_RAISE", errno);
        }
    }

    /* 7. Seccomp LAST: it must never block the setup above, and execve
     * (which the Go side reserves from the deny list) is still allowed. */
    if (filter != NULL) {
        prog.len = (unsigned short)(hdr.seccomp_len / sizeof(struct sock_filter));
        prog.filter = filter;
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
            log_err("PR_SET_SECCOMP", errno);
        free(filter);
    }

    /* 8. Exec the real workload. */
    execvp(argv[3], &argv[3]);
    fprintf(stderr, "opensandbox-launcher: exec %s: %s\n", argv[3], strerror(errno));
    _exit(EXEC_FAILURE);
}
