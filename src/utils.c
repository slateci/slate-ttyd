#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/wait.h>

#ifdef __linux__
// https://github.com/karelzak/util-linux/blob/master/misc-utils/kill.c
const char *sys_signame[NSIG] = {
    "zero",  "HUP",  "INT",   "QUIT", "ILL",   "TRAP", "ABRT", "UNUSED",
    "FPE",   "KILL", "USR1",  "SEGV", "USR2",  "PIPE", "ALRM", "TERM",
    "STKFLT","CHLD", "CONT",  "STOP", "TSTP",  "TTIN", "TTOU", "URG",
    "XCPU",  "XFSZ", "VTALRM","PROF", "WINCH", "IO",   "PWR",  "SYS", NULL
};
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#include <shellapi.h>
// https://github.com/mirror/newlib-cygwin/blob/master/winsup/cygwin/strsig.cc
#ifndef NSIG
#define NSIG 33
#endif
const char *sys_signame[NSIG] = {
    "zero",  "HUP",  "INT",   "QUIT", "ILL",   "TRAP", "IOT",  "EMT",
    "FPE",   "KILL", "BUS",   "SEGV", "SYS",   "PIPE", "ALRM", "TERM",
    "URG",   "STOP", "TSTP",  "CONT", "CHLD",  "TTIN", "TTOU", "IO",
    "XCPU",  "XFSZ", "VTALRM","PROF", "WINCH", "PWR",  "USR1", "USR2", NULL
};
#endif

void *
xmalloc(size_t size) {
    if (size == 0)
        return NULL;
    void *p = malloc(size);
    if (!p)
        abort();
    return p;
}

void *
xrealloc(void *p, size_t size) {
    if ((size == 0) && (p == NULL))
        return NULL;
    p = realloc(p, size);
    if (!p)
        abort();
    return p;
}

char *
uppercase(char *str) {
    int i = 0;
    do {
        str[i] = (char) toupper(str[i]);
    } while (str[i++] != '\0');
    return str;
}

bool
endswith(const char *str, const char *suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    return str_len > suffix_len && !strcmp(str + (str_len - suffix_len), suffix);
}

int
get_sig_name(int sig, char *buf, size_t len) {
    int n = snprintf(buf, len, "SIG%s", sig < NSIG ? sys_signame[sig] : "unknown");
    uppercase(buf);
    return n;
}

int
get_sig(const char *sig_name) {
    for (int sig = 1; sig < NSIG; sig++) {
        const char *name = sys_signame[sig];
        if (name != NULL && (strcasecmp(name, sig_name) == 0 || strcasecmp(name, sig_name + 3) == 0))
            return sig;
    }
    return atoi(sig_name);
}

int
wait_proc(pid_t in, pid_t *out) {
    int stat = 0, pid;
    do {
        pid = waitpid(in, &stat, WNOHANG);
    } while (pid < 0 && errno == EINTR);
    if (out != NULL) *out = pid;
    int status  = -1;
    if (WIFEXITED(stat)) {
        status = WEXITSTATUS(stat);
    } else if (WIFSIGNALED(stat)) {
        status = WTERMSIG(stat);
    }
    return status;
}

int
open_uri(char *uri) {
#ifdef __APPLE__
    char command[256];
    sprintf(command, "open %s > /dev/null 2>&1", uri);
    return system(command);
#elif defined(_WIN32) || defined(__CYGWIN__)
    return ShellExecute(0, 0, uri, 0, 0 , SW_SHOW) > 32 ? 0 : 1;
#else
    // check if X server is running
    if (system("xset -q > /dev/null 2>&1"))
        return 1;
    char command[256];
    sprintf(command, "xdg-open %s > /dev/null 2>&1", uri);
    return system(command);
#endif
}

// https://github.com/darkk/redsocks/blob/master/base64.c
char *
base64_encode(const unsigned char *buffer, size_t length) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *ret, *dst;
    unsigned i_bits = 0;
    int i_shift = 0;
    int bytes_remaining = (int) length;

    ret = dst = xmalloc((size_t) (((length + 2) / 3 * 4) + 1));
    while (bytes_remaining) {
        i_bits = (i_bits << 8) + *buffer++;
        bytes_remaining--;
        i_shift += 8;

        do {
            *dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
            i_shift -= 6;
        } while (i_shift > 6 || (bytes_remaining == 0 && i_shift > 0));
    }
    while ((dst - ret) & 3)
        *dst++ = '=';
    *dst = '\0';

    return ret;
}