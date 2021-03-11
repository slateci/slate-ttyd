#ifndef TTYD_UTIL_H
#define TTYD_UTIL_H

#define container_of(ptr, type, member)                \
  ({                                                   \
    const typeof(((type *)0)->member) *__mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member)); \
  })

// malloc with NULL check
void *xmalloc(size_t size);

// realloc with NULL check
void *xrealloc(void *p, size_t size);

// Convert a string to upper case
char *uppercase(char *str);

// Check whether str ends with suffix
bool endswith(const char *str, const char *suffix);

// Get human readable signal string
int get_sig_name(int sig, char *buf, size_t len);

// Get signal code from string like SIGHUP
int get_sig(const char *sig_name);

// Open uri with the default application of system
int open_uri(char *uri);

// Encode text to base64, the caller should free the returned string
char *base64_encode(const unsigned char *buffer, size_t length);

#ifdef _WIN32
char *strsep(char **sp, char *sep);
const char *quote_arg(const char *arg);
void print_error(char *func);
#endif
#endif  // TTYD_UTIL_H
