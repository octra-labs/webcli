#include <stdint.h>
#include <stdlib.h>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

void randombytes(uint8_t *buf, uint64_t len) {
    if (BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        abort();
}

#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

void randombytes(uint8_t *buf, uint64_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) abort();
    while (len > 0) {
        ssize_t n = read(fd, buf, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(fd);
            abort();
        }
        buf += n;
        len -= (uint64_t)n;
    }
    close(fd);
}
#endif