/* =========================
   common.c
   ========================= */
#include "common.h"

void die(const char *msg)
{
    perror(msg);
    exit(1);
}

void gss_die(const char *msg, OM_uint32 maj, OM_uint32 min)
{
    printf("%s failed (maj=%u min=%u)\n", msg, maj, min);
    exit(1);
}

int send_all(int fd, void *buf, size_t len)
{
    size_t done = 0;

    while (done < len) {
        int n = write(fd, (char *)buf + done, len - done);
        if (n <= 0)
            return -1;
        done += n;
    }

    return 0;
}

int recv_all(int fd, void *buf, size_t len)
{
    size_t done = 0;

    while (done < len) {
        int n = read(fd, (char *)buf + done, len - done);
        if (n <= 0)
            return -1;
        done += n;
    }

    return 0;
}

int send_token(int fd, gss_buffer_t tok)
{
    uint32_t n = htonl(tok->length);

    send_all(fd, &n, 4);
    send_all(fd, tok->value, tok->length);

    return 0;
}

int recv_token(int fd, gss_buffer_t tok)
{
    uint32_t n;

    recv_all(fd, &n, 4);
    n = ntohl(n);

    tok->length = n;
    tok->value = malloc(n);

    recv_all(fd, tok->value, n);

    return 0;
}
