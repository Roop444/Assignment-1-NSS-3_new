
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LISTEN_PORT 6666
#define SERVER_PORT 5555

int main()
{
    /* Disable buffering so logs appear instantly */
    setbuf(stdout, NULL);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));

    a.sin_family = AF_INET;
    a.sin_port = htons(LISTEN_PORT);
    a.sin_addr.s_addr = INADDR_ANY;

    if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(lfd, 5) < 0) {
        perror("listen");
        return 1;
    }

    printf("Tamper proxy listening on %d\n", LISTEN_PORT);

    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        perror("accept");
        return 1;
    }

    printf("Client connected.\n");

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));

    srv.sin_family = AF_INET;
    srv.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "192.168.1.30", &srv.sin_addr);

    if (connect(sfd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("connect");
        return 1;
    }

    printf("Connected to real server on %d\n", SERVER_PORT);

    unsigned char buf[4096];
    int n;
    int packet_count = 0;
    int tampered = 0;

    while ((n = read(cfd, buf, sizeof(buf))) > 0) {

        packet_count++;

        printf("Forwarding packet %d (%d bytes)\n", packet_count, n);

        /*
         * IMPORTANT:
         * First few packets are Kerberos/GSS handshake.
         * Tamper later packets only (likely encrypted file data).
         */
        if (!tampered && n > 100) {
            buf[n - 30] ^= 0xFF;
            tampered = 1;
            printf(">>> Ciphertext tampered on packet %d <<<\n", packet_count);
        }

        if (write(sfd, buf, n) != n) {
            perror("write");
            break;
        }
    }

    printf("Connection closed.\n");

    close(cfd);
    close(sfd);
    close(lfd);

    return 0;
}
