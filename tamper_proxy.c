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
    int lfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));

    a.sin_family = AF_INET;
    a.sin_port = htons(LISTEN_PORT);
    a.sin_addr.s_addr = INADDR_ANY;

    bind(lfd, (struct sockaddr *)&a, sizeof(a));
    listen(lfd, 5);

    printf("Tamper proxy listening on %d\n", LISTEN_PORT);

    int cfd = accept(lfd, NULL, NULL);

    printf("Client connected.\n");

    int sfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));

    srv.sin_family = AF_INET;
    srv.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr);

    connect(sfd, (struct sockaddr *)&srv, sizeof(srv));

    printf("Connected to real server.\n");

    unsigned char buf[4096];
    int n;
    int tampered = 0;

    while ((n = read(cfd, buf, sizeof(buf))) > 0) {

        if (!tampered && n > 40) {
            buf[30] ^= 0xFF;
            tampered = 1;
            printf("Ciphertext tampered!\n");
        }

        write(sfd, buf, n);
    }

    close(cfd);
    close(sfd);
    close(lfd);

    return 0;
}
