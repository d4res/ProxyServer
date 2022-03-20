#include <arpa/inet.h>
#include <bits/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
    int cfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in con_addr;
    con_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &con_addr.sin_addr);
    con_addr.sin_port = htons(9090);

    int ret = connect(cfd, (struct sockaddr *)&con_addr, sizeof(con_addr));
    if (ret == -1) {
        perror(NULL);
        exit(-1);
    }

    char wbuf[] = "GET / HTTP/1.1";
    char rbuf[1024] = {0};

    while (1) {
        bzero(rbuf, sizeof(rbuf));
        write(cfd, wbuf, sizeof(wbuf) + 1);
        int count = read(cfd, rbuf, sizeof(rbuf) - 1);
        if (count == -1) {
            perror(NULL);
        } else if (count == 0) {
            printf("connection closed\n");
        }
        printf("recv: %s", rbuf);
        system("pause");
    }

    close(cfd);
    return 0;
}