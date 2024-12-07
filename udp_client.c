#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#define SERVER_PORT 1000
#define SERVER_IP "127.0.0.1"
#define MESSAGE "Hello, UDP Server!"
#define INTERVAL 1000

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[1024];

    
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));

    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    while (1) {
        
        sendto(sockfd, MESSAGE, strlen(MESSAGE), MSG_CONFIRM, (const struct sockaddr *) &server_addr, sizeof(server_addr));
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = INTERVAL * 1000000L;
        nanosleep(&ts, NULL);
    }

    close(sockfd);
    return 0;
}