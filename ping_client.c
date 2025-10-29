#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "mipd.h" 

int main(int argc, char *argv[]){
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <socket_lower>, <message>, <destination_host>\n", argv[0]); 
        exit(1);
    }

    const char *sock_path = argv[1];
    const char *message = argv[2];
    uint8_t dest_mip = (uint8_t)atoi(argv[3]);
    uint8_t ttl = 0;    // 0 = use default
    
    if (argc >= 5) {
        ttl = (uint8_t)atoi(argv[4]);
    }

    int sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sockfd);
        exit(1);
    }

    printf("[CLIENT] Connected to mipd UNIX socket! fd=%d\n", sockfd);

    /* Create PING message */
    uint8_t buffer[MAX_SDU_SIZE];
    buffer[0] = dest_mip;
    buffer[1] = ttl;
    sprintf((char*)(buffer + 2), "PING:%s", message);
    int ping_len = strlen((char*)buffer + 2);

    int total_len = ping_len + 2; // +2 for dest_mip byte and ttl bytes

    printf("[CLIENT] Sending %d bytes: dest=%d, TTL=%d, msg='%.*s'\n", 
           total_len, dest_mip, ttl, ping_len, (char*)(buffer + 2));

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    /* Send PING message to mipd */
    if (send(sockfd, buffer, total_len, 0) < 0) {
        perror("write");
        close(sockfd);
        exit(1);
    }

    printf("[CLIENT]Sent PING to MIP %d: %s\n", dest_mip, buffer + 1);

    struct timeval timeout;
    timeout.tv_sec = 1; // 1 second timeout
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
    }

    /* Read reply from mipd */
    uint8_t reply[MAX_SDU_SIZE];
    ssize_t n = recv(sockfd, reply, sizeof(reply) - 1, 0);
    gettimeofday(&end_time, NULL);

    if (n > 0) {
        uint8_t reply_src = reply[0];
        //uint8_t reply_ttl = reply[1];
        char *reply_msg = (char*)(reply + 2);
        size_t reply_len = n - 2;

        /* Calculate RTT in milliseconds */
        long rtt_ms = ((end_time.tv_sec - start_time.tv_sec) * 1000) +
                      ((end_time.tv_usec - start_time.tv_usec) / 1000);
        
        printf("[CLIENT] Reply from MIP %d: %.*s (RTT: %ld ms)\n",
                reply_src, (int)reply_len, reply_msg, rtt_ms);
    } else if(n == 0) {
        printf("[CLIENT] Connection closed by mipd\n");
    } else {
        printf("[CLIENT] Timeout or error waiting for reply\n");
    }

    close(sockfd);
    printf("[CLIENT] Closed socket, exiting\n");

    return 0;
}