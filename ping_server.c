/**
 * ping_server.c - MIP PING Server Application
 * 
 * Listens for PING messages from the MIP daemon and responds with PONG messages.
 * Runs continuously until connection is closed or error occurs.
 * 
 * Usage: ping_server <socket_path>
 * 
 * Arguments:
 *   socket_path: Path to MIP daemon's UNIX domain socket
 * 
 * Protocol:
 *   - Receives messages in format: [src_mip][ttl][PING:message]
 *   - Responds with: [src_mip][ttl=0][PONG:message]
 * 
 * Returns: 0 on clean exit, 1 on error
 */

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

#include "mipd.h" 

/**
 * Main function for ping server
 * 
 * Connects to MIP daemon via UNIX socket and enters infinite loop
 * receiving PING messages and sending PONG responses.
 * 
 * Global variables: None
 * Returns: 0 on clean exit, 1 on error or connection close
 * Error conditions: Invalid arguments, connection failure, read/write errors
 */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <socket_lower>\n", argv[0]);
        exit(1);
    }

    const char *sock_path = argv[1];

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

    printf("\n======================================\n");
    printf("[SERVER] Waiting for PING messages...\n");
    printf("======================================\n");

    while (1) {
        uint8_t buffer[MAX_SDU_SIZE];
        ssize_t n = read(sockfd, buffer, sizeof(buffer));
        if (n <= 0) {
            if (n < 0) perror("read");
            else printf("\n[SERVER] Connection closed by mipd\n");
            break;
        }

        if (n < 1) {
            continue;
        }

        uint8_t src_mip = buffer[0];
        uint8_t src_ttl = buffer[1];
        char *msg = (char*)(buffer + 2);
        size_t msg_len = n - 2;

        printf("\n[SERVER] Received PING from MIP %d (TTL=%d)\n", src_mip, src_ttl);
        printf("[SERVER] Message: \"%.*s\"\n", (int)msg_len, msg);
        
        if (msg_len >= 5 && strncmp(msg, "PING:", 5) == 0) {
            uint8_t reply_buffer[MAX_SDU_SIZE];

            reply_buffer[0] = src_mip;
            reply_buffer[1] = 0;  // TTL=0 means use default (let MIP daemon set it)
            sprintf((char*)(reply_buffer + 2), "PONG:%.*s", (int)(msg_len - 5), msg + 5);
            int reply_len = strlen((char*)(reply_buffer + 2));

            if (reply_len < 0 || reply_len >= MAX_SDU_SIZE - 2) {
                fprintf(stderr, "[SERVER] Reply message too long\n");
                continue;
            }

            int reply_total_len = reply_len + 2;

            printf("[SERVER] Sending PONG to MIP %d\n", src_mip);
            printf("[SERVER] Message: \"%.*s\"\n", reply_len, reply_buffer + 2);

            if (write(sockfd, reply_buffer, reply_total_len) < 0) {
                perror("send");
                break;
            }
        } else {
            printf("[SERVER] Received non-PING message, ignoring\n");
        }
    }

    close(sockfd);
    return 0;
}