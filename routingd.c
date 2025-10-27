#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>    
#include <sys/select.h> 

#include "mipd.h"
#include "routingd.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-d] <socket_to_mip_daemon>\n", argv[0]);
        exit(1);
    }

    int debug = 0;
    int arg_idx = 1;

    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        debug = 1;
        arg_idx++;
    }

    const char *sock_path = argv[arg_idx];

    // Connect to MIP daemon
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

    if (debug) {
        printf("[ROUTING] Connected to MIP daemon\n");
        fflush(stdout);
    }

    // Identify as routing daemon
    printf("[ROUTING] Sending identification to MIP daemon (SDU_TYPE=0x%02x)\n", 
           SDU_TYPE_ROUTING);
    uint8_t ident = SDU_TYPE_ROUTING;
    if (send(sockfd, &ident, 1, 0) < 0) {
        perror("send identification");
        close(sockfd);
        exit(1);
    }
    printf("[ROUTING] Sent identification, waiting for MIP address...\n");

    // Read local MIP address from daemon
    uint8_t mip_info[2];
    printf("[ROUTING] Receiving MIP address from daemon...\n");
    ssize_t n = recv(sockfd, mip_info, 2, 0);
    printf("[ROUTING] Received %zd bytes from daemon\n", n);
    if (n < 1) {
        fprintf(stderr, "[ROUTING] Failed to receive MIP address (received %zd bytes)\n", n);
        close(sockfd);
        exit(1);
    }

    uint8_t local_mip = mip_info[0];
    printf("[ROUTING] Got MIP address: %d\n", local_mip);

    printf("[ROUTING] Initializing routing state...\n");
    struct routing_state state;
    init_routing_state(&state, local_mip);
    state.mip_sock = sockfd;

    printf("[ROUTING] Routing daemon started for MIP %d, socket fd=%d\n", 
           local_mip, sockfd);
    fflush(stdout);

    // Main loop
    time_t last_print = 0;
    while (1) {
        time_t now = time(NULL);

        // Periodic tasks
        if (now - state.last_hello_sent >= HELLO_INTERVAL) {
            printf("[ROUTING] Time to send HELLO: now=%ld, last_hello_sent=%ld, interval=%d\n",
                   now, state.last_hello_sent, HELLO_INTERVAL);
            send_hello(&state);
        }

        if (now - state.last_update_sent >= UPDATE_INTERVAL) {
            send_update(&state);
        }

        update_neighbors(&state);
        update_routes(&state);

        // Print routing table every 10 seconds
        if (now - last_print >= 10) {
            print_routing_table(&state);
            last_print = now;
        }

        // Check for incoming messages (non-blocking)
        uint8_t buffer[MAX_SDU_SIZE];
        struct timeval tv = {0, 100000};    // 100ms timeout
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        int ready = select(sockfd + 1, &readfds, NULL, NULL, &tv);
        if (ready > 0) {
            ssize_t nread = recv(sockfd, buffer, sizeof(buffer), 0);
            if (nread <= 0) {
                if (nread == 0) {
                    printf("[ROUTING] Connection closed\n");
                } else {
                    perror("recv");
                }
                break;
            }

            printf("[ROUTING] Received %zd bytes from MIP daemon\n", nread);

            // Parse message: [src_mip][ttl][payload...]
            if (nread < 3) {
                printf("[ROUTING] Message too short (%zd bytes), ignoring\n", nread);
                continue;
            }

            uint8_t src_mip = buffer[0];
            uint8_t ttl = buffer[1];
            (void)ttl;
            uint8_t *payload = buffer + 2;
            size_t payload_len = nread - 2;

            printf("[ROUTING] Parsed: src_mip=%d, ttl=%d, payload_len=%zu\n", 
                   src_mip, ttl, payload_len);

            if (payload_len < 1) {
                printf("[ROUTING] Payload too short (%zu bytes), ignoring\n", payload_len);
                continue;
            }

            uint8_t msg_type = payload[0];
            printf("[ROUTING] Message type: 0x%02x\n", msg_type);

            switch (msg_type) {
                case MSG_HELLO:
                    handle_hello(&state, src_mip);
                    break;
                
                case MSG_UPDATE:
                    if (payload_len >= 2) {
                        handle_update(&state, src_mip, payload + 1, payload_len - 1);
                    }
                    break;
                
                case 0x52: // 'R' - Route request
                if (payload_len >= 4 && payload[1] == 0x45 && payload[2] == 0x51) {
                    // REQ format: ['R']['E']['Q'][dest_mip]
                    uint8_t dest_mip = payload[3];
                    handle_route_request(&state, dest_mip);
                }
                break;
            
            default:
                if (debug) printf("[ROUTING] Unknown message type: 0x%02x\n", msg_type);
                break;
            }
        } else if (ready < 0 && errno != EINTR) {
            perror("select");
            break;
        }
    }

    close(sockfd);
    return 0;
}