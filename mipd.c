/**
 * mipd.c - MIP Daemon Main Program
 * 
 * The MIP (Minimal Internet Protocol) daemon is the core network layer component
 * that handles packet forwarding, ARP resolution, and communication between
 * upper layer applications and the routing daemon.
 * 
 * Usage: mipd [-d] <socket_upper> <MIP address>
 * 
 * Architecture:
 * - Uses epoll for non-blocking I/O multiplexing
 * - Manages multiple RAW sockets (one per network interface)
 * - Accepts connections from upper layer applications via UNIX socket
 * - Communicates with routing daemon for route lookups
 * - Implements automatic ARP learning and resolution
 * - Forwards packets based on routing table information
 * 
 * Main loop handles:
 * 1. RAW socket events (incoming MIP packets from network)
 * 2. UNIX socket events (new application connections)
 * 3. Application events (PING requests, PONG responses)
 * 4. Routing daemon events (route responses, routing protocol messages)
 * 
 * Returns: 0 on clean exit, 1 on error
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/time.h>

#include "mipd.h"

/**
 * Main function for MIP daemon
 * 
 * Initializes network interfaces, creates RAW sockets, sets up UNIX socket
 * for upper layer connections, creates epoll instance, and enters main event
 * loop to handle all I/O events non-blockingly.
 * 
 * Global variables: None
 * Returns: 0 on success, 1 on error
 * Error conditions: Invalid arguments, initialization failures, I/O errors
 */
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [-d] <socket_upper> <MIP address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int debug = 0;
    int arg_idx = 1;
    if (strcmp(argv[1], "-d") == 0) {
        debug = 1;
        arg_idx++;
    }

    const char *unix_path = argv[arg_idx];
    uint8_t mip_addr = (uint8_t)atoi(argv[arg_idx + 1]);

    struct ifs_data local_if;
    memset(&local_if, 0, sizeof(local_if));
    local_if.local_mip_addr = mip_addr;
    local_if.arp.entry_count = 0;
    local_if.server_fd = -1;        // -1 -> no persistent server connected yet
    local_if.routing_daemon_fd = -1;
    local_if.pending_ping_count = 0;
    local_if.upper_layer_count = 0;
    local_if.pending_forward_count = 0;

    for (int i = 0; i < MAX_PENDING_CLIENTS; i++) {
        local_if.pending_pings[i].client_fd = -1;
        local_if.pending_pings[i].waiting_for_arp = 0;
    }

    /* Initialize interfaces (MACs, sockaddr_ll) and open/bind RAW sockets */
    init_ifs(&local_if, mip_addr);

    /* Create UNIX domain listening socket for upper layer */
    int unix_sock = init_unix_socket(unix_path);
    if (unix_sock < 0) {
        fprintf(stderr, "Failed to init UNIX socket at %s\n", unix_path);
        exit(EXIT_FAILURE);
    }

    printf("[MIPD] UNIX socket created at path: %s, fd=%d\n", unix_path, unix_sock);

    int epollfd = epoll_create1(0);
    if (epollfd < 0) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev, events[MAX_EVENTS];

    /* Add RAW sockets to epoll */
    for (int i = 0; i < local_if.ifn; i++) {
        ev.events = EPOLLIN;
        ev.data.fd = local_if.rsock[i];
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, local_if.rsock[i], &ev) < 0) {
            perror("epoll_ctl RAW socket");
            exit(EXIT_FAILURE);
        }
    }

    /* Add UNIX listen socket to epoll */
    ev.events = EPOLLIN;
    ev.data.fd = unix_sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, unix_sock, &ev) < 0) {
        perror("epoll_ctl UNIX socket");
        exit(EXIT_FAILURE);
    }
    printf("\n========================================\n");
    printf("[MIPD] Started for MIP %d\n", mip_addr);
    printf("========================================\n");

    while (1) {
        int n = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        /* Categorize events for deterministic handling order */
        int idx_accept[MAX_EVENTS], n_accept = 0;
        int idx_client[MAX_EVENTS], n_client = 0;
        int idx_server[MAX_EVENTS], n_server = 0;
        int idx_routing[MAX_EVENTS], n_routing = 0;
        int idx_raw[MAX_EVENTS],    n_raw    = 0;

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == unix_sock) { idx_accept[n_accept++] = i; continue; }

            int is_raw = 0;
            for (int j = 0; j < local_if.ifn; j++) {
                if (fd == local_if.rsock[j]) { is_raw = 1; break; }
            }
            if (is_raw) { idx_raw[n_raw++] = i; continue; }

            if (fd == local_if.routing_daemon_fd) { idx_routing[n_routing++] = i; continue; }

            if (fd == local_if.server_fd) { idx_server[n_server++] = i; continue; }
            idx_client[n_client++] = i; // short-lived client
        }

        /* Handle new connections */
        for (int k = 0; k < n_accept; k++) {
            int i = idx_accept[k];
            (void)i; // events[i] not needed further here
            int client_fd = accept(unix_sock, NULL, NULL);
            if (client_fd < 0) {
                perror("accept");
                continue;
            }

            /* Use select to check if upper layer identification or client ping */
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(client_fd, &readfds);
            struct timeval tv = {0, 200000};
            
            int sel = select(client_fd + 1, &readfds, NULL, NULL, &tv);
            
            char peekbuf[64];
            ssize_t peek = 0;
            if (sel > 0) {
                peek = recv(client_fd, peekbuf, sizeof(peekbuf), MSG_PEEK);
            }
            
            if (peek == 1) {
                uint8_t first_byte = (uint8_t)peekbuf[0];
                
                if (first_byte <= 7) {
                    uint8_t sdu_type;
                    recv(client_fd, &sdu_type, 1, 0);

                    if (sdu_type == SDU_TYPE_ROUTING) {
                        local_if.routing_daemon_fd = client_fd;
                        printf("\n[MIPD] Routing daemon connected for MIP %d\n", 
                               local_if.local_mip_addr);

                        uint8_t mip_info[2];
                        mip_info[0] = local_if.local_mip_addr;
                        mip_info[1] = 0;
                        send(client_fd, mip_info, 2, 0);

                        struct epoll_event rev = { .events = EPOLLIN, .data.fd = client_fd };
                        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &rev) < 0) {
                            perror("epoll_ctl add routing_fd");
                            close(client_fd);
                            if (local_if.routing_daemon_fd == client_fd) local_if.routing_daemon_fd = -1;
                        }
                    } else {
                        if (local_if.upper_layer_count < MAX_UPPER_LAYERS) {
                            local_if.upper_layers[local_if.upper_layer_count].fd = client_fd;
                            local_if.upper_layers[local_if.upper_layer_count].sdu_type = sdu_type;
                            local_if.upper_layers[local_if.upper_layer_count].active = 1;

                            struct epoll_event uev = { .events = EPOLLIN, .data.fd = client_fd};
                            epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &uev);
                        }
                    }
                    continue;
                } else {
                    printf("[MIPD] Single byte (0x%02x) but not valid SDU type, treating as client\n", first_byte);
                }
            }
            
            if (peek >= 1) {
                printf("\n[MIPD] PING client connected for MIP %d\n", local_if.local_mip_addr);
                
                struct epoll_event cev = { .events = EPOLLIN, .data.fd = client_fd };
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &cev) < 0) {
                    perror("epoll_ctl add client_fd");
                    close(client_fd);
                    continue;
                }
                
                int rc = handle_unix_connection(&local_if, client_fd, debug);
                if (rc < 0) {
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, client_fd, NULL);
                    close(client_fd);
                }
            } else {
                printf("\n[MIPD] PING server connected for MIP %d\n", local_if.local_mip_addr);
                if (local_if.server_fd < 0) {
                    local_if.server_fd = client_fd;
                }
                struct epoll_event sev = { .events = EPOLLIN, .data.fd = client_fd };
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &sev) < 0) {
                    perror("epoll_ctl add server_fd");
                    if (local_if.server_fd == client_fd) local_if.server_fd = -1;
                    close(client_fd);
                } else if (debug) {
                    printf("[MIPD] Added server fd %d to epoll\n", client_fd);
                }
            }
        }

        /* Handle routing daemon messages */
        for (int k = 0; k < n_routing; k++) {
            int i = idx_routing[k];
            int fd = events[i].data.fd;

            // Read ALL available messages from routing daemon (may be multiple)
            while (1) {
                uint8_t buffer[MAX_SDU_SIZE];
                ssize_t m = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
                if (m <= 0) {
                    if (m == 0) {
                        printf("[MIPD] Routing dameon disconnected\n");
                        epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
                        close(fd);
                        if (local_if.routing_daemon_fd == fd) local_if.routing_daemon_fd = -1;
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recv from routing daemon");
                        epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
                        close(fd);
                        if (local_if.routing_daemon_fd == fd) local_if.routing_daemon_fd = -1;
                    }
                    // EAGAIN/EWOULDBLOCK = no more messages, break out of while loop
                    break;
                }
                
                // Message format: [dest_mip][ttl][payload...]
                if (m < 3) {
                    printf("[MIPD] Message from routing daemon too short (%zd bytes), ignoring\n", m);
                    continue;
                }

                uint8_t dest = buffer[0];
                uint8_t ttl = buffer[1];
                uint8_t *payload = buffer + 2;
                size_t payload_len = m - 2;

                // Check if it is a route response (RSP)
                if (payload_len >= 4 && payload[0] == 0x52 &&
                    payload[1] == 0x53 && payload[2] == 0x50) {
                        // Route response - handle it internally
                        handle_route_response(&local_if, payload, payload_len);
                } else {
                    // Routing protocol message (HELLO/UPDATE) - forward to network
                    const char *msg_type = (payload_len > 0 && payload[0] == 0x01) ? "HELLO" : 
                                           (payload_len > 0 && payload[0] == 0x02) ? "UPDATE" : "ROUTING";
                    printf("\n[MIPD] Forwarding %s from routing daemon to MIP %d\n", msg_type, dest);
                    send_mip_packet(&local_if, 0, dest, SDU_TYPE_ROUTING, 
                                    payload, payload_len, ttl, 0);
                }
            } // end while (reading all messages from routing daemon)
        } // end for (routing daemon events)

        /* Handle client messages */
        for (int k = 0; k < n_client; k++) {
            int i = idx_client[k];
            int fd = events[i].data.fd;
            int rc = handle_unix_connection(&local_if, fd, debug);
            if (rc < 0) {
                epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
            }
        }

        /* Handle server messages */
        for (int k = 0; k < n_server; k++) {
            int i = idx_server[k];
            int fd = events[i].data.fd;

            uint8_t buffer[MAX_SDU_SIZE];
            ssize_t m = recv(fd, buffer, sizeof(buffer), 0);
            if (m <= 0) {
                if (m == 0) printf("[MIPD] Server disconnected (fd=%d)\n", fd);
                else perror("recv from server");
                epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
                if (local_if.server_fd == fd) local_if.server_fd = -1;
            } else {
                if (m < 3) {
                    continue;
                }
                uint8_t dest = buffer[0];
                uint8_t ttl = buffer[1];
                uint8_t *sdu = buffer + 2;
                size_t sdu_len = (size_t)m - 2;

                printf("\n[MIPD] Server sending PONG: MIP %d -> %d (TTL=%d)\n",
                       local_if.local_mip_addr, dest, (ttl == 0) ? DEFAULT_TTL : ttl);
                printf("[MIPD] Payload: \"%.*s\"\n", (int)sdu_len, sdu);

                // Check if destination is local
                if (dest == local_if.local_mip_addr) {
                    fprintf(stderr, "[MIPD] Server trying to send to local address - ignoring\n");
                    continue;
                }

                // Check if destination is a direct neighbor (in ARP cache)
                uint8_t dst_mac[6];
                int send_if = -1;
                int have_arp = (arp_cache_lookup(local_if.arp.entries, local_if.arp.entry_count,
                                                 dest, dst_mac, &send_if) == 0);

                if (have_arp) {
                    // Direct neighbor - send directly
                    printf("[MIPD] PONG destination MIP %u is direct neighbor, sending directly\n", dest);
                    int rc = send_mip_packet(&local_if, send_if, dest, SDU_TYPE_PING, 
                                             sdu, sdu_len, ttl, 0);
                    if (rc < 0) {
                        fprintf(stderr, "[MIPD] Failed to send PONG to MIP %u\n", dest);
                    } else {
                        printf("[MIPD] PONG sent directly to MIP %u\n", dest);
                    }
                } else {
                    // Not a direct neighbor - use forwarding engine
                    printf("[MIPD] PONG destination MIP %u is NOT direct neighbor, using forwarding engine\n", dest);
                    uint8_t eff_ttl = (ttl == 0) ? DEFAULT_TTL : ttl;
                    forward_mip_packet(&local_if, dest, local_if.local_mip_addr, eff_ttl,
                                      SDU_TYPE_PING, sdu, sdu_len);
                }
            }
        }

        /* Handle RAW socket events */
        for (int k = 0; k < n_raw; k++) {
            int i = idx_raw[k];
            int fd = events[i].data.fd;

            int if_index = -1;
            for (int j = 0; j < local_if.ifn; j++) {
                if (fd == local_if.rsock[j]) { if_index = j; break; }
            }
            if (if_index < 0) continue;

            uint8_t buf[MAX_SDU_SIZE];
            struct sockaddr_ll addr;
            socklen_t addr_len = sizeof(addr);
            
            ssize_t rc = recvfrom(fd, buf, sizeof(buf), 0, 
                                 (struct sockaddr*)&addr, &addr_len);
            if (rc < 0) {
                perror("recvfrom RAW socket");
            } else if (rc > 0) {
                handle_mip_packet(&local_if, buf, (size_t)rc, if_index);
            }
        }
    }

    /* Cleanup */
    for (int i = 0; i < local_if.ifn; i++) {
        close(local_if.rsock[i]);
    }
    
    close(epollfd);
    close(unix_sock);
    unlink(unix_path);
    return 0;
}