#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "mipd.h"

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
        printf("Added RAW socket fd %d to epoll (if %d)\n", local_if.rsock[i], i);
    }

    /* Add UNIX listen socket to epoll */
    ev.events = EPOLLIN;
    ev.data.fd = unix_sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, unix_sock, &ev) < 0) {
        perror("epoll_ctl UNIX socket");
        exit(EXIT_FAILURE);
    }
    printf("Added UNIX socket fd %d to epoll\n", unix_sock);

    printf("MIP daemon started at MIP addr %d, unix socket %s\n", mip_addr, unix_path);

    while (1) {
        if (debug) {
            printf("[MIPD] Waiting for events...\n");
            fflush(stdout);
        }

        int n = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        if (debug) printf("[MIPD] Got %d events\n", n);

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
            if (debug) printf("[MIPD] UNIX socket event - accepting connection\n");
            int client_fd = accept(unix_sock, NULL, NULL);
            if (client_fd < 0) {
                perror("accept");
                continue;
            }
            printf("\n========== NEW CONNECTION fd=%d ==========\n", client_fd);
            fflush(stdout);
            if (debug) printf("[MIPD] New upper-layer connection: fd=%d\n", client_fd);

            // Check if this is an upper layer identification
            // Use select to wait for data with timeout
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(client_fd, &readfds);
            struct timeval tv = {0, 200000}; // 200ms timeout
            
            int sel = select(client_fd + 1, &readfds, NULL, NULL, &tv);
            
            char peekbuf[64];
            ssize_t peek = 0;
            if (sel > 0) {
                peek = recv(client_fd, peekbuf, sizeof(peekbuf), MSG_PEEK);
            }
            
            printf("[MIPD] Peeked %zd bytes from fd=%d (select returned %d)\n", peek, client_fd, sel);
            if (peek < 0) {
                printf("[MIPD] Peek error: %s\n", strerror(errno));
            } else if (peek > 0) {
                printf("[MIPD] First byte: 0x%02x (%d decimal)\n", 
                       (unsigned char)peekbuf[0], (unsigned char)peekbuf[0]);
                if (peek >= 2) {
                    printf("[MIPD] First 2 bytes: 0x%02x 0x%02x\n", 
                           (unsigned char)peekbuf[0], (unsigned char)peekbuf[1]);
                }
            } else {
                printf("[MIPD] No data peeked (select=%d, peek=%zd)\n", sel, peek);
            }
            fflush(stdout);
            
            if (peek == 1) {
                // Single byte = SDU type identification (but only if it's a valid SDU type)
                uint8_t first_byte = (uint8_t)peekbuf[0];
                
                // SDU types are in range [0, 7], so check if this is a valid identification
                if (first_byte <= 7) {
                    // This is an identification byte
                    uint8_t sdu_type;
                    recv(client_fd, &sdu_type, 1, 0);

                    printf("[MIPD] Upper layer identified: SDU type 0x%02x\n", sdu_type);

                    if (sdu_type == SDU_TYPE_ROUTING) {
                        // This is the routing daemon
                        printf("\n");
                        printf("=====================================================\n");
                        printf("[MIPD] ***** ROUTING DAEMON IDENTIFICATION *****\n");
                        printf("[MIPD] SDU type 0x%02x == SDU_TYPE_ROUTING (0x%02x)\n", 
                               sdu_type, SDU_TYPE_ROUTING);
                        printf("[MIPD] OLD routing_daemon_fd = %d\n", local_if.routing_daemon_fd);
                        printf("[MIPD] NEW routing_daemon_fd = %d (client_fd)\n", client_fd);
                        
                        if (local_if.routing_daemon_fd >= 0 && local_if.routing_daemon_fd != client_fd) {
                            printf("[MIPD] WARNING: Overwriting existing routing daemon fd=%d with fd=%d!\n",
                                   local_if.routing_daemon_fd, client_fd);
                        }
                        
                        local_if.routing_daemon_fd = client_fd;
                        printf("[MIPD] Routing daemon connected (fd=%d) for MIP %d\n", 
                               client_fd, local_if.local_mip_addr);
                        printf("[MIPD] ***** END ROUTING DAEMON SETUP *****\n");
                        printf("=====================================================\n");
                        printf("\n");

                        // Send local MIP address to routing daemon
                        uint8_t mip_info[2];
                        mip_info[0] = local_if.local_mip_addr;
                        mip_info[1] = 0;
                        ssize_t sent = send(client_fd, mip_info, 2, 0);
                        printf("[MIPD] Sent MIP info to routing daemon: mip=%d (sent=%zd bytes)\n", 
                               local_if.local_mip_addr, sent);

                        // Add to epoll
                        struct epoll_event rev = { .events = EPOLLIN, .data.fd = client_fd };
                        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &rev) < 0) {
                            perror("epoll_ctl add routing_fd");
                            close(client_fd);
                            if (local_if.routing_daemon_fd == client_fd) local_if.routing_daemon_fd = -1;
                        } else if (debug) {
                            printf("[MIPD] Added routing daemon fd %d to epoll\n", client_fd);
                        }
                    } else {
                        // Other upper layer (store for later)
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
                    // peek == 1 but first_byte > 7, so it's not an identification
                    // Treat it as a client connection with data waiting
                    printf("[MIPD] Single byte (0x%02x) but not valid SDU type, treating as client\n", first_byte);
                    // Fall through to handle as client connection
                }
            }
            
            if (peek >= 1) {
                // Data waiting = client ping request (or peek==1 with invalid SDU type)
                if (debug) {
                    printf("[MIPD] fd=%d has %zd bytes waiting (client). First bytes: '%.*s'\n",
                           client_fd, peek, (int)(peek > 40 ? 40 : peek), peekbuf);
                }
                struct epoll_event cev = { .events = EPOLLIN, .data.fd = client_fd };
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &cev) < 0) {
                    perror("epoll_ctl add client_fd");
                    close(client_fd);
                    continue;
                } else if (debug) {
                    printf("[MIPD] Added client fd %d to epoll\n", client_fd);
                }
                if (debug) printf("[MIPD] Immediately handling client_fd=%d after accept (client)\n", client_fd);
                int rc = handle_unix_connection(&local_if, client_fd, debug);
                if (rc < 0) {
                    if (debug) printf("[MIPD] Client fd %d failed processing after accept (rc=%d). Removing.\n", client_fd, rc);
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, client_fd, NULL);
                    close(client_fd);
                } else {
                    if (debug) printf("[MIPD] Client fd %d processed after accept (rc=%d). Keeping open for PONG.\n", client_fd, rc);
                }
            } else {
                // No data = server connection
                if (local_if.server_fd < 0) {
                    local_if.server_fd = client_fd;
                    if (debug) printf("[MIPD] Storing fd %d as persistent server connection\n", client_fd);
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
            if (debug) printf("[MIPD] Routing daemon event on fd=%d\n", fd);

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
                printf("[MIPD] Received %zd bytes from routing daemon (fd=%d): ", m, fd);
                for (ssize_t j = 0; j < m && j < 10; j++) {
                    printf("0x%02x ", buffer[j]);
                }
                printf("\n");
                
                // Message format: [dest_mip][ttl][payload...]
                if (m < 3) {
                    printf("[MIPD] Message from routing daemon too short (%zd bytes), ignoring\n", m);
                    continue;
                }

                uint8_t dest = buffer[0];
                uint8_t ttl = buffer[1];
                uint8_t *payload = buffer + 2;
                size_t payload_len = m - 2;

                printf("[MIPD] Parsing routing daemon message: dest=%d, ttl=%d, payload_len=%zu\n",
                       dest, ttl, payload_len);
                if (payload_len >= 1) {
                    printf("[MIPD] Payload[0]=0x%02x", payload[0]);
                    if (payload_len >= 2) printf(" Payload[1]=0x%02x", payload[1]);
                    if (payload_len >= 3) printf(" Payload[2]=0x%02x", payload[2]);
                    if (payload_len >= 4) printf(" Payload[3]=0x%02x", payload[3]);
                    printf("\n");
                }

                // Check if it is a route response
                printf("[MIPD] Checking if route response: payload_len=%zu (need >=4), ", payload_len);
                printf("payload[0]=0x%02x (need 0x52), payload[1]=0x%02x (need 0x53), payload[2]=0x%02x (need 0x50)\n",
                       payload_len >= 1 ? payload[0] : 0,
                       payload_len >= 2 ? payload[1] : 0,
                       payload_len >= 3 ? payload[2] : 0);
                
                if (payload_len >= 4 && payload[0] == 0x52 &&
                    payload[1] == 0x53 && payload[2] == 0x50) {
                        // Route response - handle it
                        printf("[MIPD] *** RECEIVED ROUTE RESPONSE FROM ROUTING DAEMON ***\n");
                        printf("[MIPD] Calling handle_route_response with payload_len=%zu\n", payload_len);
                        handle_route_response(&local_if, payload, payload_len);
                        printf("[MIPD] *** ROUTE RESPONSE HANDLED ***\n");
                } else {
                    // Regular routing protocol message - send it
                    if (debug) printf("[MPID] Routing daemon sending to MIP %d\n", dest);
                    send_mip_packet(&local_if, 0, dest, SDU_TYPE_ROUTING, 
                                    payload, payload_len, ttl, 0);
                }
            } // end while (reading all messages from routing daemon)
        } // end for (routing daemon events)

        /* Handle client messages */
        for (int k = 0; k < n_client; k++) {
            int i = idx_client[k];
            int fd = events[i].data.fd;
            if (debug) printf("[MIPD] Handling short-lived client fd=%d\n", fd);
            int rc = handle_unix_connection(&local_if, fd, debug);
            if (rc < 0) {
                if (debug) printf("[MIPD] Client fd %d failed processing (rc=%d). Removing from epoll.\n", fd, rc);
                epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
            } else {
                if (debug) printf("[MIPD] Client fd %d PING sent/deferred (rc=%d). Keeping socket open for PONG.\n", fd, rc);
            }
        }

        /* Handle server messages */
        for (int k = 0; k < n_server; k++) {
            int i = idx_server[k];
            int fd = events[i].data.fd;
            if (debug) printf("[MIPD] server_fd event on fd=%d\n", fd);

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
                    if (debug) printf("[MIPD] Server sent too short message (%zd bytes)\n", m);
                    continue;
                }
                uint8_t dest = buffer[0];
                uint8_t ttl = buffer[1];
                uint8_t *sdu = buffer + 2;
                size_t sdu_len = (size_t)m - 2;

                printf("[MIPD] Server (fd=%d) sending PONG: %zd bytes to MIP %u, TTL %u\n",
                       fd, m, dest, ttl);
                printf("[MIPD] PONG payload: '%.*s'\n", (int)sdu_len, sdu);

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
            if (debug) printf("[MIPD] RAW socket event on interface %d (fd=%d)\n", if_index, fd);

            uint8_t buf[MAX_SDU_SIZE];
            struct sockaddr_ll addr;
            socklen_t addr_len = sizeof(addr);
            
            ssize_t rc = recvfrom(fd, buf, sizeof(buf), 0, 
                                 (struct sockaddr*)&addr, &addr_len);
            if (rc < 0) {
                perror("recvfrom RAW socket");
            } else if (rc == 0) {
                if (debug) printf("recvfrom returned 0\n");
            } else {
                if (debug) printf("[MIPD] Received %zd bytes on RAW fd %d\n", rc, fd);
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