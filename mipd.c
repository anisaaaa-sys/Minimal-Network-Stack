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
    local_if.server_fd = -1; // -1 -> no persistent server connected yet
    local_if.pending_ping_count = 0;
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
    if (debug) printf("[DEBUG] Creating epoll...\n");

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
            printf("Waiting for events...\n");
            fflush(stdout);
        }

        int n = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        if (debug) printf("Got %d events\n", n);

        /* Categorize events for deterministic handling order */
        int idx_accept[MAX_EVENTS], n_accept = 0;
        int idx_client[MAX_EVENTS], n_client = 0;
        int idx_server[MAX_EVENTS], n_server = 0;
        int idx_raw[MAX_EVENTS],    n_raw    = 0;

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (debug) {
                uint32_t evf = events[i].events;
                printf("[EPOLL EVENT] idx=%d fd=%d flags=0x%x (IN=%d ERR=%d HUP=%d RDHUP=%d)\n",
                       i, fd, evf,
                       !!(evf & EPOLLIN), !!(evf & EPOLLERR),
                       !!(evf & EPOLLHUP), !!(evf & EPOLLRDHUP));
            }

            if (fd == unix_sock) { idx_accept[n_accept++] = i; continue; }

            int is_raw = 0;
            for (int j = 0; j < local_if.ifn; j++) {
                if (fd == local_if.rsock[j]) { is_raw = 1; break; }
            }
            if (is_raw) { idx_raw[n_raw++] = i; continue; }

            if (fd == local_if.server_fd) { idx_server[n_server++] = i; continue; }

            idx_client[n_client++] = i; // short-lived client
        }

        for (int k = 0; k < n_accept; k++) {
            int i = idx_accept[k];
            (void)i; // events[i] not needed further here
            if (debug) printf("UNIX socket event - accepting connection\n");
            int client_fd = accept(unix_sock, NULL, NULL);
            if (client_fd < 0) {
                perror("accept");
                continue;
            }
            if (debug) printf("[DEBUG MIPD] New upper-layer connection: fd=%d\n", client_fd);

            // Differentiate client vs server by checking if data is already waiting
            char peekbuf[64];
            ssize_t peek = recv(client_fd, peekbuf, sizeof(peekbuf), MSG_PEEK | MSG_DONTWAIT);
            if (peek > 0) {
                if (debug) {
                    printf("[AFTER ACCEPT] fd=%d has %zd bytes waiting (client). First bytes: '%.*s'\n",
                           client_fd, peek, (int)(peek > 40 ? 40 : peek), peekbuf);
                }
                struct epoll_event cev = { .events = EPOLLIN, .data.fd = client_fd };
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &cev) < 0) {
                    perror("epoll_ctl add client_fd");
                    close(client_fd);
                    continue;
                } else if (debug) {
                    printf("[DEBUG] Added client fd %d to epoll\n", client_fd);
                }
                if (debug) printf("[DEBUG] Immediately handling client_fd=%d after accept (client)\n", client_fd);
                int rc = handle_unix_connection(&local_if, client_fd, debug);
                if (rc < 0) {
                    if (debug) printf("[MIPD] Client fd %d failed processing after accept (rc=%d). Removing.\n", client_fd, rc);
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, client_fd, NULL);
                    close(client_fd);
                } else {
                    if (debug) printf("[MIPD] Client fd %d processed after accept (rc=%d). Keeping open for PONG.\n", client_fd, rc);
                }
            } else {
                if (debug) {
                    if (peek == 0) printf("[AFTER ACCEPT] fd=%d peek==0 (peer closed?)\n", client_fd);
                    else if (errno == EAGAIN || errno == EWOULDBLOCK)
                        printf("[AFTER ACCEPT] fd=%d no data yet (probable server)\n", client_fd);
                    else perror("[AFTER ACCEPT] recv(MSG_PEEK) error");
                }
                if (local_if.server_fd < 0) {
                    local_if.server_fd = client_fd;
                    if (debug) printf("[DEBUG] Storing fd %d as persistent server connection\n", client_fd);
                }
                struct epoll_event sev = { .events = EPOLLIN, .data.fd = client_fd };
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &sev) < 0) {
                    perror("epoll_ctl add server_fd");
                    if (local_if.server_fd == client_fd) local_if.server_fd = -1;
                    close(client_fd);
                } else if (debug) {
                    printf("[DEBUG] Added server fd %d to epoll\n", client_fd);
                }
            }
        }

        for (int k = 0; k < n_client; k++) {
            int i = idx_client[k];
            int fd = events[i].data.fd;
            if (debug) printf("[DEBUG PASS A] Handling short-lived client fd=%d\n", fd);
            int rc = handle_unix_connection(&local_if, fd, debug);
            if (rc < 0) {
                if (debug) printf("[MIPD] Client fd %d failed processing (rc=%d). Removing from epoll.\n", fd, rc);
                epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
            } else {
                if (debug) printf("[MIPD] Client fd %d PING sent/deferred (rc=%d). Keeping socket open for PONG.\n", fd, rc);
            }
        }

        for (int k = 0; k < n_server; k++) {
            int i = idx_server[k];
            int fd = events[i].data.fd;
            if (debug) printf("[DEBUG PASS B] server_fd event on fd=%d\n", fd);

            uint8_t buffer[512];
            ssize_t m = recv(fd, buffer, sizeof(buffer), 0);
            if (m <= 0) {
                if (m == 0) printf("[MIPD] Server disconnected (fd=%d)\n", fd);
                else perror("recv from server");
                epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
                if (local_if.server_fd == fd) local_if.server_fd = -1;
            } else {
                if (m < 2) {
                    if (debug) printf("[MIPD] server sent too short message (%zd bytes)\n", m);
                    continue;
                }
                uint8_t dest = buffer[0];
                uint8_t *sdu = buffer + 1;
                size_t sdu_len = (size_t)m - 1;
                uint8_t sdu_type = SDU_TYPE_PING; // PING/PONG both use this type in your handler

                if (debug) {
                    printf("[MIPD] Server (fd=%d) sending message '%.*s' (%zd bytes) to MIP %u, sdu_type 0x%02x, sdu_len %zu\n",
                           fd, (int)sdu_len, sdu, m, dest, sdu_type, sdu_len);
                }

                int rc = send_mip_packet(&local_if, 0, dest, sdu_type, sdu, sdu_len);
                if (rc < 0) {
                    fprintf(stderr, "[MIPD] Failed to forward server message to MIP %u\n", dest);
                    int exists = 0;
                    for (int k = 0; k < local_if.pending_ping_count; k++) {
                        if (local_if.pending_pings[k].dest_mip == dest) {
                            exists = -1;
                            break;
                        }
                    }

                    if (!exists) {
                        if (local_if.pending_ping_count < MAX_PENDING_CLIENTS) {
                            struct pending_ping *p = &local_if.pending_pings[local_if.pending_ping_count++];
                            p->client_fd = -1;
                            p->dest_mip  = dest;
                            size_t cap = (sdu_len > MAX_SDU_SIZE) ? MAX_SDU_SIZE : sdu_len;
                            memcpy(p->sdu, sdu, cap);
                            p->sdu_len = cap;
                            p->waiting_for_arp = 1;
                        } else {
                            fprintf(stderr, "[MIPD] Pending queue full; dropping server message\n");
                        }
                    }
                } else if (debug) {
                    printf("[MIPD] Forwarded server message to MIP %u (rc=%d)\n", dest, rc);
                }
            }
        }

        for (int k = 0; k < n_raw; k++) {
            int i = idx_raw[k];
            int fd = events[i].data.fd;

            int if_index = -1;
            for (int j = 0; j < local_if.ifn; j++) {
                if (fd == local_if.rsock[j]) { if_index = j; break; }
            }
            if (if_index < 0) continue;
            if (debug) printf("[DEBUG PASS C] RAW socket event on interface %d (fd=%d)\n", if_index, fd);

            uint8_t buf[2048];
            struct sockaddr_ll addr;
            socklen_t addr_len = sizeof(addr);
            ssize_t rc = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &addr_len);
            if (rc < 0) {
                perror("recvfrom RAW socket");
            } else if (rc == 0) {
                if (debug) printf("recvfrom returned 0\n");
            } else {
                if (debug) printf("[DEBUG] Received %zd bytes on RAW fd %d\n", rc, fd);
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