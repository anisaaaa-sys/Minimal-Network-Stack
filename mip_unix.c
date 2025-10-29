/**
 * mip_unix.c - UNIX Domain Socket Interface for Upper Layer Communication
 * 
 * Implements communication between the MIP daemon and upper layer applications
 * (ping client/server, routing daemon) using UNIX domain sockets (SOCK_SEQPACKET).
 * Handles connection setup, message passing, and application protocol.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <arpa/inet.h>  /* htons */ 
#include <time.h>

#include "mipd.h" 

/**
 * Initialize a UNIX domain socket to communicate with upper layer applications
 * path: Path to UNIX socket file (will be created)
 * 
 * Creates, binds, and listens on a UNIX SOCK_SEQPACKET socket.
 * The socket will be used to accept connections from ping clients/servers
 * and the routing daemon.
 * 
 * Global variables: None
 * Returns: Socket file descriptor on success, -1 on error
 * Error conditions: Socket creation failure, bind failure (path exists),
 *                   listen failure
 */
int init_unix_socket(const char *path) {
    int sock;
    struct sockaddr_un addr;

    sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        perror("init_unix_socket: socket");
        return -1;
    }


    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    
    /* Remove any previous socket file */
    unlink(path);

    /* Bind socket to address */
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("init_unix_socket: bind");
        close(sock);
        return -1;
    }

    /* Listen for incoming connections */
    if (listen(sock, 5) < 0) {
        perror("init_unix_socket: listen");
        close(sock);
        return -1;
    }

    return sock;
}

/**
 * Handle data received from UNIX socket (upper layer application)
 * ifs: Interface data for sending packets
 * client_fd: File descriptor of the client connection
 * debug: Debug flag (currently unused)
 * 
 * Reads data from ping client over UNIX socket and processes the request.
 * 
 * Message format from client: [dest_mip (1)][ttl (1)][message (variable)]
 * 
 * Processing:
 * 1. Check if destination is a direct neighbor (1-hop away in routing table)
 * 2. If neighbor: send directly via send_mip_packet()
 * 3. If not neighbor: queue for forwarding via forward_mip_packet()
 * 
 * Special commands:
 * - First byte 0xFF: Clear ARP cache command
 * 
 * Global variables: ifs->pending_pings (may add pending ping if ARP miss)
 *                   ifs->arp (for neighbor check and cache clear)
 * Returns: 0 on success, -1 on error or connection close
 * Error conditions: Read error, invalid message format, queue full
 */
int handle_unix_connection(struct ifs_data *ifs, int client_fd, int debug) {
    uint8_t buffer[MAX_SDU_SIZE];
    ssize_t nread = read(client_fd, buffer, sizeof(buffer));

    if (nread <= 0) {
        if (nread < 0) {
            if (debug) perror("handle_unix_connection: read");
        } else {
            if (debug) printf("[MIPD] Client closed connection. Closing fd %d\n", client_fd);
        }
        close(client_fd);
        return -1;
    } 

    if (nread == 1 && buffer[0] == 0xFF) {
        ifs->arp.entry_count = 0;
        uint8_t ack = SDU_TYPE_ARP;
        write(client_fd, &ack, 1);
        close(client_fd);
        return 0;
    }

    if (nread < 2) {
        fprintf(stderr, "handle_unix_connection: message too short\n");
        close(client_fd);
        return -1;
    }

    uint8_t dest_mip = buffer[0];
    uint8_t ttl = buffer[1];
    const uint8_t *sdu = buffer + 2;
    size_t sdu_len_bytes = nread - 2;

    if (dest_mip == ifs->local_mip_addr) {
        close(client_fd);
        return -1;
    }

    size_t padded_sdu_len = ((sdu_len_bytes + 3) / 4) * 4;
    uint8_t *padded_sdu = malloc(padded_sdu_len);
    if (!padded_sdu) {
        fprintf(stderr, "Memory allocation failed\n");
        close(client_fd);
        return -1;
    }
    memcpy(padded_sdu, sdu, sdu_len_bytes);
    memset(padded_sdu + sdu_len_bytes, 0, padded_sdu_len - sdu_len_bytes);

    if (ifs->pending_ping_count >= MAX_PENDING_CLIENTS) {
        fprintf(stderr, "[MIPD] Too many pending pings, dropping request from fd %d\n", client_fd);
        free(padded_sdu);
        close(client_fd);
        return -1;
    }

    struct pending_ping *pending = &ifs->pending_pings[ifs->pending_ping_count++];
    pending->client_fd = client_fd;
    pending->dest_mip = dest_mip;
    pending->ttl = (ttl == 0) ? DEFAULT_TTL : ttl;
    pending->waiting_for_arp = 0;
    if (sdu_len_bytes > MAX_SDU_SIZE) sdu_len_bytes = MAX_SDU_SIZE;
    memcpy(pending->sdu, sdu, sdu_len_bytes);
    pending->sdu_len = sdu_len_bytes;

    if (dest_mip == MIP_DEST_ADDR) {
        uint8_t eff_ttl = (ttl == 0) ? DEFAULT_TTL : ttl;

        for (int i = 0; i < ifs->ifn; i++) {
            int rc = send_mip_packet(ifs, i, MIP_DEST_ADDR, SDU_TYPE_PING,
                                     padded_sdu, padded_sdu_len, eff_ttl, 0);
            if (rc < 0) {
                perror("send_mip_packet: broadcast failed");
            }
        }
        free(padded_sdu);
        return 1;
    }

    /* ARP cache lookup */
    uint8_t dst_mac[6];
    int send_if = -1;
    int arp_found = arp_cache_lookup(ifs->arp.entries, ifs->arp.entry_count,
                            dest_mip, dst_mac, &send_if);
    
    if (arp_found != 0) {
        // Not in cache: use forwarding engine for route lookup
        printf("\n[MIPD] Received PING from client: MIP %d -> %d (TTL=%d)\n",
               ifs->local_mip_addr, dest_mip, (ttl == 0) ? DEFAULT_TTL : ttl);
        printf("[MIPD] Payload: \"%.*s\"\n", (int)sdu_len_bytes, sdu);
        printf("[MIPD] Forwarding via routing daemon\n");
        
        uint8_t eff_ttl = (ttl == 0) ? DEFAULT_TTL : ttl;
        forward_mip_packet(ifs, dest_mip, ifs->local_mip_addr, eff_ttl, 
                          SDU_TYPE_PING, sdu, sdu_len_bytes);
        
        free(padded_sdu);
        return 1; 
    } else {
        printf("\n[MIPD] Received PING from client: MIP %d -> %d (TTL=%d)\n",
               ifs->local_mip_addr, dest_mip, pending->ttl);
        printf("[MIPD] Payload: \"%.*s\"\n", (int)sdu_len_bytes, sdu);
        printf("[MIPD] Sending using cached ARP entry\n");
        
        int rc = send_mip_packet(ifs, send_if, dest_mip, SDU_TYPE_PING, 
                                 padded_sdu, padded_sdu_len, pending->ttl, 0);
    
        free(padded_sdu);

        if (rc < 0) {
            perror("handle_unix_connection: send_mip_packet");
            ifs->pending_ping_count--;
            close(client_fd);
            return -1;
        }

        return 1;
    }
}