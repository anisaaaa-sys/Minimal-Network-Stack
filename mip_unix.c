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

/* Initialize a UNIX domain socket to communicate with upper layer */
int init_unix_socket(const char *path) {
    int sock;
    struct sockaddr_un addr;

    sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        perror("init_unix_socket: socket");
        return -1;
    }

    printf("[MIPD] UNIX socket created: fd=%d\n", sock);

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

/* Handle incoming UNIX socket connection from upper layer */
int handle_unix_connection(struct ifs_data *ifs, int client_fd, int debug) {
    uint8_t buffer[MAX_SDU_SIZE];
    ssize_t nread = read(client_fd, buffer, sizeof(buffer));
    printf("[MIPD] Read %ld bytes from client\n", nread);
    fflush(stdout);

    if (nread <= 0) {
        if (nread < 0) {
            if (debug) perror("handle_unix_connection: read");
        } else {
            // nread == 0: Client closed the socket
            if (debug) printf("[MIPD] Client closed connection (nread == 0). Closing fd %d\n", client_fd);
        }
        close(client_fd);
        return -1;
    } 

    // SPECIAL COMMAND: Check if first byte is 0xFF (clear ARP cache command)
    if (nread == 1 && buffer[0] == 0xFF) {
        printf("[MIPD] Received ARP cache clear command\n");
        ifs->arp.entry_count = 0;
        printf("[MIPD] ARP cache cleared (was %d entries, now 0)\n", ifs->arp.entry_count);
        
        // Send acknowledgment back
        uint8_t ack = SDU_TYPE_ARP;
        write(client_fd, &ack, 1);
        close(client_fd);
        return 0;
    }

    /* Message format: [dest_mip][ttl][sdu...] */
    if (nread < 2) {
        fprintf(stderr, "handle_unix_connection: message too short\n");
        close(client_fd);
        return -1;
    }

    uint8_t dest_mip = buffer[0];       // First byte is destination MIP address
    uint8_t ttl = buffer[1];            // Second byte is TTL (0 = use default)
    const uint8_t *sdu = buffer + 2;    // Rest is the message
    size_t sdu_len_bytes = nread - 2;

    printf("[MIPD RECV CLIENT] nread = %ld, dest=%d, ttl=%d\n", nread, dest_mip, ttl);

    // Check if destination is local
    if (dest_mip == ifs->local_mip_addr) {
        printf("[MIPD] Destination is local (loopback), not implemented\n");
        close(client_fd);
        return -1;
    }

    // PAD SDU to 32-bit boundary
    size_t padded_sdu_len = ((sdu_len_bytes + 3) / 4) * 4; // Round up to multiple of 4
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
    printf("[PENDING] Added pending EARLY: fd=%d dest=%d total=%d\n",
           pending->client_fd, pending->dest_mip, ifs->pending_ping_count);

    uint8_t dst_mac[6];
    int send_if = -1;


    if (dest_mip == MIP_DEST_ADDR) {
        printf("[MIPD] Broadcast packet detected (dest=255) - sending on all interfaces\n");

        uint8_t eff_ttl = (ttl == 0) ? DEFAULT_TTL : ttl;

        for (int i = 0; i < ifs->ifn; i++) {
            int rc = send_mip_packet(ifs, i, MIP_DEST_ADDR, SDU_TYPE_PING,
                                     padded_sdu, padded_sdu_len, eff_ttl, 0);
            if (rc < 0) {
                perror("send_mip_packet: broadcast failed");
            } else {
                printf("[MIPD] Broadcast sent on interface %d", i);
            }
        }
        free(padded_sdu);
        return 1;
    }

    /* ARP cache lookup */
    printf("[MIPD] ********** CHECKING ARP CACHE FOR MIP %d **********\n", dest_mip);
    printf("[MIPD] ARP cache count=%d\n", ifs->arp.entry_count);
    
    int arp_found = arp_cache_lookup(ifs->arp.entries, ifs->arp.entry_count,
                            dest_mip, dst_mac, &send_if);

    printf("[MIPD] ARP lookup result: arp_found=%d\n", arp_found);
    
    if (arp_found != 0) {
        // Not in cache: use forwarding engine for multi-hop routing
        printf("[MIPD] ********** ARP MISS - USING FORWARDING ENGINE **********\n");
        printf("[MIPD] Calling forward_mip_packet(dest=%d, src=%d, ttl=%d)\n",
               dest_mip, ifs->local_mip_addr, (ttl == 0) ? DEFAULT_TTL : ttl);
        
        uint8_t eff_ttl = (ttl == 0) ? DEFAULT_TTL : ttl;
        forward_mip_packet(ifs, dest_mip, ifs->local_mip_addr, eff_ttl, 
                          SDU_TYPE_PING, sdu, sdu_len_bytes);
        
        free(padded_sdu);
        // Keep client connection open for PONG
        return 1; 
    } else {
        printf("[MIPD] ARP CACHE HIT for MIP %d - using cached MAC\n", dest_mip);

        /* Send the MIP packet with specified TTL */
        printf("[MIPD] Sending MIP packet to MIP %d via interface %d (TTL=%d)\n", 
               dest_mip, send_if, pending->ttl);
        int rc = send_mip_packet(ifs, send_if, dest_mip, SDU_TYPE_PING, 
                                 padded_sdu, padded_sdu_len, pending->ttl, 0);
    
        free(padded_sdu);

        if (rc < 0) {
            perror("handle_unix_connection: send_mip_packet");
            ifs->pending_ping_count--;
            close(client_fd);
            return -1;
        } else if (debug) {
            printf("[MIPD] Sent SDU to MIP %u via if %d: %.*s\n",
                   dest_mip, send_if, (int)sdu_len_bytes, sdu);
        }

        return 1;
    }
}