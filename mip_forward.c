#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include "mipd.h"

/* Send route lookup request to routing daemon */
void send_route_request(struct ifs_data *ifs, uint8_t dest_mip) {
    if (ifs->routing_daemon_fd < 0) {
        printf("[FORWARD] No routing daemon connected\n");
        return;
    }

    // REQUEST format: [local_mip][ttl=0]['R']['E']['Q'][dest_mip]
    uint8_t buffer[6];
    buffer[0] = ifs->local_mip_addr;
    buffer[1] = 0; // TTL
    buffer[2] = 0x52; // 'R'
    buffer[3] = 0x45; // 'E'
    buffer[4] = 0x51; // 'Q'
    buffer[5] = dest_mip;

    ssize_t sent = send(ifs->routing_daemon_fd, buffer, 6, 0);
    if (sent < 0) {
        perror("send_route_request");
    } else {
        printf("[FORWARD] Sent route request for MIP %d to routing daemon\n", dest_mip);
    }
}

/* Handle route response from routing daemon */
void handle_route_response(struct ifs_data *ifs, const uint8_t *payload, size_t len) {
    // RESPONSE format: ['R']['S']['P'][next_hop_mip]
    if (len < 4) {
        fprintf(stderr, "[FORWARD] Route response too short\n");
        return;
    }

    if (payload[0] != 0x52 || payload[1] != 0x53 || payload[2] != 0x50) {
        fprintf(stderr, "[FORWARD] Invalid route response format\n");
        return;
    }

    uint8_t next_hop = payload[3];

    printf("[FORWARD] Received route response: next_hop=%d\n", next_hop);

    // Process all pending forwards
    for (int i = 0; i < ifs->pending_forward_count; i++) {
        struct pending_forward *pf = &ifs->pending_forwards[i];
        if (!pf->active) continue;

        if (next_hop == 255) {
            // No route found - drop packet
            printf("[FORWARD] No route to MIP %d, dropping packet\n", pf->dest_mip);
            pf->active = 0;
            continue;
        }

        printf("[FORWARD] Forwarding to MIP %d via next hop %d (TTL=%d)\n",
                pf->dest_mip, next_hop, pf->ttl);

        //Look up next hop in ARP cache
        uint8_t next_hop_mac[6];
        int send_if = -1;
        int arp_found = arp_cache_lookup(ifs->arp.entries, ifs->arp.entry_count,
                                         next_hop, next_hop_mac, &send_if);
        
        if (arp_found != 0) {
            // Next hop not in ARP cache, send ARP request
            printf("[FORWARD] Next hop MIP %d not in ARP cache, broadcasting ARP\n", next_hop);
            for (int j = 0; j < ifs->ifn; j++) {
                send_arp_request(ifs, j, next_hop);
            }
            // Keep packet pending
            continue;
        }

        // Send the packet
        int rc = send_mip_packet(ifs, send_if, pf->dest_mip, pf->sdu_type,
                                 pf->sdu, pf->sdu_len, pf->ttl);
        
        if (rc < 0) {
            fprintf(stderr, "[FORWARD] Failed to forward packet to MIP %d\n", pf->dest_mip);
        } else {
            printf("[FORWARD] Successfully forwarded packet to MIP %d\n", pf->dest_mip);
        }
        pf->active = 0;
    }

    // Compact pending forwards list
    int write_idx = 0;
    for (int i = 0; i < ifs->pending_forward_count; i++) {
        if (ifs->pending_forwards[i].active) {
            if (write_idx != i) {
                ifs->pending_forwards[write_idx] = ifs->pending_forwards[i];
            }
            write_idx++;
        }
    }
    ifs->pending_forward_count = write_idx;
}

/* Forward a MIP packet (non-blocking with routing lookup) */
void forward_mip_packet(struct ifs_data *ifs, uint8_t dest_mip, uint8_t src_mip,
                        uint8_t ttl, uint8_t sdu_type, const uint8_t *sdu, 
                        size_t sdu_len) {
    printf("[FORWARD] ===== FORWARDING PACKET =====\n");
    printf("[FORWARD] Request to forward packet: dest=%d, src=%d, TTL=%d, type=0x%02x\n",
            dest_mip, src_mip, ttl, sdu_type);
    printf("[FORWARD] Routing daemon fd: %d\n", ifs->routing_daemon_fd);
    
    // Check TTL
    if (ttl == 0) {
        printf("[FORWARD] TTL expired (TTL=0), dropping packet\n");
        return;
    }

    // Decrement TTL
    ttl--;
    printf("[FORWARD] Decremented TTL: %d -> %d\n", ttl + 1, ttl);
    if (ttl == 0) {
        printf("[FORWARD] TTL would become 0 after decrement, dropping packet\n");
        return;
    }

    // Check if we already have a pending forward for this destination
    int found_pending = 0;
    for (int i = 0; i < ifs->pending_forward_count; i++) {
        if (ifs->pending_forwards[i].active &&
            ifs->pending_forwards[i].dest_mip == dest_mip) {
            found_pending = 1;
            printf("[FORWARD] Already have a pending forward for MIP %d\n", dest_mip);
            break;
        }
    }

    // Add to pending forwards
    if (ifs->pending_forward_count < MAX_PENDING_FORWARDS) {
        struct pending_forward *pf = &ifs->pending_forwards[ifs->pending_forward_count];
        pf->dest_mip = dest_mip;
        pf->src_mip = src_mip;
        pf->ttl = ttl;
        pf->sdu_type = sdu_type;

        size_t copy_len = (sdu_len < MAX_SDU_SIZE) ? sdu_len : MAX_SDU_SIZE;
        memcpy(pf->sdu, sdu, copy_len);
        pf->sdu_len = copy_len;
        pf->timestamp = time(NULL);
        pf->active = 1;

        ifs->pending_forward_count++;

        // Request route lookup (only if not already pending)
        if (!found_pending) {
            send_route_request(ifs, dest_mip);
        }
    } else {
        fprintf(stderr, "[FORWARD] Too many pending forwards, dropping packet\n");
    }
}

/* Find upper layer client by SDU type */
int find_upper_layer_client(struct ifs_data *ifs, uint8_t sdu_type) {
    for (int i = 0; i < ifs->upper_layer_count; i++) {
        if (ifs->upper_layers[i].active &&
            ifs->upper_layers[i].sdu_type == sdu_type) {
            return ifs->upper_layers[i].fd;
        }
    }
    return -1; // Not found
}