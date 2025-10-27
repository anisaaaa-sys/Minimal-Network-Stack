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
    printf("[FORWARD] ============ HANDLE ROUTE RESPONSE ============\n");
    printf("[FORWARD] Payload length: %zu\n", len);
    
    // RESPONSE format: ['R']['S']['P'][next_hop_mip]
    if (len < 4) {
        fprintf(stderr, "[FORWARD] Route response too short (%zu bytes)\n", len);
        return;
    }

    printf("[FORWARD] Payload bytes: 0x%02x 0x%02x 0x%02x 0x%02x\n",
           payload[0], payload[1], payload[2], payload[3]);

    if (payload[0] != 0x52 || payload[1] != 0x53 || payload[2] != 0x50) {
        fprintf(stderr, "[FORWARD] Invalid route response format\n");
        return;
    }

    uint8_t next_hop = payload[3];

    printf("[FORWARD] *** RECEIVED ROUTE RESPONSE: next_hop=%d ***\n", next_hop);
    printf("[FORWARD] Pending forwards count: %d\n", ifs->pending_forward_count);

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

        printf("[FORWARD] Next hop MIP %d found in ARP cache: MAC %02x:%02x:%02x:%02x:%02x:%02x on if %d\n",
               next_hop, next_hop_mac[0], next_hop_mac[1], next_hop_mac[2],
               next_hop_mac[3], next_hop_mac[4], next_hop_mac[5], send_if);

        // CRITICAL: When forwarding, we need to send to the NEXT HOP's MAC address,
        // not the final destination. So we call send_mip_packet with next_hop as dst_mip
        // to ensure it uses the next hop's MAC. But we need to fix the MIP header afterward.
        // Actually, a better approach: temporarily add the dest_mip with next_hop's MAC to ARP cache
        
        // Save any existing ARP entry for dest_mip
        uint8_t old_mac[6];
        int old_if = -1;
        int had_dest_arp = (arp_cache_lookup(ifs->arp.entries, ifs->arp.entry_count,
                                             pf->dest_mip, old_mac, &old_if) == 0);
        
        // Temporarily set dest_mip to use next_hop's MAC
        // Find or create ARP entry for dest_mip
        int dest_entry_idx = -1;
        for (int j = 0; j < ifs->arp.entry_count; j++) {
            if (ifs->arp.entries[j].mip_addr == pf->dest_mip) {
                dest_entry_idx = j;
                break;
            }
        }
        if (dest_entry_idx < 0 && ifs->arp.entry_count < ARP_CACHE_SIZE) {
            dest_entry_idx = ifs->arp.entry_count++;
        }
        
        if (dest_entry_idx >= 0) {
            // Temporarily override: make dest_mip point to next_hop's MAC
            ifs->arp.entries[dest_entry_idx].mip_addr = pf->dest_mip;
            memcpy(ifs->arp.entries[dest_entry_idx].mac_addr, next_hop_mac, 6);
            ifs->arp.entries[dest_entry_idx].if_index = send_if;
            
            printf("[FORWARD] Temporarily set ARP[%d]: MIP %d -> next_hop MAC\n",
                   dest_entry_idx, pf->dest_mip);
        }

        // Send the packet - now send_mip_packet will find dest_mip with next_hop's MAC
        // IMPORTANT: Pass pf->src_mip to preserve the original source address when forwarding
        int rc = send_mip_packet(ifs, send_if, pf->dest_mip, pf->sdu_type,
                                 pf->sdu, pf->sdu_len, pf->ttl, pf->src_mip);
        
        // Restore original ARP entry if it existed
        if (dest_entry_idx >= 0) {
            if (had_dest_arp) {
                ifs->arp.entries[dest_entry_idx].mip_addr = pf->dest_mip;
                memcpy(ifs->arp.entries[dest_entry_idx].mac_addr, old_mac, 6);
                ifs->arp.entries[dest_entry_idx].if_index = old_if;
                printf("[FORWARD] Restored original ARP entry for MIP %d\n", pf->dest_mip);
            } else {
                // Remove the temporary entry
                for (int j = dest_entry_idx; j < ifs->arp.entry_count - 1; j++) {
                    ifs->arp.entries[j] = ifs->arp.entries[j + 1];
                }
                ifs->arp.entry_count--;
                printf("[FORWARD] Removed temporary ARP entry for MIP %d\n", pf->dest_mip);
            }
        }
        
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