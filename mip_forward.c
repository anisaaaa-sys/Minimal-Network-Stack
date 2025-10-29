/**
 * mip_forward.c - MIP Packet Forwarding Engine
 * 
 * Implements the forwarding logic for MIP packets that need to be relayed
 * to non-directly-connected destinations. Coordinates with the routing daemon
 * to obtain next-hop information and manages a queue of packets awaiting
 * route resolution.
 * 
 * Key features:
 * - Sends route requests to routing daemon
 * - Processes route responses and forwards queued packets
 * - Handles ARP resolution for next hops
 * - Manages pending forward queue with retry logic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#include "mipd.h"

/**
 * Send route lookup request to routing daemon
 * ifs: Interface data (routing_daemon_fd used)
 * dest_mip: Destination MIP address to find route for
 * 
 * Constructs and sends a route request message to the routing daemon.
 * The request asks for the next hop to reach dest_mip.
 * 
 * Request format: [local_mip][ttl=0]['R']['E']['Q'][dest_mip]
 * 
 * Global variables: ifs->routing_daemon_fd (writes to socket)
 * Returns: Nothing
 * Error conditions: Routing daemon not connected (silent failure)
 */
void send_route_request(struct ifs_data *ifs, uint8_t dest_mip) {
    if (ifs->routing_daemon_fd < 0) {
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
    }
}

/* Handle route response from routing daemon */
/**
 * Handle route response from routing daemon and forward pending packets
 * ifs: Interface data (pending_forwards processed)
 * payload: Pointer to route response message
 * len: Length of response in bytes
 * 
 * Processes route response from routing daemon containing next hop information.
 * Finds all pending forwards for the destination, attempts to send them using
 * the provided next hop. If ARP cache miss occurs for next hop, sends ARP
 * request and keeps packet pending.
 * 
 * Response format: [dest_mip][next_hop_mip][metric]
 * 
 * Global variables: ifs->pending_forwards (processed and modified)
 *                   ifs->arp (reads for next hop lookup)
 * Returns: Nothing
 * Error conditions: Invalid response format, ARP cache miss (packet re-queued)
 */
void handle_route_response(struct ifs_data *ifs, const uint8_t *payload, size_t len) {
    // RESPONSE format: ['R']['S']['P'][next_hop_mip]
    if (len < 4) {
        fprintf(stderr, "[FORWARD] Route response too short (%zu bytes)\n", len);
        return;
    }

    if (payload[0] != 0x52 || payload[1] != 0x53 || payload[2] != 0x50) {
        fprintf(stderr, "[FORWARD] Invalid route response format\n");
        return;
    }

    uint8_t next_hop = payload[3];

    // Process all pending forwards
    for (int i = 0; i < ifs->pending_forward_count; i++) {
        struct pending_forward *pf = &ifs->pending_forwards[i];
        if (!pf->active) continue;

        if (next_hop == 255) {
            // No route found - drop packet
            pf->active = 0;
            continue;
        }

        //Look up next hop in ARP cache
        uint8_t next_hop_mac[6];
        int send_if = -1;
        int arp_found = arp_cache_lookup(ifs->arp.entries, ifs->arp.entry_count,
                                         next_hop, next_hop_mac, &send_if);
        
        if (arp_found != 0) {
            // Next hop not in ARP cache, send ARP request
            for (int j = 0; j < ifs->ifn; j++) {
                send_arp_request(ifs, j, next_hop);
            }
            // Keep packet pending
            continue;
        }

        // When forwarding, temporarily override ARP cache so dest_mip uses next_hop's MAC
        // Save any existing ARP entry for dest_mip
        uint8_t old_mac[6];
        int old_if = -1;
        int had_dest_arp = (arp_cache_lookup(ifs->arp.entries, ifs->arp.entry_count,
                                             pf->dest_mip, old_mac, &old_if) == 0);
        
        // Find or create ARP entry for dest_mip to temporarily override with next_hop's MAC
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
        }

        // Send the packet - now send_mip_packet will find dest_mip with next_hop's MAC
        // IMPORTANT: Pass pf->src_mip to preserve the original source address when forwarding
        printf("\n[FORWARD] MIP %d -> %d via next-hop %d (TTL=%d)\n",
               pf->src_mip, pf->dest_mip, next_hop, pf->ttl);
        printf("[FORWARD] Payload: \"%.*s\"\n", (int)pf->sdu_len, pf->sdu);
        
        int rc = send_mip_packet(ifs, send_if, pf->dest_mip, pf->sdu_type,
                                 pf->sdu, pf->sdu_len, pf->ttl, pf->src_mip);
        
        // Restore original ARP entry if it existed
        if (dest_entry_idx >= 0) {
            if (had_dest_arp) {
                ifs->arp.entries[dest_entry_idx].mip_addr = pf->dest_mip;
                memcpy(ifs->arp.entries[dest_entry_idx].mac_addr, old_mac, 6);
                ifs->arp.entries[dest_entry_idx].if_index = old_if;
            } else {
                // Remove the temporary entry
                for (int j = dest_entry_idx; j < ifs->arp.entry_count - 1; j++) {
                    ifs->arp.entries[j] = ifs->arp.entries[j + 1];
                }
                ifs->arp.entry_count--;
            }
        }
        
        if (rc < 0) {
            fprintf(stderr, "[FORWARD] Failed to forward packet to MIP %d\n", pf->dest_mip);
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
/**
 * Queue packet for forwarding and request route from routing daemon
 * ifs: Interface data (pending_forwards queue will be updated)
 * dest_mip: Final destination MIP address
 * src_mip: Original source MIP address
 * ttl: Current Time-To-Live value
 * sdu_type: Type of SDU (protocol identifier)
 * sdu: Pointer to SDU payload
 * sdu_len: Length of SDU in bytes
 * 
 * Adds packet to pending_forwards queue and immediately sends a route
 * request to the routing daemon. The packet will be sent once a route
 * response is received in handle_route_response().
 * 
 * Global variables: ifs->pending_forwards, ifs->pending_forward_count (modified)
 *                   ifs->routing_daemon_fd (sends route request)
 * Returns: Nothing
 * Error conditions: Queue full (packet dropped with error message)
 */
void forward_mip_packet(struct ifs_data *ifs, uint8_t dest_mip, uint8_t src_mip,
                        uint8_t ttl, uint8_t sdu_type, const uint8_t *sdu,
                        size_t sdu_len) {
    // Check and decrement TTL
    if (ttl == 0 || ttl == 1) {
        // TTL expired - drop packet
        return;
    }
    ttl--;

    // Check if we already have a pending forward for this destination
    int found_pending = 0;
    for (int i = 0; i < ifs->pending_forward_count; i++) {
        if (ifs->pending_forwards[i].active &&
            ifs->pending_forwards[i].dest_mip == dest_mip) {
            found_pending = 1;
            break;
        }
    }

    // ALWAYS add to pending forwards (even if we already have one for this dest)
    // This ensures ALL packets get forwarded, not just the first one
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

        // Send route request only if not already pending for this destination
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