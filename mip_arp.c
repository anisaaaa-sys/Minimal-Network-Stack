/**
 * mip_arp.c - ARP (Address Resolution Protocol) Implementation for MIP
 * 
 * Handles ARP request/response messages to resolve MIP addresses to MAC addresses.
 * Maintains an ARP cache and automatically triggers pending packet transmission
 * when ARP entries are learned.
 */

#include <string.h>    /* memcpy */
#include <stdlib.h>    /* calloc, free */
#include <stdio.h>     /* printf, perror */
#include <unistd.h>    /* close */
#include <arpa/inet.h> /* htons */
#include <time.h>

#include "mipd.h" 

/**
 * Send ARP request for a given MIP address
 * ifs: Interface data containing socket and address information
 * if_index: Interface index to send request on
 * target_mip: MIP address to resolve
 * 
 * Constructs an ARP request packet with broadcast destination and sends
 * it on the specified interface. The request asks "who has target_mip?"
 * 
 * ARP SDU format: [ARP_TYPE_REQ (1 byte)][target_mip (1 byte)]
 * 
 * Global variables: ifs->rsock, ifs->addr (reads)
 * Returns: Number of bytes sent on success, -1 on error
 * Error conditions: Memory allocation failure, sendmsg failure
 */
int send_arp_request(struct ifs_data *ifs, int if_index, uint8_t target_mip) {
    struct ether_frame frame_hdr;
    struct mip_header mip_hdr;
    uint8_t arp_sdu[2];
    struct msghdr *msg;
    struct iovec msgvec[3];
    ssize_t rc;

    /* ARP SDU format: [ARP_TYPE][MIP_ADDRESS] */
    arp_sdu[0] = ARP_TYPE_REQ;  /* This is a REQUEST */
    arp_sdu[1] = target_mip;         /* Looking for this MIP address */

    /* Fill in Ethernet header - BROADCAST */
    uint8_t dst_addr[] = ETH_BROADCAST;
    memcpy(frame_hdr.dst_addr, dst_addr, 6);
    memcpy(frame_hdr.src_addr, ifs->addr[if_index].sll_addr, 6);
    frame_hdr.eth_proto = htons(ETH_P_MIP);

    /* Fill in MIP header */
    memset(&mip_hdr, 0, sizeof(mip_hdr));
    mip_hdr.dest = 0xFF;  /* Broadcast destination */
    mip_hdr.src = ifs->local_mip_addr;
    
    /* SDU length in 32-bit words: 2 bytes = 1 word (rounded up) */
    size_t sdu_len_words = 1;  /* (2 + 3) / 4 = 1 */
    mip_hdr.ttl_sdu = htons(MIP_MAKE_TTL_SDU(15, sdu_len_words, SDU_TYPE_ARP));

    /* Pad ARP SDU to 4 bytes (32-bit word boundary) */
    uint8_t padded_arp_sdu[4] = {0};
    memcpy(padded_arp_sdu, arp_sdu, 2);

    /* Allocate a zeroed-out message info struct */
    msg = (struct msghdr *)calloc(1, sizeof(struct msghdr));
    if (!msg) {
        perror("calloc");
        return -1;
    }

    /* Point to frame header, MIP header, and ARP SDU */
    msgvec[0].iov_base = &frame_hdr;
    msgvec[0].iov_len  = sizeof(struct ether_frame);
    msgvec[1].iov_base = &mip_hdr;
    msgvec[1].iov_len  = sizeof(struct mip_header);
    msgvec[2].iov_base = padded_arp_sdu;
    msgvec[2].iov_len  = 4;

    /* Fill out message metadata struct */
    msg->msg_name    = &(ifs->addr[if_index]);
    msg->msg_namelen = sizeof(struct sockaddr_ll);
    msg->msg_iovlen  = 3;
    msg->msg_iov     = msgvec;

    /* Send message via RAW socket */
    rc = sendmsg(ifs->rsock[if_index], msg, 0);
    if (rc == -1) {
        perror("sendmsg ARP request");
        free(msg);
        return -1;
    }
    
    printf("[ARP] Requesting MAC for MIP %d\n", target_mip);

    /* Free the allocated message struct */
    free(msg);
    return rc;
}

/**
 * Send ARP response to a requester
 * ifs: Interface data containing local MIP and MAC information
 * if_index: Interface index to send response on
 * requester_mip: MIP address of the node that sent the request
 * requester_mac: MAC address of the requester (destination for unicast)
 * 
 * Constructs an ARP response packet containing this node's MIP-to-MAC mapping
 * and sends it directly to the requester (unicast).
 * 
 * ARP SDU format: [ARP_TYPE_RESP (1 byte)][local_mip (1 byte)]
 * 
 * Global variables: ifs->rsock, ifs->addr, ifs->local_mip_addr (reads)
 * Returns: Number of bytes sent on success, -1 on error
 * Error conditions: Memory allocation failure, sendmsg failure
 */
int send_arp_response(struct ifs_data *ifs, int if_index, uint8_t requester_mip, 
                      uint8_t requester_mac[6]) {
    struct ether_frame frame_hdr;
    struct mip_header mip_hdr;
    uint8_t arp_sdu[2];
    struct msghdr *msg;
    struct iovec msgvec[3];
    int rc;

    /* ARP SDU format: [ARP_TYPE][MIP_ADDRESS] */
    arp_sdu[0] = ARP_TYPE_RESP;      /* This is a RESPONSE */
    arp_sdu[1] = ifs->local_mip_addr;    /* This is MY MIP address */

    /* Fill in Ethernet header - UNICAST to requester */
    memcpy(frame_hdr.dst_addr, requester_mac, 6);
    memcpy(frame_hdr.src_addr, ifs->addr[if_index].sll_addr, 6);
    frame_hdr.eth_proto = htons(ETH_P_MIP);

    /* Fill in MIP header */
    memset(&mip_hdr, 0, sizeof(mip_hdr));
    mip_hdr.dest = requester_mip;  /* Unicast to requester */
    mip_hdr.src = ifs->local_mip_addr;
    
    /* SDU length in 32-bit words: 2 bytes = 1 word (rounded up) */
    size_t sdu_len_words = 1;
    mip_hdr.ttl_sdu = htons(MIP_MAKE_TTL_SDU(15, sdu_len_words, SDU_TYPE_ARP));

    /* Pad ARP SDU to 4 bytes */
    uint8_t padded_arp_sdu[4] = {0};
    memcpy(padded_arp_sdu, arp_sdu, 2);

    /* Allocate a zeroed-out message info struct */
    msg = (struct msghdr *)calloc(1, sizeof(struct msghdr));
    if (!msg) {
        perror("calloc");
        return -1;
    }

    /* Point to frame header, MIP header, and ARP SDU */
    msgvec[0].iov_base = &frame_hdr;
    msgvec[0].iov_len  = sizeof(struct ether_frame);
    msgvec[1].iov_base = &mip_hdr;
    msgvec[1].iov_len  = sizeof(struct mip_header);
    msgvec[2].iov_base = padded_arp_sdu;
    msgvec[2].iov_len  = 4;

    /* Fill out message metadata struct */
    msg->msg_name    = &(ifs->addr[if_index]);
    msg->msg_namelen = sizeof(struct sockaddr_ll);
    msg->msg_iovlen  = 3;
    msg->msg_iov     = msgvec;

    /* Send message via RAW socket */
    rc = sendmsg(ifs->rsock[if_index], msg, 0);
    if (rc == -1) {
        perror("sendmsg ARP response");
        free(msg);
        return -1;
    }

    /* Free the allocated message struct */
    free(msg);

    return rc;
}

/**
 * Handle received ARP packet (request or response)
 * ifs: Interface data (ARP cache will be updated)
 * sdu: Pointer to ARP packet payload
 * sdu_len: Length of ARP packet in bytes
 * src_mip: Source MIP address from MIP header
 * src_mac: Source MAC address from Ethernet frame
 * if_index: Interface on which packet was received
 * 
 * Processing logic:
 * 1. Learn source MAC-to-MIP mapping from any ARP packet
 * 2. If ARP REQUEST for us: send ARP RESPONSE
 * 3. If ARP RESPONSE: update cache and trigger pending packets
 * 
 * When ARP is resolved, this function:
 * - Sends route requests for pending forwards (to get next hop)
 * - Directly sends pending pings that were waiting for this ARP entry
 * 
 * Global variables: ifs->arp (ARP cache modified)
 *                   ifs->pending_forwards, ifs->pending_pings (processed)
 * Returns: 0 on success, -1 on error
 * Error conditions: Invalid ARP packet format
 */
int handle_arp_packet(struct ifs_data *ifs, const uint8_t *sdu, 
                      size_t sdu_len, uint8_t src_mip, 
                      const uint8_t *src_mac, int if_index) {
    if (sdu_len < 2) {
        fprintf(stderr, "[ARP] ARP SDU too short (%zu bytes)\n", sdu_len);
        return -1;
    }
    
    uint8_t arp_type = sdu[0];      /* Request or Response */
    uint8_t mip_addr = sdu[1];      /* The MIP address in question */
    
    if (arp_type == ARP_TYPE_REQ) {
        /* ARP Request: "Who has mip_addr?" */
        if (mip_addr == ifs->local_mip_addr) {
            /* Request is for us - send response */
            uint8_t target_mip = src_mip;
            const uint8_t *target_mac = src_mac; 
            int found = 0;

            /* Learn/refresh the requester (so we can unicast response fast) */
            for (int i = 0; i < ifs->arp.entry_count; i++) {
                if (ifs->arp.entries[i].mip_addr == target_mip) {
                    /* Update existing entry */
                    memcpy(ifs->arp.entries[i].mac_addr, target_mac, 6);
                    ifs->arp.entries[i].if_index = if_index;
                    found = 1;
                    break;
                }
            }
            
            if (!found && ifs->arp.entry_count < ARP_CACHE_SIZE) {
                struct arp_entry *entry = &ifs->arp.entries[ifs->arp.entry_count++];
                entry->mip_addr = target_mip;
                entry->if_index = if_index;
                memcpy(entry->mac_addr, target_mac, 6);
            }

            /* Copy MAC address to avoid const issues */
            uint8_t requester_mac[6];
            memcpy(requester_mac, src_mac, 6);
            return send_arp_response(ifs, if_index, src_mip, requester_mac);
        }
    } else if (arp_type == ARP_TYPE_RESP) {
        /* ARP Response: "I (mip_addr) am at this MAC address" */
        if (mip_addr == src_mip) {
            /* Add to/update ARP cache */
            int found = 0;
            for (int i = 0; i < ifs->arp.entry_count; i++) {
                if (ifs->arp.entries[i].mip_addr == mip_addr) {
                    /* Update existing entry */
                memcpy(ifs->arp.entries[i].mac_addr, src_mac, 6);
                ifs->arp.entries[i].if_index = if_index;
                found = 1;
                break;
                }
            }
            
            if (!found && ifs->arp.entry_count < ARP_CACHE_SIZE) {
                struct arp_entry *entry = &ifs->arp.entries[ifs->arp.entry_count++];
                entry->mip_addr = mip_addr;
                entry->if_index = if_index;
                memcpy(entry->mac_addr, src_mac, 6);
                printf("[ARP] Learned MIP %d -> MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                       mip_addr, src_mac[0], src_mac[1], src_mac[2],
                       src_mac[3], src_mac[4], src_mac[5]);
            }

            // Flush pending messages and forwards waiting for this ARP 
            for (int fwd_idx = 0; fwd_idx < ifs->pending_forward_count; fwd_idx++) {
                struct pending_forward *pf = &ifs->pending_forwards[fwd_idx];
                if (!pf->active) continue;
                // Send route request to trigger forward retry
                send_route_request(ifs, pf->dest_mip);
            }
            
            for (int i = 0; i < ifs->pending_ping_count; i++) {
                struct pending_ping *pending = &ifs->pending_pings[i];

                if (pending->waiting_for_arp && pending->dest_mip == mip_addr) {
                    pending->waiting_for_arp = 0;

                    int rc = send_mip_packet(ifs, if_index, mip_addr, 
                                             SDU_TYPE_PING, pending->sdu, pending->sdu_len, pending->ttl, 0);
                    
                    if (rc >= 0) {
                        if (pending->client_fd < 0) {
                            for (int j = i; j < ifs->pending_ping_count - 1; j++)
                                ifs->pending_ping_count--;
                            i--;
                        } else {
                            pending->waiting_for_arp = 0;
                        }
                    } else {
                        fprintf(stderr, "[ARP] ERROR: Failed to send pending ping to MIP %d\n", mip_addr);
                        pending->waiting_for_arp = 1;
                    }
                }
            }
        }
    } else {
        fprintf(stderr, "[ARP] Unknown ARP type: 0x%02x\n", arp_type);
        return -1;
    }
    
    return 0;
}

/* Lookup MAC from ARP cache */
/**
 * Look up MIP address in ARP cache
 * entries: Array of ARP cache entries
 * count: Number of entries in cache
 * mip: MIP address to look up
 * mac: Output buffer for MAC address (6 bytes) - must be allocated by caller
 * if_index: Output pointer for interface index
 * 
 * Searches ARP cache linearly for the specified MIP address.
 * If found, copies MAC address to output buffer and sets interface index.
 * 
 * Global variables: None (operates on provided array)
 * Returns: 0 if found, -1 if not found
 */
int arp_cache_lookup(struct arp_entry *entries, int count,  
                     uint8_t mip, uint8_t mac[6], int *if_index) {
    for (int i = 0; i < count; i++) {
        if (entries[i].mip_addr == mip) {
            memcpy(mac, entries[i].mac_addr, 6);
            *if_index = entries[i].if_index;
            return 0;
        }
    }
    return -1; // Not found
}