#include <string.h>    /* memcpy */
#include <stdlib.h>    /* calloc, free */
#include <stdio.h>     /* printf, perror */
#include <unistd.h>    /* close */
#include <arpa/inet.h> /* htons */
#include <time.h>


#include "mipd.h" 

int send_arp_request(struct ifs_data *ifs, int if_index, uint8_t target_mip) {
    struct ether_frame frame_hdr;
    struct mip_header mip_hdr;
    uint8_t arp_sdu[2];
    struct msghdr *msg;
    struct iovec msgvec[3];
    ssize_t rc;

    printf("[ARP] Sending ARP request for MIP %d on interface %d\n", target_mip, if_index);

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
    printf("[ARP] Preparing ARP request: src_mip=%d target_mip=%d if=%d\n",
           ifs->local_mip_addr, target_mip, if_index);
    rc = sendmsg(ifs->rsock[if_index], msg, 0);
    if (rc == -1) {
        perror("sendmsg ARP request");
        free(msg);
        return -1;
    } else printf("[ARP] sendmsg rc=%zd bytes sent on rsock[%d]=%d\n",
            rc, if_index, ifs->rsock[if_index]);

    printf("[ARP] Sent ARP request (%ld bytes) on interface %d\n", rc, if_index);

    /* Free the allocated message struct */
    free(msg);
    return rc;
}

int send_arp_response(struct ifs_data *ifs, int if_index, uint8_t requester_mip, 
                      uint8_t requester_mac[6]) {
    struct ether_frame frame_hdr;
    struct mip_header mip_hdr;
    uint8_t arp_sdu[2];
    struct msghdr *msg;
    struct iovec msgvec[3];
    int rc;

    printf("[ARP] Sending ARP response to MIP %d: I am MIP %d\n", 
           requester_mip, ifs->local_mip_addr);

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

    printf("[ARP] Sent ARP response (%d bytes) to ", rc);
    print_mac_addr(requester_mac, 6);
    printf("\n");

    /* Free the allocated message struct */
    free(msg);

    return rc;
}

int handle_arp_packet(struct ifs_data *ifs, const uint8_t *sdu, 
                      size_t sdu_len, uint8_t src_mip, 
                      const uint8_t *src_mac, int if_index) {
    if (sdu_len < 2) {
        fprintf(stderr, "[ARP] ARP SDU too short (%zu bytes)\n", sdu_len);
        return -1;
    }
    
    uint8_t arp_type = sdu[0];      /* Request or Response */
    uint8_t mip_addr = sdu[1];      /* The MIP address in question */
    
    printf("[ARP] Received packet: type=0x%02x, mip_addr=%d, from MIP %d (MAC ", 
           arp_type, mip_addr, src_mip);
    print_mac_addr((uint8_t*)src_mac, 6);
    printf(") on interface %d\n", if_index);
    
    if (arp_type == ARP_TYPE_REQ) {
        /* ARP Request: "Who has mip_addr?" */
        printf("[ARP] ARP REQUEST: Who has MIP %d? (asked by MIP %d)\n", 
               mip_addr, src_mip);
        
        if (mip_addr == ifs->local_mip_addr) {
            /* Request is for us - send response */
            printf("[ARP] Request is for us! Sending response back\n");
            
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
                    printf("[ARP] Cache UPDATED for MIP %d on IF %d\n", target_mip, if_index);
                    break;
                }
            }
            
            if (!found && ifs->arp.entry_count < ARP_CACHE_SIZE) {
                struct arp_entry *entry = &ifs->arp.entries[ifs->arp.entry_count++];
                entry->mip_addr = target_mip;
                entry->if_index = if_index;
                memcpy(entry->mac_addr, target_mac, 6);
                printf("[ARP] Cache ADDED: MIP %d on IF %d (total: %d)\n", 
                       target_mip, if_index, ifs->arp.entry_count);
            } else if (!found) {
                printf("[ARP] WARNING: ARP cache full, cannot add entry for MIP %d\n", target_mip);
            }

            /* Copy MAC address to avoid const issues */
            uint8_t requester_mac[6];
            memcpy(requester_mac, src_mac, 6);
            return send_arp_response(ifs, if_index, src_mip, requester_mac);
        } else {
            printf("[ARP] Request not for us (we are MIP %d), ignoring\n", 
                   ifs->local_mip_addr);
        }
    } else if (arp_type == ARP_TYPE_RESP) {
        /* ARP Response: "I (mip_addr) am at this MAC address" */
        printf("[ARP] ARP RESPONSE: MIP %d is at MAC ", mip_addr);
        print_mac_addr((uint8_t*)src_mac, 6);
        printf(" on interface %d\n", if_index);
        
        if (mip_addr == src_mip) {
            /* Add to/update ARP cache */
            int found = 0;
            for (int i = 0; i < ifs->arp.entry_count; i++) {
                if (ifs->arp.entries[i].mip_addr == mip_addr) {
                    /* Update existing entry */
                    memcpy(ifs->arp.entries[i].mac_addr, src_mac, 6);
                    ifs->arp.entries[i].if_index = if_index;
                    found = 1;
                    printf("[ARP] Updated existing cache entry for MIP %d\n", mip_addr);
                    break;
                }
            }
            
            if (!found && ifs->arp.entry_count < ARP_CACHE_SIZE) {
                struct arp_entry *entry = &ifs->arp.entries[ifs->arp.entry_count++];
                entry->mip_addr = mip_addr;
                entry->if_index = if_index;
                memcpy(entry->mac_addr, src_mac, 6);
                printf("[ARP] Added new cache entry: MIP %d -> MAC ", mip_addr);
                print_mac_addr(entry->mac_addr, 6);
                printf(" on interface %d (total: %d)\n", if_index, ifs->arp.entry_count);
            } else if (!found) {
                printf("[ARP] WARNING: ARP cache full, cannot add entry for MIP %d\n", 
                       mip_addr);
            }

            /* Immediately flush any pending messages that were waiting on this ARP.
               We send them *now* using the interface the ARP RESP arrived on (per spec step 6). */
            printf("[ARP] Checking for pending pings waiting for MIP %d\n", mip_addr);
            for (int i = 0; i < ifs->pending_ping_count; i++) {
                struct pending_ping *pending = &ifs->pending_pings[i];

                /* Only flush entries that actually waited for ARP for this dest. */
                if (pending->waiting_for_arp && pending->dest_mip == mip_addr) {
                    printf("[ARP] Found pending ping for MIP %d (fd=%d), sending now!\n", 
                           mip_addr, pending->client_fd);
                    pending->waiting_for_arp = 0;

                    /* No manual padding here. Let send_mip_packet() do padding.
                       This avoids double-padding and keeps wire-format single-sourced. */
                    int rc = send_mip_packet(ifs, if_index, mip_addr, 
                                             SDU_TYPE_PING, pending->sdu, pending->sdu_len, pending->ttl, 0);
                    printf("[ARP] send_mip_packet (flush pending) rc=%d\n", rc);
                    
                    if (rc >= 0) {
                        if (pending->client_fd < 0) {
                            for (int j = i; j < ifs->pending_ping_count - 1; j++)
                                ifs->pending_ping_count--;
                            i--;
                        } else {
                            printf("[ARP] Successfully sent pending ping to MIP %d\n", mip_addr);
                            pending->waiting_for_arp = 0;
                        }
                    } else {
                        fprintf(stderr, "[ARP] ERROR: Failed to send pending ping to MIP %d\n", mip_addr);
                        pending->waiting_for_arp = 1;
                    }
                }
            }
        } else {
            printf("[ARP] WARNING: ARP response mismatch - mip_addr=%d but src_mip=%d\n",
                   mip_addr, src_mip);
        }
    } else {
        fprintf(stderr, "[ARP] Unknown ARP type: 0x%02x\n", arp_type);
        return -1;
    }
    
    return 0;
}

/* Lookup MAC from ARP cache */
int arp_cache_lookup(struct arp_entry *entries, int count,  
                uint8_t mip, uint8_t mac[6], int *if_index) {
    for (int i = 0; i < count; i++) {
        if (entries[i].mip_addr == mip) {
            memcpy(mac, entries[i].mac_addr, 6);
            *if_index = entries[i].if_index;
            printf("[ARP] Cache HIT for MIP %d: MAC ", mip);
            print_mac_addr(entries[i].mac_addr, 6);
            printf(" on interface %d\n", *if_index);
            return 0;
        }
    }
    printf("[ARP] Cache MISS for MIP %d\n", mip);
    return -1; // Not found
}