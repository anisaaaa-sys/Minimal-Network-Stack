/**
 * mip_network.c - MIP Network Layer Packet Handling
 * 
 * Implements core MIP protocol functions including:
 * - Sending MIP packets with proper header construction
 * - Receiving and parsing MIP packets
 * - Automatic ARP learning from received packets
 * - TTL management and forwarding decisions
 * - Dispatching packets to appropriate handlers (ARP, routing, applications)
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <fcntl.h>
#include "mipd.h" 

/**
 * Send MIP packet with specified parameters
 * ifs: Interface data containing sockets and ARP cache
 * if_index: Interface index to send packet on (or -1 for broadcast on all interfaces)
 * dst_mip: Destination MIP address (0xFF for broadcast)
 * sdu_type: Type of SDU (SDU_TYPE_PING, SDU_TYPE_ROUTING, etc.)
 * sdu: Pointer to SDU payload
 * sdu_len_bytes: Length of SDU in bytes
 * ttl: Time-To-Live value (0 = use DEFAULT_TTL)
 * src_mip: Source MIP address (0 = use local MIP address)
 * 
 * This function:
 * 1. Validates parameters
 * 2. Looks up destination MAC in ARP cache (unless broadcast)
 * 3. Constructs Ethernet frame and MIP header
 * 4. Sends packet via RAW socket
 * 
 * For broadcast (dst_mip == 0xFF or if_index == -1), sends on all interfaces.
 * For unicast, requires ARP cache hit and sends on specified interface.
 * 
 * Global variables: ifs->arp (reads ARP cache)
 *                   ifs->rsock, ifs->addr (for sending)
 * Returns: 0 on success, -1 on error
 * Error conditions: Invalid parameters, ARP cache miss, sendmsg failure,
 *                   network interface down (ENETDOWN)
 */
int send_mip_packet(struct ifs_data *ifs, int if_index,
                uint8_t dst_mip, uint8_t sdu_type, 
                const uint8_t *sdu, size_t sdu_len_bytes, uint8_t ttl, uint8_t src_mip) {
    if (!ifs) return -1;
    if (sdu == NULL && sdu_len_bytes != 0) return -1;
    if (ifs->ifn <= 0) {
        fprintf(stderr, "send_mip_packet: no interfaces available\n");
        return -1;
    }

    if (ttl == 0) {
        ttl = DEFAULT_TTL;
    }
    
    if (src_mip == 0) {
        src_mip = ifs->local_mip_addr;
    }

    if (dst_mip == MIP_DEST_ADDR) {

        uint8_t bmac[6] = ETH_BROADCAST;

        struct ether_frame frame_hdr;
        struct mip_header mip_hdr;
        memset(&frame_hdr, 0, sizeof(frame_hdr));
        memset(&mip_hdr, 0, sizeof(mip_hdr));

        size_t sdu_len_words = (sdu_len_bytes + 3) / 4;
        if (sdu_len_words > MIP_SDU_LEN_MASK) sdu_len_words = MIP_SDU_LEN_MASK;
        size_t padded_len = sdu_len_words * 4;

        uint8_t *padded = NULL;
        if (padded_len > sdu_len_bytes) {
            padded = malloc(padded_len);
            if (!padded) return -1;
            memcpy(padded, sdu, sdu_len_bytes);
            memset(padded + sdu_len_bytes, 0, padded_len - sdu_len_bytes);
        }

        struct iovec msgvec[3];
        struct msghdr msg = {0};
        msgvec[0].iov_base = &frame_hdr;
        msgvec[0].iov_len = sizeof(frame_hdr);
        msgvec[1].iov_base = &mip_hdr;
        msgvec[1].iov_len = sizeof(mip_hdr);
        msgvec[2].iov_base = padded ? padded : (void*)sdu;
        msgvec[2].iov_len = padded ? padded_len : sdu_len_bytes;
        msg.msg_iov = msgvec;
        msg.msg_iovlen = 3;

        for (int i = 0; i < ifs->ifn; i++) {
            memcpy(frame_hdr.dst_addr, bmac, 6);
            memcpy(frame_hdr.src_addr, ifs->macs[i], 6);
            frame_hdr.eth_proto = htons(ETH_P_MIP);

            mip_hdr.dest = MIP_DEST_ADDR;
            mip_hdr.src = src_mip;
            mip_hdr.ttl_sdu = htons(MIP_MAKE_TTL_SDU(ttl, sdu_len_words, sdu_type));

            msg.msg_name = &(ifs->addr[i]);
            msg.msg_namelen = sizeof(struct sockaddr_ll);

            ssize_t rc = sendmsg(ifs->rsock[i], &msg, 0);
            if (rc < 0) {
                perror("[MIPD] broadcast sendmsg failed");
            }
        }

        if (padded) free(padded);
        return 0;
    }

    /* Try to find MAC + if_index from ARP cache */
    uint8_t dst_mac[6];
    int arp_if_index = -1;
    int have_arp = (arp_cache_lookup(ifs->arp.entries, ifs->arp.entry_count,
                    dst_mip, dst_mac, &arp_if_index) == 0);

    int chosen_if = ((have_arp && arp_if_index >= 0) ? arp_if_index : if_index);
    if (chosen_if < 0 || chosen_if >= ifs->ifn) chosen_if = 0;

    /* If ARP miss, don't send, wait for ARP */
    if (!have_arp) {
        send_arp_request(ifs, if_index, dst_mip);
        return -1;
    }

    /* Prepare headers */
    struct ether_frame frame_hdr;
    struct mip_header mip_hdr;
    memset(&frame_hdr, 0, sizeof(frame_hdr));
    memset(&mip_hdr, 0, sizeof(mip_hdr));

    /* Fill in Ethernet header */
    memcpy(frame_hdr.dst_addr, dst_mac, 6);
    memcpy(frame_hdr.src_addr, ifs->macs[chosen_if], 6);
    frame_hdr.eth_proto = htons(ETH_P_MIP);

    /* Fill in MIP header */
    mip_hdr.dest = dst_mip;
    mip_hdr.src = src_mip;
    size_t sdu_len_words = (sdu_len_bytes + 3) / 4;
    if (sdu_len_words > MIP_SDU_LEN_MASK) sdu_len_words = MIP_SDU_LEN_MASK;
    mip_hdr.ttl_sdu = htons(MIP_MAKE_TTL_SDU(ttl, sdu_len_words, sdu_type)); 

    /* Build iovec: frame header, mip header, payload */
    struct iovec msgvec[3];
    msgvec[0].iov_base = &frame_hdr;
    msgvec[0].iov_len = sizeof(frame_hdr);
    msgvec[1].iov_base = &mip_hdr;
    msgvec[1].iov_len = sizeof(mip_hdr);

    /* Pad SDU to 32-bit word boundary */
    size_t padded_len = sdu_len_words * 4;
    uint8_t *padded = NULL;
    if (padded_len > sdu_len_bytes) {
        padded = malloc(padded_len);
        if (!padded) return -1;
        memcpy(padded, sdu, sdu_len_bytes);
        memset(padded + sdu_len_bytes, 0, padded_len - sdu_len_bytes);
        msgvec[2].iov_base = padded;
        msgvec[2].iov_len = padded_len;
    } else {
        msgvec[2].iov_base = (void*)sdu;
        msgvec[2].iov_len = sdu_len_bytes;
    }
    
    /* Fill out message metadata struct */
    struct msghdr msg = {0};
    msg.msg_name = &(ifs->addr[chosen_if]);
    msg.msg_namelen = sizeof(struct sockaddr_ll);
    msg.msg_iov = msgvec;
    msg.msg_iovlen = 3;

    if (ifs->rsock[chosen_if] <= 0) {
        fprintf(stderr, "send_mip_packet: invalid rsock for if %d\n", chosen_if);
        if (padded) free(padded);
        return -1;
    }

    ssize_t rc = sendmsg(ifs->rsock[chosen_if], &msg, 0);
    if (rc < 0) {
        perror("sendmsg");
        if (padded) free(padded);
        return -1;
    }
    if (padded) free(padded);
    return (int)rc;
}

/**
 * Handle received MIP packet
 * ifs: Interface data (for forwarding, ARP learning, and delivery)
 * packet: Pointer to raw Ethernet frame (including Ethernet header)
 * len: Total length of frame in bytes
 * if_index: Interface on which packet was received
 * 
 * This function performs complete MIP packet processing:
 * 1. Parses Ethernet frame and MIP header
 * 2. Validates packet structure and unpacks MIP header fields
 * 3. Automatically learns source MAC-to-MIP mapping (ARP learning)
 * 4. Checks if packet is for this node or needs forwarding
 * 5. For packets destined here:
 *    - ARP packets: forward to handle_arp_packet()
 *    - Routing packets: forward to routing daemon
 *    - PING packets: deliver to ping server or cache PONG for client
 * 6. For packets to forward:
 *    - Decrement TTL (drop if TTL reaches 0)
 *    - Queue for forwarding via routing daemon
 * 
 * Global variables: ifs->arp (ARP cache updated automatically)
 *                   ifs->routing_daemon_fd (for routing packets)
 *                   ifs->upper_layers (for application delivery)
 *                   ifs->pending_forwards (for forwarding)
 * Returns: 0 on success, -1 on error
 * Error conditions: Malformed packet, TTL expired
 */
int handle_mip_packet(struct ifs_data *ifs, const uint8_t *packet, 
                size_t len, int if_index) {
    
    if (!ifs || !packet) return -1;

    /* Must contain at least an Ethernet header + MIP header */
    if (len < sizeof(struct ether_frame) + sizeof(struct mip_header)) {
        fprintf(stderr, "handle_mip_packet: packet too short (%zu bytes)\n", len);
        return -1;
    }

    const struct ether_frame *frame_hdr = (const struct ether_frame*)packet;
    const struct mip_header *mip_hdr = (const struct mip_header*)frame_hdr->contents;
    const uint8_t *sdu = (const uint8_t*)(mip_hdr + 1);

    /* Extract MIP header fields */
    uint16_t host_ttl_sdu = ntohs(mip_hdr->ttl_sdu);
    uint8_t ttl = MIP_EXTRACT_TTL(host_ttl_sdu);
    uint8_t sdu_type = MIP_EXTRACT_SDU_TYPE(host_ttl_sdu);
    uint16_t sdu_len_words = MIP_EXTRACT_SDU_LEN(host_ttl_sdu);
    size_t sdu_len_bytes = (size_t)sdu_len_words * 4;


    /* Learn source MAC→MIP mapping from any received packet (automatic ARP learning) */
    if (mip_hdr->src != ifs->local_mip_addr) {
        int found = 0;
        for (int i = 0; i < ifs->arp.entry_count; i++) {
            if (ifs->arp.entries[i].mip_addr == mip_hdr->src) {
                memcpy(ifs->arp.entries[i].mac_addr, frame_hdr->src_addr, 6);
                ifs->arp.entries[i].if_index = if_index;
                found = 1;
                break;
            }
        }
        if (!found && ifs->arp.entry_count < ARP_CACHE_SIZE) {
            ifs->arp.entries[ifs->arp.entry_count].mip_addr = mip_hdr->src;
            memcpy(ifs->arp.entries[ifs->arp.entry_count].mac_addr, frame_hdr->src_addr, 6);
            ifs->arp.entries[ifs->arp.entry_count].if_index = if_index;
            ifs->arp.entry_count++;
        }
    }

    /* Verify we have enough bytes */
    size_t avail_sdu_bytes = len - (sizeof(struct ether_frame) + sizeof(struct mip_header));
    if (sdu_len_bytes > avail_sdu_bytes) {
        sdu_len_bytes = avail_sdu_bytes;
    }

    /* Handle MIP-ARP packets */
    if (sdu_type == SDU_TYPE_ARP) {
        return handle_arp_packet(ifs, sdu, sdu_len_bytes, mip_hdr->src, 
                                 frame_hdr->src_addr, if_index);
    }

    /* Check if packet is for us (or broadcast) */
    if (mip_hdr->dest != ifs->local_mip_addr && mip_hdr->dest != 255) {
        // Forward packet to next hop
        forward_mip_packet(ifs, mip_hdr->dest, mip_hdr->src, ttl, sdu_type, sdu, sdu_len_bytes);
        return 0;
    }

    /* Handle ROUTING packets */
    if (sdu_type == SDU_TYPE_ROUTING) {
        if (ifs->routing_daemon_fd >= 0) {
            const char *msg_type = (sdu_len_bytes > 0 && sdu[0] == 0x01) ? "HELLO" : 
                                   (sdu_len_bytes > 0 && sdu[0] == 0x02) ? "UPDATE" : "ROUTING";
            printf("\n[MIPD] Received %s from MIP %d, forwarding to routing daemon\n", 
                   msg_type, mip_hdr->src);
            
            uint8_t buffer[MAX_SDU_SIZE];
            buffer[0] = mip_hdr->src;
            buffer[1] = ttl;

            size_t copy_len = (sdu_len_bytes < MAX_SDU_SIZE - 2) ?
                               sdu_len_bytes : (MAX_SDU_SIZE - 2);
            memcpy(buffer + 2, sdu, copy_len);

            ssize_t sent = send(ifs->routing_daemon_fd, buffer, copy_len + 2, 0);
            if (sent < 0) {
                perror("forward to routing daemon");
            }
        }
        return 0;
    }

    /* Handle PING/PONG packets */
    if (sdu_type == SDU_TYPE_PING) {
        /* Determine actual message length (stop at null terminator) */
        size_t actual_len = 0;
        for (size_t i = 0; i < sdu_len_bytes; i++) {
            if (sdu[i] == 0) break;
            actual_len++;
        }

        /* Check if it's a PONG or PING */
        int is_pong = (actual_len >= 5 && strncmp((char*)sdu, "PONG:", 5) == 0);
        
        if (is_pong) {
            /* PONG response - find waiting client */

            int target_fd = -1;
            int target_index = -1;
            
            size_t pong_msg_len = (actual_len >= 5) ? (actual_len - 5) : 0;
            const char *pong_msg = (const char*)sdu + 5;

            for (int i = 0; i < ifs->pending_ping_count; i++) {
                struct pending_ping *p = &ifs->pending_pings[i];

                if (p->client_fd < 0) continue;
                if (p->dest_mip != mip_hdr->src) continue;
                if (p->waiting_for_arp) continue;
                if (p->sdu_len < 5) continue;
                if (strncmp((char*)p->sdu, "PING:", 5) != 0) continue;

                const char *req_msg = (char*)p->sdu + 5;
                size_t req_len = p->sdu_len - 5;

                if (req_len == pong_msg_len && memcmp(req_msg, pong_msg, req_len) == 0) {
                    target_fd = p->client_fd;
                    target_index = i;
                    break;
                }
            }
             
            if (target_fd < 0) {
                return 0;
            }
 
            /* Send PONG to waiting client: [src_mip][ttl][pong_message] */
            uint8_t response[MAX_SDU_SIZE];
            response[0] = mip_hdr->src;
            response[1] = ttl;
            size_t to_copy = actual_len;
            if (to_copy > sizeof(response) - 2) to_copy = sizeof(response) - 2;
            memcpy(response + 2, sdu, to_copy);

            ssize_t written = write(target_fd, response, to_copy + 2);
            if (written < 0) {
                perror("write to client");
            } else {
                printf("\n[PONG] Delivered PONG to client from MIP %d\n", mip_hdr->src);
                printf("[PONG] Payload: \"%.*s\"\n", (int)to_copy, sdu);
            }
             
            /* Close client connection after delivering PONG */
            close(target_fd);  

            /* Remove from pending list */
            if (target_index >= 0) {
                for (int j = target_index; j < ifs->pending_ping_count - 1; j++)
                    ifs->pending_pings[j] = ifs->pending_pings[j + 1];
                ifs->pending_ping_count--;
            }
        } else {
            /* PING request - send to server */
            if (ifs->server_fd < 0) {
                return 0;
            }

            printf("\n[PING] Received PING from MIP %d, delivering to server\n", mip_hdr->src);
            printf("[PING] Payload: \"%.*s\"\n", (int)actual_len, sdu);

            /* Send to server: [src_mip][ttl][ping_message] */
            uint8_t response[MAX_SDU_SIZE];
            response[0] = mip_hdr->src;
            response[1] = ttl;
            size_t to_copy = actual_len;
            if (to_copy > sizeof(response) - 2) to_copy = sizeof(response) - 2;
            memcpy(response + 2, sdu, to_copy);

            ssize_t written = write(ifs->server_fd, response, to_copy + 2);
            if (written < 0) {
                perror("write to server");
                close(ifs->server_fd);
                ifs->server_fd = -1;
            }
        }
    }

    return 0;
}