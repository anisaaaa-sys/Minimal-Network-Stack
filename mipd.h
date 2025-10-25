#ifndef MIPD_H
#define MIPD_H

#include <stdint.h>				/* uint8_t, uint16_t */
#include <stddef.h>				/* size_t */
#include <unistd.h> 			/* POSIX APIs (close, read, write, usleep) */
#include <linux/if_packet.h>	/* struct sockaddr_ll */
#include <net/if.h>				/* IFNAMSIZ, if_nametoindex */
#include <sys/socket.h>			/* socket, bind, recvfrom, sendto */
#include <time.h>

/* Constants */
#define MAX_EVENTS 10
#define MAX_IF 16
#define ARP_CACHE_SIZE 10
#define MAX_SDU_SIZE 256
#define MAX_PENDING_CLIENTS 10
#define MAX_UPPER_LAYERS 8
#define MAX_PONG_CACHE 8
#define MAX_PENDING_FORWARDS 20

/* SDU packet types */
#define SDU_TYPE_ARP 0x01
#define SDU_TYPE_PING 0x02
#define SDU_TYPE_ROUTING 0x04

/* Default TTL */
#define DEFAULT_TTL 15

/* ARP packet types */
#define ARP_TYPE_REQ 0x00
#define ARP_TYPE_RESP 0x01

/* Common MAC address for testbed (initializer-friendly macros) */
#define ETH_BROADCAST {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
/* Ethertype for MIP (host byte order constant) */
#define ETH_P_MIP 0x88B5
/* Destination MIP address of the PDU = 0xFF, meaning broadcast */
#define MIP_DEST_ADDR 0xFF

/* ARP cache entry */
struct arp_entry {
	uint8_t mip_addr;
	uint8_t mac_addr[6];
	int if_index;
};

/* Simple ARP cache */
struct arp_cache {
	struct arp_entry entries[ARP_CACHE_SIZE];
	int entry_count;
};

/* Upper layer client connection */
struct upper_layer_client {
	int fd;
	uint8_t sdu_type;
	int active;
};

struct pending_ping {
	int client_fd;
	uint8_t dest_mip;
	uint8_t sdu[MAX_SDU_SIZE];
	size_t sdu_len;
	uint8_t ttl;
	int waiting_for_arp;
};

/* Pending forward - waiting for route lookup */
struct pending_forward {
	uint8_t dest_mip;
	uint8_t src_mip;
	uint8_t ttl;
	uint8_t sdu_type;
	uint8_t sdu[MAX_SDU_SIZE];
	size_t sdu_len;
	time_t timestamp;
	int active;
};

struct pending_pong {
	int used;
	uint8_t src_mip;
	uint8_t pong_message[MAX_SDU_SIZE];
	size_t pong_len;
};

/* 
 * Ethernet frame convenience struct.
 * eth_proto is a 16-bit Ethertype in network byte order when placed on the wire.
 * contents is a flexible array member for payload bytes.
 */
struct ether_frame {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_proto; 	/* network byte order is preferred when sending */
	uint8_t contents[]; 	/* Flexible array member (C99) */
} __attribute__((packed));

/*
 * MIP header:
 *  +--------------+-------------+---------+-----------+-----------+
 *  | Dest. Addr.  | Src. Addr.  | TTL     | SDU Len.  | SDU type  |
 *  +--------------+-------------+---------+-----------+-----------+
 *  | 8 bits       | 8 bits      | 4 bits  | 9 bits    | 3 bits    |
 *  +--------------+-------------+---------+-----------+-----------+
 *
 * TTL(4) + SDU_len(9) + SDU_type(3) == 16 bits, so we pack them into a uint16_t.
 *
 * We store that 16-bit word in network byte order on the wire.
 */
struct mip_header {
	uint8_t dest;
	uint8_t src;
	uint8_t ttl;
	uint8_t sdu_len;
	uint8_t sdu_type;
	uint16_t ttl_sdu; 		/* packed field: TTL + SDU length + SDU type */
} __attribute__((packed));

/* Bit masks & shifts for the packed 16-bit field (host-side, before htons/ntohs) */
#define MIP_TTL_SHIFT 12
#define MIP_TTL_MASK 0xF /* 4 bits */

#define MIP_SDU_LEN_SHIFT 3
#define MIP_SDU_LEN_MASK 0x1FF /* 9 bits */

#define MIP_SDU_TYPE_SHIFT 0
#define MIP_SDU_TYPE_MASK 0x7 /* 3 bits */

/* Helper macros (work on host-order 16-bit values) */
#define MIP_MAKE_TTL_SDU(ttl, sdu_len, sdu_type) \
	((((uint16_t)(ttl) & MIP_TTL_MASK) << MIP_TTL_SHIFT) | \
	 (((uint16_t)(sdu_len) & MIP_SDU_LEN_MASK) << MIP_SDU_LEN_SHIFT) | \
	 (((uint16_t)(sdu_type) & MIP_SDU_TYPE_MASK) << MIP_SDU_TYPE_SHIFT))

#define MIP_EXTRACT_TTL(x) ((((uint16_t)(x) >> MIP_TTL_SHIFT) & MIP_TTL_MASK))
#define MIP_EXTRACT_SDU_LEN(x) ((((uint16_t)(x) >> MIP_SDU_LEN_SHIFT) & MIP_SDU_LEN_MASK))
#define MIP_EXTRACT_SDU_TYPE(x) ((((uint16_t)(x) >> MIP_SDU_TYPE_SHIFT) & MIP_SDU_TYPE_MASK))

/*
 * Note to self:
 * When writing a mip_header to the wire, convert ttl_sdu to network order:
 *    header.ttl_sdu = htons( MIP_MAKE_TTL_SDU(ttl, sdu_len_words, sdu_type) );
 * When reading from the wire:
 *    uint16_t host_packed = ntohs(header.ttl_sdu);
 *    ttl = MIP_EXTRACT_TTL(host_packed);
 *    sdu_len_words = MIP_EXTRACT_SDU_LEN(host_packed);
 *    sdu_type = MIP_EXTRACT_SDU_TYPE(host_packed);
 */

/* Interface data: up to MAX_IF interfaces */
struct ifs_data {
	struct sockaddr_ll addr[MAX_IF];
	int rsock[MAX_IF];			// RAW socket used to send/receive frames 
	uint8_t local_mip_addr;		// Assigned MIP address for this host 
	int ifn;					// Number of active interfaces 
	uint8_t macs[MAX_IF][6];	// Cached local MACs per interface (optional helper) 
	struct arp_cache arp;		// Simple ARP cache 
	int server_fd;
	struct pending_ping pending_pings[MAX_PENDING_CLIENTS];
	int pending_ping_count;
	struct pending_pong pong_cache[MAX_PONG_CACHE];
	struct upper_layer_client upper_layers[MAX_UPPER_LAYERS];
	int upper_layer_count;
	int routing_daemon_fd; 		// FD of routing daemon connection
	struct pending_forward pending_forwards[MAX_PENDING_FORWARDS];
	int pending_forward_count;
};

/* Function prototypes */
void print_mac_addr(const uint8_t *mac, size_t len);
void init_ifs(struct ifs_data *ifs, int mip_addr);
int send_arp_request(struct ifs_data *ifs, int if_index, uint8_t target_mip);
int send_arp_response(struct ifs_data *ifs, int if_index, uint8_t requester_mip,
					  uint8_t requester_mac[6]);
int handle_arp_packet(struct ifs_data *ifs, const uint8_t *sdu, 
                      size_t sdu_len, uint8_t src_mip, 
                      const uint8_t *src_mac, int if_index);
int send_mip_packet(struct ifs_data *ifs, int if_index,
					uint8_t dst_mip, uint8_t sdu_type, 
					const uint8_t *sdu, size_t sdu_len_bytes, uint8_t ttl);
int handle_mip_packet(struct ifs_data *ifs, const uint8_t *packet, size_t len, int if_index);
int init_unix_socket(const char *path);
int handle_unix_connection(struct ifs_data *ifs, int client_fd, 
                     	   int debug);
int arp_cache_lookup(struct arp_entry *entries, int count,  
                	 uint8_t mip, uint8_t mac[6], int *if_index);
void forward_mip_packet(struct ifs_data *ifs, uint8_t dest_mip, uint8_t src_mip,
						uint8_t ttl, uint8_t sdu_type, const uint8_t *sdu,
						size_t sdu_len);
void send_route_request(struct ifs_data *ifs, uint8_t dest_mip);
void handle_route_response(struct ifs_data *ifs, const uint8_t *payload, size_t len);
int find_upper_layer_client(struct ifs_data *ifs, uint8_t sdu_type);

#endif /* MIPD_H */