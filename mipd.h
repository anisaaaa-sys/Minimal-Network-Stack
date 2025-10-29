/**
 * mipd.h - MIP Daemon Header File
 * 
 * Defines the MIP protocol headers, data structures, and function prototypes
 * for the MIP daemon implementation. The MIP daemon handles network layer
 * packet forwarding, ARP resolution, and communication with upper layer
 * applications and the routing daemon.
 */

#ifndef MIPD_H
#define MIPD_H

#include <stdint.h>				/* uint8_t, uint16_t */
#include <stddef.h>				/* size_t */
#include <unistd.h> 			/* POSIX APIs (close, read, write, usleep) */
#include <linux/if_packet.h>	/* struct sockaddr_ll */
#include <net/if.h>				/* IFNAMSIZ, if_nametoindex */
#include <sys/socket.h>			/* socket, bind, recvfrom, sendto */
#include <time.h>

/* ============================================================================
 * CONSTANTS AND PROTOCOL DEFINITIONS
 * ============================================================================ */

/* Maximum number of epoll events to process per iteration */
#define MAX_EVENTS 10

/* Maximum number of network interfaces supported */
#define MAX_IF 16

/* Maximum number of ARP cache entries */
#define ARP_CACHE_SIZE 10

/* Maximum size of Service Data Unit (SDU) payload in bytes */
#define MAX_SDU_SIZE 256

/* Maximum number of pending client connections */
#define MAX_PENDING_CLIENTS 10

/* Maximum number of upper layer (application) connections */
#define MAX_UPPER_LAYERS 8

/* Maximum number of cached PONG messages */
#define MAX_PONG_CACHE 8

/* Maximum number of packets waiting for route resolution */
#define MAX_PENDING_FORWARDS 20

/* SDU packet types - identifies upper layer protocol */
#define SDU_TYPE_ARP 0x01      /* Address Resolution Protocol */
#define SDU_TYPE_PING 0x02     /* PING/PONG application */
#define SDU_TYPE_ROUTING 0x04  /* Routing protocol (DVR) */

/* Default Time-To-Live for packets (max hops) */
#define DEFAULT_TTL 15

/* ARP packet types */
#define ARP_TYPE_REQ 0x00   /* ARP request */
#define ARP_TYPE_RESP 0x01  /* ARP response */

/* Ethernet broadcast MAC address */
#define ETH_BROADCAST {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

/* Ethertype for MIP protocol (host byte order) */
#define ETH_P_MIP 0x88B5

/* MIP broadcast address - packets sent to this address reach all nodes */
#define MIP_DEST_ADDR 0xFF

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/**
 * ARP cache entry - maps MIP address to MAC address
 * 
 * mip_addr: The MIP address (network layer)
 * mac_addr: The corresponding MAC address (link layer)
 * if_index: Interface index where this mapping was learned
 */
struct arp_entry {
	uint8_t mip_addr;
	uint8_t mac_addr[6];
	int if_index;
};

/**
 * ARP cache - stores MIP-to-MAC address mappings
 * 
 * entries: Array of ARP cache entries
 * entry_count: Number of active entries in the cache
 */
struct arp_cache {
	struct arp_entry entries[ARP_CACHE_SIZE];
	int entry_count;
};

/**
 * Upper layer client connection
 * Represents a connection from an application (ping client/server)
 * 
 * fd: File descriptor for the UNIX domain socket connection
 * sdu_type: Type of SDU this client handles (e.g., SDU_TYPE_PING)
 * active: 1 if connection is active, 0 if available/closed
 */
struct upper_layer_client {
	int fd;
	uint8_t sdu_type;
	int active;
};

/**
 * Pending PING packet
 * Stores PING packets waiting for ARP resolution before sending
 * 
 * client_fd: File descriptor of the client that sent the PING
 * dest_mip: Destination MIP address
 * sdu: Service Data Unit (payload)
 * sdu_len: Length of SDU in bytes
 * ttl: Time-To-Live value
 * waiting_for_arp: 1 if waiting for ARP response, 0 otherwise
 */
struct pending_ping {
	int client_fd;
	uint8_t dest_mip;
	uint8_t sdu[MAX_SDU_SIZE];
	size_t sdu_len;
	uint8_t ttl;
	int waiting_for_arp;
};

/**
 * Pending forward packet
 * Stores packets waiting for route resolution from routing daemon
 * 
 * dest_mip: Final destination MIP address
 * src_mip: Original source MIP address
 * ttl: Current Time-To-Live value
 * sdu_type: Type of SDU (protocol identifier)
 * sdu: Service Data Unit (payload)
 * sdu_len: Length of SDU in bytes
 * timestamp: Time when this forward was queued (for timeout detection)
 * active: 1 if this slot is in use, 0 if available
 */
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

/**
 * Cached PONG message
 * Stores PONG responses temporarily for delivery to clients
 * 
 * used: 1 if this slot contains a valid PONG, 0 if empty
 * src_mip: MIP address of PONG sender
 * pong_message: The PONG message content
 * pong_len: Length of PONG message in bytes
 */
struct pending_pong {
	int used;
	uint8_t src_mip;
	uint8_t pong_message[MAX_SDU_SIZE];
	size_t pong_len;
};

/**
 * Ethernet frame structure
 * Represents a complete Ethernet frame with MIP protocol payload
 * 
 * dst_addr: Destination MAC address (6 bytes)
 * src_addr: Source MAC address (6 bytes)
 * eth_proto: Ethertype field (must be ETH_P_MIP in network byte order)
 * contents: Flexible array member for payload (MIP header + SDU)
 * 
 * Note: Packed attribute ensures no padding between fields
 */
struct ether_frame {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_proto; 	/* network byte order is preferred when sending */
	uint8_t contents[]; 	/* Flexible array member (C99) */
} __attribute__((packed));

/**
 * MIP protocol header
 * 
 * Header layout (4 bytes total):
 *  +--------------+-------------+---------+-----------+-----------+
 *  | Dest. Addr.  | Src. Addr.  | TTL     | SDU Len.  | SDU type  |
 *  +--------------+-------------+---------+-----------+-----------+
 *  | 8 bits       | 8 bits      | 4 bits  | 9 bits    | 3 bits    |
 *  +--------------+-------------+---------+-----------+-----------+
 *
 * dest: Destination MIP address (0xFF = broadcast)
 * src: Source MIP address
 * ttl: Time-To-Live (unpacked, for convenience)
 * sdu_len: Length of SDU (unpacked, for convenience)
 * sdu_type: Type of SDU/protocol (unpacked, for convenience)
 * ttl_sdu: Packed 16-bit field containing TTL(4) + SDU_len(9) + SDU_type(3)
 *          Stored in network byte order on the wire
 * 
 * Note: ttl, sdu_len, and sdu_type are convenience fields for host-side use.
 *       The ttl_sdu field is the actual packed representation sent on the wire.
 */
struct mip_header {
	uint8_t dest;
	uint8_t src;
	uint8_t ttl;
	uint8_t sdu_len;
	uint8_t sdu_type;
	uint16_t ttl_sdu; 		/* packed field: TTL + SDU length + SDU type */
} __attribute__((packed));

/* ============================================================================
 * MIP HEADER PACKING/UNPACKING MACROS
 * ============================================================================ */

/* Bit shifts for packed 16-bit TTL_SDU field (host byte order) */
#define MIP_TTL_SHIFT 12      /* TTL occupies bits 15-12 */
#define MIP_SDU_LEN_SHIFT 3   /* SDU length occupies bits 11-3 */
#define MIP_SDU_TYPE_SHIFT 0  /* SDU type occupies bits 2-0 */

/* Bit masks for extracting fields */
#define MIP_TTL_MASK 0xF      /* 4 bits: 0000-1111 */
#define MIP_SDU_LEN_MASK 0x1FF /* 9 bits: 0-511 */
#define MIP_SDU_TYPE_MASK 0x7  /* 3 bits: 0-7 */

/**
 * Pack TTL, SDU length, and SDU type into 16-bit field (host byte order)
 * ttl: Time-To-Live (0-15)
 * sdu_len: SDU length in bytes (0-511)
 * sdu_type: SDU type identifier (0-7)
 * 
 * Returns: 16-bit packed value in host byte order
 * Note: Use htons() to convert to network byte order before sending
 */
#define MIP_MAKE_TTL_SDU(ttl, sdu_len, sdu_type) \
	((((uint16_t)(ttl) & MIP_TTL_MASK) << MIP_TTL_SHIFT) | \
	 (((uint16_t)(sdu_len) & MIP_SDU_LEN_MASK) << MIP_SDU_LEN_SHIFT) | \
	 (((uint16_t)(sdu_type) & MIP_SDU_TYPE_MASK) << MIP_SDU_TYPE_SHIFT))

/**
 * Extract TTL from packed 16-bit field (host byte order)
 * x: Packed 16-bit value (after ntohs())
 * Returns: TTL value (0-15)
 */
#define MIP_EXTRACT_TTL(x) ((((uint16_t)(x) >> MIP_TTL_SHIFT) & MIP_TTL_MASK))

/**
 * Extract SDU length from packed 16-bit field (host byte order)
 * x: Packed 16-bit value (after ntohs())
 * Returns: SDU length in bytes (0-511)
 */
#define MIP_EXTRACT_SDU_LEN(x) ((((uint16_t)(x) >> MIP_SDU_LEN_SHIFT) & MIP_SDU_LEN_MASK))

/**
 * Extract SDU type from packed 16-bit field (host byte order)
 * x: Packed 16-bit value (after ntohs())
 * Returns: SDU type (0-7)
 */
#define MIP_EXTRACT_SDU_TYPE(x) ((((uint16_t)(x) >> MIP_SDU_TYPE_SHIFT) & MIP_SDU_TYPE_MASK))

/**
 * Interface state and configuration
 * Contains all state for the MIP daemon including sockets, ARP cache,
 * routing information, and pending packets.
 * 
 * addr: Sockaddr structures for each interface (for bind/sendto)
 * rsock: RAW socket file descriptors for each interface
 * local_mip_addr: This node's MIP address
 * ifn: Number of active network interfaces
 * macs: Local MAC addresses for each interface
 * arp: ARP cache storing MIP-to-MAC mappings
 * server_fd: UNIX socket for accepting upper layer connections
 * pending_pings: Queue of PING packets waiting for ARP resolution
 * pending_ping_count: Number of pending PINGs
 * pong_cache: Cache of received PONG messages for delivery to clients
 * upper_layers: Active connections to upper layer applications
 * upper_layer_count: Number of active upper layer connections
 * routing_daemon_fd: File descriptor for routing daemon connection
 * pending_forwards: Queue of packets waiting for route resolution
 * pending_forward_count: Number of pending forwards
 * 
 * Global variables affected: None (all state is encapsulated)
 */
struct ifs_data {
	struct sockaddr_ll addr[MAX_IF];
	int rsock[MAX_IF];
	uint8_t local_mip_addr;
	int ifn;
	uint8_t macs[MAX_IF][6];
	struct arp_cache arp;
	int server_fd;
	struct pending_ping pending_pings[MAX_PENDING_CLIENTS];
	int pending_ping_count;
	struct pending_pong pong_cache[MAX_PONG_CACHE];
	struct upper_layer_client upper_layers[MAX_UPPER_LAYERS];
	int upper_layer_count;
	int routing_daemon_fd;
	struct pending_forward pending_forwards[MAX_PENDING_FORWARDS];
	int pending_forward_count;
};

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * Print MAC address in human-readable format
 * mac: Pointer to MAC address bytes
 * len: Number of bytes to print (typically 6)
 * 
 * Prints MAC address as colon-separated hex values to stdout
 */
void print_mac_addr(const uint8_t *mac, size_t len);

/**
 * Initialize interface data structures and create RAW sockets
 * ifs: Pointer to interface data structure to initialize
 * mip_addr: MIP address to assign to this node
 * 
 * Scans available network interfaces (excluding loopback), creates
 * RAW sockets for each, and initializes the ifs_data structure.
 * 
 * Global variables: None
 * Error handling: Exits program on fatal errors (no interfaces, socket/bind failure)
 */
void init_ifs(struct ifs_data *ifs, int mip_addr);

/**
 * Send ARP request for a given MIP address
 * ifs: Interface data containing socket and address information
 * if_index: Interface index to send request on
 * target_mip: MIP address to resolve
 * 
 * Constructs and broadcasts an ARP request on the specified interface.
 * 
 * Returns: 0 on success, -1 on error
 * Global variables: None
 */
int send_arp_request(struct ifs_data *ifs, int if_index, uint8_t target_mip);

/**
 * Send ARP response to a requester
 * ifs: Interface data containing local MIP and MAC information
 * if_index: Interface index to send response on
 * requester_mip: MIP address of the node that sent the request
 * requester_mac: MAC address of the requester
 * 
 * Constructs and sends an ARP response containing this node's MIP-to-MAC mapping.
 * 
 * Returns: 0 on success, -1 on error
 * Global variables: None
 */
int send_arp_response(struct ifs_data *ifs, int if_index, uint8_t requester_mip,
					  uint8_t requester_mac[6]);

/**
 * Handle received ARP packet (request or response)
 * ifs: Interface data (ARP cache will be updated)
 * sdu: Pointer to ARP packet payload
 * sdu_len: Length of ARP packet in bytes
 * src_mip: Source MIP address from MIP header
 * src_mac: Source MAC address from Ethernet frame
 * if_index: Interface on which packet was received
 * 
 * Processes ARP requests (sends response) and ARP responses (updates cache).
 * Automatically triggers sending of pending packets when ARP is resolved.
 * 
 * Returns: 0 on success, -1 on error
 * Global variables: ifs->arp (ARP cache is modified)
 */
int handle_arp_packet(struct ifs_data *ifs, const uint8_t *sdu, 
                      size_t sdu_len, uint8_t src_mip, 
                      const uint8_t *src_mac, int if_index);

/**
 * Send MIP packet with specified parameters
 * ifs: Interface data containing sockets and ARP cache
 * if_index: Interface index to send packet on (or -1 for broadcast on all)
 * dst_mip: Destination MIP address
 * sdu_type: Type of SDU (SDU_TYPE_PING, SDU_TYPE_ROUTING, etc.)
 * sdu: Pointer to SDU payload
 * sdu_len_bytes: Length of SDU in bytes
 * ttl: Time-To-Live value (0 = use DEFAULT_TTL)
 * src_mip: Source MIP address (0 = use local MIP address)
 * 
 * Constructs MIP header, looks up destination MAC in ARP cache,
 * and sends packet via RAW socket.
 * 
 * Returns: 0 on success, -1 on error
 * Global variables: ifs->arp (reads ARP cache)
 * Error conditions: ARP cache miss, network interface down, invalid parameters
 */
int send_mip_packet(struct ifs_data *ifs, int if_index,
				uint8_t dst_mip, uint8_t sdu_type, 
				const uint8_t *sdu, size_t sdu_len_bytes, uint8_t ttl, uint8_t src_mip);

/**
 * Handle received MIP packet
 * ifs: Interface data (for forwarding, ARP learning, and delivery)
 * packet: Pointer to raw Ethernet frame
 * len: Total length of frame in bytes
 * if_index: Interface on which packet was received
 * 
 * Parses MIP header, automatically learns source MAC-to-MIP mapping,
 * decrements TTL for forwarded packets, and dispatches to appropriate
 * handler (ARP, routing daemon, ping client/server, or forwarding engine).
 * 
 * Returns: 0 on success, -1 on error
 * Global variables: ifs->arp (ARP cache updated), ifs->routing_daemon_fd,
 *                   ifs->upper_layers (for application delivery)
 * Error conditions: Malformed packet, TTL expired, unknown destination
 */
int handle_mip_packet(struct ifs_data *ifs, const uint8_t *packet, size_t len, int if_index);

/**
 * Initialize UNIX domain socket for application connections
 * path: Path to UNIX socket file
 * 
 * Creates, binds, and listens on a UNIX SOCK_SEQPACKET socket for
 * upper layer application connections (ping client/server, routing daemon).
 * 
 * Returns: Socket file descriptor on success, -1 on error
 * Global variables: None
 * Error conditions: Socket creation/bind/listen failure, path already exists
 */
int init_unix_socket(const char *path);

/**
 * Handle data received from UNIX socket (upper layer application)
 * ifs: Interface data for sending packets
 * client_fd: File descriptor of the client connection
 * debug: Debug flag (unused)
 * 
 * Reads PING request from client, queues it for forwarding via routing
 * daemon or sends directly if destination is a neighbor.
 * 
 * Returns: 0 on success, -1 on error or connection close
 * Global variables: ifs->pending_pings, ifs->routing_daemon_fd
 * Error conditions: Read error, invalid packet format, queue full
 */
int handle_unix_connection(struct ifs_data *ifs, int client_fd, 
                     	   int debug);

/**
 * Look up MIP address in ARP cache
 * entries: Array of ARP cache entries
 * count: Number of entries in cache
 * mip: MIP address to look up
 * mac: Output buffer for MAC address (6 bytes)
 * if_index: Output pointer for interface index
 * 
 * Searches ARP cache for given MIP address and returns corresponding
 * MAC address and interface index.
 * 
 * Returns: 0 if found, -1 if not found
 * Global variables: None
 */
int arp_cache_lookup(struct arp_entry *entries, int count,  
                	 uint8_t mip, uint8_t mac[6], int *if_index);

/**
 * Queue packet for forwarding and request route from routing daemon
 * ifs: Interface data (pending_forwards queue will be updated)
 * dest_mip: Final destination MIP address
 * src_mip: Original source MIP address
 * ttl: Current Time-To-Live value
 * sdu_type: Type of SDU
 * sdu: Pointer to SDU payload
 * sdu_len: Length of SDU in bytes
 * 
 * Adds packet to pending_forwards queue and sends route request to
 * routing daemon. Packet will be sent once route response is received.
 * 
 * Returns: Nothing
 * Global variables: ifs->pending_forwards, ifs->routing_daemon_fd
 * Error conditions: Queue full (packet dropped)
 */
void forward_mip_packet(struct ifs_data *ifs, uint8_t dest_mip, uint8_t src_mip,
						uint8_t ttl, uint8_t sdu_type, const uint8_t *sdu,
						size_t sdu_len);

/**
 * Send route request to routing daemon
 * ifs: Interface data (routing_daemon_fd used)
 * dest_mip: Destination MIP address to find route for
 * 
 * Sends a route request message to the routing daemon asking for the
 * next hop to reach dest_mip.
 * 
 * Returns: Nothing
 * Global variables: ifs->routing_daemon_fd
 * Error conditions: Routing daemon not connected (silent failure)
 */
void send_route_request(struct ifs_data *ifs, uint8_t dest_mip);

/**
 * Handle route response from routing daemon
 * ifs: Interface data (pending_forwards processed)
 * payload: Pointer to route response message
 * len: Length of response in bytes
 * 
 * Parses route response containing next hop MIP address, finds matching
 * packets in pending_forwards queue, and attempts to send them.
 * 
 * Returns: Nothing
 * Global variables: ifs->pending_forwards, ifs->arp
 * Error conditions: Invalid response format, ARP cache miss (packet re-queued)
 */
void handle_route_response(struct ifs_data *ifs, const uint8_t *payload, size_t len);

/**
 * Find upper layer client by SDU type
 * ifs: Interface data containing upper_layers array
 * sdu_type: SDU type to search for (e.g., SDU_TYPE_PING)
 * 
 * Searches for an active upper layer client connection that handles
 * the specified SDU type.
 * 
 * Returns: File descriptor of matching client, or -1 if not found
 * Global variables: ifs->upper_layers
 */
int find_upper_layer_client(struct ifs_data *ifs, uint8_t sdu_type);

#endif /* MIPD_H */