/**
 * routingd.h - Routing Daemon Header File
 * 
 * Defines data structures and constants for the Distance Vector Routing (DVR)
 * protocol with Poisoned Reverse. The routing daemon maintains a routing table,
 * exchanges routing information with neighbors, and responds to route queries
 * from the MIP daemon.
 */

#ifndef ROUTING_DAEMON_H
#define ROUTING_DAEMON_H

#include <stdint.h>
#include <time.h>

/* ============================================================================
 * PROTOCOL CONSTANTS
 * ============================================================================ */

/* Maximum number of routes in routing table */
#define MAX_ROUTES 256

/* Maximum number of direct neighbors */
#define MAX_NEIGHBORS 16

/* Send HELLO broadcast every 3 seconds to discover neighbors */
#define HELLO_INTERVAL 3

/* Send routing UPDATE to all neighbors every 5 seconds */
#define UPDATE_INTERVAL 5

/* Neighbor timeout - consider neighbor unreachable after 3 seconds without HELLO */
#define NEIGHBOR_TIMEOUT 3

/* Route timeout - remove route after 10 seconds without updates */
#define ROUTE_TIMEOUT 10

/* Infinity metric - routes with this metric are unreachable (DVR loop prevention) */
#define INFINITY_METRIC 16

/* Message types for routing protocol */
#define MSG_HELLO 0x01    /* Neighbor discovery message */
#define MSG_UPDATE 0x02   /* Routing table update message */

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/**
 * Routing table entry
 * Represents a destination and how to reach it using Distance Vector Routing
 * 
 * dest: Destination MIP address
 * next_hop: Next hop MIP address to reach destination
 * metric: Distance to destination in hops (0 = local, 1 = neighbor, etc.)
 * last_update: Timestamp of last update for this route (for timeout detection)
 * valid: 1 if route is active, 0 if expired/invalid
 */
struct route_entry {
    uint8_t dest;
    uint8_t next_hop;
    uint8_t metric;
    time_t last_update;
    int valid;
};

/**
 * Neighbor information
 * Tracks directly connected neighbors discovered via HELLO messages
 * 
 * mip_addr: Neighbor's MIP address
 * last_hello: Timestamp of last received HELLO message
 * valid: 1 if neighbor is active, 0 if timed out
 */
struct neighbor {
    uint8_t mip_addr;
    time_t last_hello;
    int valid;
};

/**
 * Routing daemon state
 * Contains complete state of the routing daemon including routing table,
 * neighbor list, and timing information
 * 
 * local_mip: This node's MIP address
 * mip_sock: Socket file descriptor for communication with MIP daemon
 * routes: Array of routing table entries
 * route_count: Number of active routes
 * neighbors: Array of discovered neighbors
 * neighbor_count: Number of active neighbors
 * last_hello_sent: Timestamp of last HELLO broadcast
 * last_update_sent: Timestamp of last UPDATE sent
 * 
 * Global variables: None (all state encapsulated)
 */
struct routing_state {
    uint8_t local_mip;
    int mip_sock;
    struct route_entry routes[MAX_ROUTES];
    int route_count;
    struct neighbor neighbors[MAX_NEIGHBORS];
    int neighbor_count;
    time_t last_hello_sent;
    time_t last_update_sent;
};

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * Initialize routing state structure
 * state: Pointer to routing state structure to initialize
 * local_mip: This node's MIP address
 * 
 * Initializes all fields to default values, sets up local route (metric 0),
 * and prepares state for operation.
 * 
 * Global variables: None
 * Returns: Nothing
 */
void init_routing_state(struct routing_state *state, uint8_t local_mip);

/**
 * Send HELLO broadcast message to discover neighbors
 * state: Routing state (contains mip_sock and local_mip)
 * 
 * Broadcasts a HELLO message with TTL=1 to all directly connected nodes.
 * Used for neighbor discovery in the DVR protocol.
 * 
 * Global variables: state->mip_sock (writes to socket)
 * Returns: Nothing
 * Error conditions: Socket write failure (printed but not fatal)
 */
void send_hello(struct routing_state *state);

/**
 * Send routing UPDATE to all neighbors
 * state: Routing state (contains routing table and neighbors)
 * 
 * Sends routing table to each neighbor using Distance Vector Routing
 * with Poisoned Reverse. Routes learned from a neighbor are advertised
 * back to that neighbor with metric = INFINITY to prevent loops.
 * 
 * Global variables: state->routes, state->neighbors (reads)
 *                   state->mip_sock (writes to socket)
 * Returns: Nothing
 * Error conditions: Socket write failure (printed but not fatal)
 */
void send_update(struct routing_state *state);

/**
 * Handle received HELLO message from neighbor
 * state: Routing state (neighbor list will be updated)
 * from_mip: MIP address of neighbor that sent HELLO
 * 
 * Adds neighbor to neighbor list or updates last_hello timestamp.
 * Automatically creates/updates route to neighbor with metric 1.
 * 
 * Global variables: state->neighbors, state->routes (modified)
 * Returns: Nothing
 */
void handle_hello(struct routing_state *state, uint8_t from_mip);

/**
 * Handle received routing UPDATE message
 * state: Routing state (routing table may be updated)
 * from_mip: MIP address of neighbor sending the update
 * data: Pointer to UPDATE message payload
 * len: Length of UPDATE message in bytes
 * 
 * Processes routing advertisements using Distance Vector Routing algorithm:
 * - Accepts better routes (lower metric)
 * - Refreshes existing routes from current next hop
 * - Ignores worse routes from different next hops
 * 
 * Global variables: state->routes (modified)
 * Returns: Nothing
 * Error conditions: Malformed UPDATE message (silently ignored)
 */
void handle_update(struct routing_state *state, uint8_t from_mip, 
                   const uint8_t *data, size_t len);

/**
 * Handle route request from MIP daemon
 * state: Routing state (routing table queried)
 * dest_mip: Destination MIP address to find route for
 * 
 * Looks up route to dest_mip in routing table and sends response
 * back to MIP daemon with next hop information.
 * 
 * Global variables: state->routes (reads), state->mip_sock (writes)
 * Returns: Nothing
 * Error conditions: No route found (sends response with metric = INFINITY)
 */
void handle_route_request(struct routing_state *state, uint8_t dest_mip);

/**
 * Update neighbor status and remove timed-out neighbors
 * state: Routing state (neighbors checked and possibly invalidated)
 * 
 * Checks each neighbor's last_hello timestamp and marks neighbors as
 * invalid if NEIGHBOR_TIMEOUT has elapsed. Invalidates routes through
 * dead neighbors.
 * 
 * Global variables: state->neighbors, state->routes (modified)
 * Returns: Nothing
 */
void update_neighbors(struct routing_state *state);

/**
 * Update routing table and remove expired routes
 * state: Routing state (routes checked and possibly invalidated)
 * 
 * Checks each route's last_update timestamp and marks routes as invalid
 * if ROUTE_TIMEOUT has elapsed without updates.
 * 
 * Global variables: state->routes (modified)
 * Returns: Nothing
 */
void update_routes(struct routing_state *state);

/**
 * Look up route to destination in routing table
 * state: Routing state (routing table queried)
 * dest: Destination MIP address
 * 
 * Searches routing table for valid route to specified destination.
 * 
 * Global variables: state->routes (reads)
 * Returns: Pointer to route_entry if found, NULL otherwise
 */
struct route_entry* lookup_route(struct routing_state *state, uint8_t dest);

/**
 * Add new route or update existing route in routing table
 * state: Routing state (routing table modified)
 * dest: Destination MIP address
 * next_hop: Next hop MIP address
 * metric: Distance metric (hop count)
 * 
 * Adds route to routing table or updates existing route if destination
 * already exists. Updates last_update timestamp.
 * 
 * Global variables: state->routes, state->route_count (modified)
 * Returns: Nothing
 * Error conditions: Routing table full (route not added, error printed)
 */
void add_or_update_route(struct routing_state *state, uint8_t dest, 
                         uint8_t next_hop, uint8_t metric);

/**
 * Print routing table to stdout for debugging
 * state: Routing state (routing table read)
 * 
 * Displays all valid routes with destination, next hop, and metric.
 * 
 * Global variables: state->routes (reads)
 * Returns: Nothing
 */
void print_routing_table(struct routing_state *state);

#endif /* ROUTING_DAEMON_H */