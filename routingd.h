#ifndef ROUTING_DAEMON_H
#define ROUTING_DAEMON_H

#include <stdint.h>
#include <time.h>

#define MAX_ROUTES 256
#define MAX_NEIGHBORS 16
#define HELLO_INTERVAL 1        // Send HELLO every 1 second
#define UPDATE_INTERVAL 5       // Send routing updates every 5 seconds
#define NEIGHBOR_TIMEOUT 15     // Consider neighbor dead after 15 seconds
#define ROUTE_TIMEOUT 30        // Remove route after 30 seconds of no updates
#define INFINITY_METRIC 16      // Metric considered unreachable

/* Message types for routing protocol */
#define MSG_HELLO 0x01
#define MSG_UPDATE 0x02
#define MSG_REQUEST 0x52    // 'R'
#define MSG_RESPONSE 0x53   // 'S' (follows REQ format)

/* Routing table entry */
struct route_entry {
    uint8_t dest;           // Destination MIP address
    uint8_t next_hop;       // Next hop to reach destination
    uint8_t metric;         // Distance to destination (hop count)
    time_t last_update;     // Last time this route was updated
    int valid;              // Is this route valid?
};

/* Neighbor information */
struct neighbor {
    uint8_t mip_addr;       // Neighbor's MIP address
    time_t last_hello;      // Last time we received HELLO from this neighbor
    int valid;              // Is this neighbor still active?
};

/* Routing daemon state */
struct routing_state {
    uint8_t local_mip;                              // Our MIP address
    int mip_sock;                                   // Socket to MIP daemon
    struct route_entry routes[MAX_ROUTES];          // Routing table
    int route_count;
    struct neighbor neighbors[MAX_NEIGHBORS];       // Active neighbors
    int neighbor_count;
    time_t last_hello_sent;                         // Last time we sent HELLO
    time_t last_update_sent;                        // Last time we sent UPDATE
};

/* Function prottotypes */
void init_routing_state(struct routing_state *state, uint8_t local_mip);
void send_hello(struct routing_state *state);
void send_update(struct routing_state *state);
void handle_hello(struct routing_state *state, uint8_t from_mip);
void handle_update(struct routing_state *state, uint8_t from_mip, 
                   const uint8_t *data, size_t len);
void handle_route_request(struct routing_state *state, uint8_t dest_mip);
void update_neighbors(struct routing_state *state);
void update_routes(struct routing_state *state);
struct route_entry* lookup_route(struct routing_state *state, uint8_t dest);
void add_or_update_route(struct routing_state *state, uint8_t dest, 
                         uint8_t next_hop, uint8_t metric);
void print_routing_table(struct routing_state *state);

#endif /* ROUTING_DAEMON_H */