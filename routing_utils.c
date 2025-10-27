#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <errno.h>
#include <sys/select.h>

#include "mipd.h"
#include "routingd.h"

void init_routing_state(struct routing_state *state, uint8_t local_mip) {
    memset(state, 0, sizeof(*state));
    state->local_mip = local_mip;
    state->mip_sock = -1;
    state->route_count = 0;
    state->neighbor_count = 0;
    state->last_hello_sent = 0;
    state->last_update_sent = 0;

    // Add route to self with metric 0
    add_or_update_route(state, local_mip, local_mip, 0);
}

void send_hello(struct routing_state *state) {
    printf("[ROUTING] send_hello called for MIP %d, mip_sock=%d\n", 
           state->local_mip, state->mip_sock);
    
    if (state->mip_sock < 0) {
        printf("[ROUTING] ERROR: mip_sock is invalid (%d), cannot send HELLO\n", 
               state->mip_sock);
        return;
    }

    // HELLO message format: [dest=255][ttl=0][MSG_HELLO][local_mip]
    uint8_t buffer[4];
    buffer[0] = MIP_DEST_ADDR;  // 0xFF = broadcast
    buffer[1] = 0;              // TTL (MIP daemon will set default)
    buffer[2] = MSG_HELLO;
    buffer[3] = state->local_mip;

    printf("[ROUTING] Sending HELLO: dest=255, ttl=0, msg_type=0x%02x, local_mip=%d\n",
           MSG_HELLO, state->local_mip);

    ssize_t sent = send(state->mip_sock, buffer, 4, 0);
    if (sent < 0) {
        perror("send_hello");
    } else {
        printf("[ROUTING] Sent HELLO broadcast from MIP %d (%zd bytes)\n", 
               state->local_mip, sent);
    }

    state->last_hello_sent = time(NULL);
}

void send_update(struct routing_state *state) {
    if (state->mip_sock < 0) return;

    // Send updates to each neighbor with poisoned reverse
    for (int i = 0; i < state->neighbor_count; i++) {
        if (!state->neighbors[i].valid) continue;

        uint8_t neighbor_mip = state->neighbors[i].mip_addr;

        // UPDATE message format:
        // [dest][ttl=0][MSG_UPDATE][num_routes][dest1][metric1][dest2][metric2]...
        uint8_t buffer[MAX_SDU_SIZE];
        int offset = 0;

        buffer[offset++] = neighbor_mip;   // Destination
        buffer[offset++] = 0;              // TTL
        buffer[offset++] = MSG_UPDATE;

        int num_routes_offset = offset++;   // Reserve space for route count
        int num_routes = 0;
        
        // Add each route with poisoned reverse
        for (int j = 0; j < state->route_count; j++) {
            if (!state->routes[j].valid) continue;
            if (offset + 2 > MAX_SDU_SIZE - 1) break;

            uint8_t dest = state->routes[j].dest;
            uint8_t metric = state->routes[j].metric;

            // Poisoned reverse: if route goes through this neighbor,
            // advertise infinite metric to prevent loops
            if (state->routes[j].next_hop == neighbor_mip) {
                metric = INFINITY_METRIC;
            }

            buffer[offset++] = dest;
            buffer[offset++] = metric;
            num_routes++;
        }

        buffer[num_routes_offset] = num_routes;

        ssize_t sent = send(state->mip_sock, buffer, offset, 0);
        if (sent < 0) {
            perror("send_update");
        } else {
            printf("[ROUTING] Sent UPDATE to MIP %d with %d routes\n",
                   neighbor_mip, num_routes);
        }
    }

    state->last_update_sent = time(NULL);
}

void handle_hello(struct routing_state *state, uint8_t from_mip) {
    if (from_mip == state->local_mip) return;  // Ignore our own HELLOs

    printf("[ROUTING] Received HELLO from MIP %d\n", from_mip);

    // Update or add neighbor
    int found = 0;
    for (int i = 0; i < state->neighbor_count; i++) {
        if (state->neighbors[i].mip_addr == from_mip) {
            state->neighbors[i].last_hello = time(NULL);
            state->neighbors[i].valid = 1;
            found = 1;
            break;
        }
    }

    if (!found && state->neighbor_count < MAX_NEIGHBORS) {
        state->neighbors[state->neighbor_count].mip_addr = from_mip;
        state->neighbors[state->neighbor_count].last_hello = time(NULL);
        state->neighbors[state->neighbor_count].valid = 1;
        state->neighbor_count++;
        printf("[ROUTING] Added new neighbor: MIP %d\n", from_mip);
        
        // Add direct route to neighbor
        add_or_update_route(state, from_mip, from_mip, 1);
    }
}

void handle_update(struct routing_state *state, uint8_t from_mip, 
                   const uint8_t *data, size_t len) {
    if (len < 1) return;

    uint8_t num_routes = data[0];
    printf("[ROUTING] Received UPDATE from MIP %d with %d routes\n",
           from_mip, num_routes);

    int offset = 1;
    for (int i = 0; i < num_routes && offset + 1 < (int)len; i++) {
        uint8_t dest = data[offset++];
        uint8_t metric = data[offset++];

        if (dest == state->local_mip) continue; // Skip route to self

        // Distance vector: metric through this neighbor is their metric + 1
        uint8_t new_metric = (metric >= INFINITY_METRIC) ?
                              INFINITY_METRIC : (metric + 1);
        
        struct route_entry *existing = lookup_route(state, dest);

        if (existing) {
            // Update if new route is better or if current route goes through from_mip
            if (new_metric < existing->metric || existing->next_hop == from_mip) {
                if (new_metric < INFINITY_METRIC) {
                    existing->next_hop = from_mip;
                    existing->metric = new_metric;
                    existing->last_update = time(NULL);
                    printf("[ROUTING] Updated route to MIP %d via %d (metric %d)\n",
                            dest, from_mip, new_metric);
                } else if (existing->next_hop == from_mip) {
                    // Route became unreachable
                    existing->valid = 0;
                    printf("[ROUTING] Route to MIP %d became unreachable\n", dest);
                }
            }
        } else {
            // New route
            if (new_metric < INFINITY_METRIC) {
                add_or_update_route(state, dest, from_mip, new_metric);
                printf("[ROUTING] Added route to MIP %d via %d (metric %d)\n",
                        dest, from_mip, new_metric);
            }
        }
    }
}

void handle_route_request(struct routing_state *state, uint8_t dest_mip) {
    printf("[ROUTING] Route lookup request for MIP %d\n", dest_mip);

    struct route_entry *route = lookup_route(state, dest_mip);

    // RESPONSE format: [local_mip][ttl=0]['R']['S']['P'][next_hop]
    uint8_t buffer[6];
    buffer[0] = state->local_mip;   // Destination (send to self/mipd)
    buffer[1] = 0;                  // TTL
    buffer[2] = 0x52;               // 'R'
    buffer[3] = 0x53;               // 'S'
    buffer[4] = 0x50;               // 'P'

    if (route && route->valid) {
        buffer[5] = route->next_hop;
        printf("[ROUTING] ***** FOUND ROUTE: MIP %d -> next_hop %d (metric %d) *****\n", 
               dest_mip, route->next_hop, route->metric);
    } else {
        buffer[5] = 255;    // No route found
        printf("[ROUTING] ***** NO ROUTE to MIP %d *****\n", dest_mip);
    }

    printf("[ROUTING] Sending RESPONSE: ['R']['S']['P'][next_hop=%d]\n", buffer[5]);
    ssize_t sent = send(state->mip_sock, buffer, 6, 0);
    if (sent < 0) {
        perror("handle_route_request: send");
    } else {
        printf("[ROUTING] Route response sent (%zd bytes)\n", sent);
    }
}

void update_neighbors(struct routing_state *state) {
    time_t now = time(NULL);

    for (int i = 0; i < state->neighbor_count; i++) {
        if (!state->neighbors[i].valid) continue;

        if (now - state->neighbors[i].last_hello > NEIGHBOR_TIMEOUT) {
            printf("[ROUTING] Neighbor MIP %d timed out\n",
                    state->neighbors[i].mip_addr);
            state->neighbors[i].valid = 0;

            // Invalidate routes through this neighbor
            for (int j = 0; j < state->route_count; j++) {
                if (state->routes[j].next_hop == state->neighbors[i].mip_addr) {
                    state->routes[j].valid = 0;
                }
            }
        }
    }
}

void update_routes(struct routing_state *state) {
    time_t now = time(NULL);

    for (int i = 0; i < state->route_count; i++) {
        if (!state->routes[i].valid) continue;
        if (state->routes[i].dest == state->local_mip) continue;    // Keep self route

        if (now - state->routes[i].last_update > ROUTE_TIMEOUT) {
            printf("[ROUTING] Route to MIP %d timed out\n", state->routes[i].dest);
            state->routes[i].valid = 0;
        }
    }
}

struct route_entry* lookup_route(struct routing_state *state, uint8_t dest) {
    for (int i = 0; i < state->route_count; i++) {
        if (state->routes[i].dest == dest && state->routes[i].valid) {
            return &state->routes[i];
        }
    }
    return NULL;
}

void add_or_update_route(struct routing_state *state, uint8_t dest, 
                         uint8_t next_hop, uint8_t metric) {
    // Try to find existing route
    for (int i = 0; i < state->route_count; i++) {
        if (state->routes[i].dest == dest) {
            state->routes[i].next_hop = next_hop;
            state->routes[i].metric = metric;
            state->routes[i].last_update = time(NULL);
            state->routes[i].valid = 1;
            return;
        }
    }

    // Add new route
    if (state->route_count < MAX_ROUTES) {
        state->routes[state->route_count].dest = dest;
        state->routes[state->route_count].next_hop = next_hop;
        state->routes[state->route_count].metric = metric;
        state->routes[state->route_count].last_update = time(NULL);
        state->routes[state->route_count].valid = 1;
        state->route_count++;
    }
}

void print_routing_table(struct routing_state *state) {
    printf("\n=== Routing Table (MIP %d) ===\n", state->local_mip);
    printf("Dest\tNext Hop\tMetric\tAge\n");

    time_t now = time(NULL);
    int valid_count = 0;
    for (int i = 0; i < state->route_count; i++) {
        if (!state->routes[i].valid) continue;

        int age = (int)(now - state->routes[i].last_update);
        printf("%d\t%d\t\t%d\t%ds\n",
               state->routes[i].dest,
               state->routes[i].next_hop,
               state->routes[i].metric,
               age);
        valid_count++;
    }
    if (valid_count == 0) {
        printf("No routes\n");
    }
    printf("==============================\n\n");
}