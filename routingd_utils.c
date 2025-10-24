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
    if (state->mip_sock < 0) return;

    // HELLO message format: [dest=255][ttl=0][MSG_HELLO][local_mip]
    uint8_t buffer[4];
    buffer[0] = MIP_DEST_ADDR;  // 0xFF = broadcast
    buffer[1] = 0;              // TTL (MIP daemon will set default)
    buffer[2] = MSG_HELLO;
    buffer[3] = state->local_mip;

    size_t sent = send(state->mip_sock, buffer, 4, 0);
    if (sent < 0) {
        perror("send_hello");
    } else {
        printf("[ROUTING] Sent HELLO broadcast from MIP %d\n", state->local_mip);
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
            if (!state->routes[i].valid) continue;
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
}