/**
 * mip_utils.c - MIP Daemon Utility Functions
 * 
 * Contains helper functions for interface initialization, MAC address
 * printing, and RAW socket creation.
 */

#include <ifaddrs.h>   /* getifaddrs, freeifaddrs */
#include <string.h>    /* strcmp, memcpy */
#include <stdlib.h>    /* exit */
#include <stdio.h>     /* printf, perror */
#include <unistd.h>    /* close */
#include <net/if.h> 
#include <arpa/inet.h> /* htons */
#include <sys/socket.h> /* socket */
#include <linux/if_packet.h> /* struct sockaddr_ll */
#include <sys/ioctl.h>   /* ioctl */

#include "mipd.h" 

/**
 * Print MAC address in human-readable hexadecimal format
 * mac: Pointer to MAC address bytes
 * len: Number of bytes to print (typically 6 for Ethernet)
 * 
 * Prints MAC address as colon-separated hex values to stdout.
 * Example output: "00:11:22:33:44:55"
 * 
 * Global variables: None
 * Returns: Nothing
 */
void print_mac_addr(const uint8_t *mac, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x%s", mac[i], (i == len - 1) ? "" : ":");
    }
}

/**
 * Initialize interface data structures and create RAW sockets
 * ifs: Pointer to interface data structure to initialize
 * mip_addr: MIP address to assign to this node
 * 
 * This function:
 * 1. Scans all available network interfaces using getifaddrs()
 * 2. Skips loopback interface
 * 3. Extracts MAC addresses for each interface
 * 4. Creates AF_PACKET RAW sockets for MIP protocol (ETH_P_MIP)
 * 5. Binds each socket to its corresponding interface
 * 6. Stores interface information in ifs_data structure
 * 
 * Global variables: None (all state stored in ifs parameter)
 * Returns: Nothing
 * Error handling: Exits program on fatal errors (no interfaces found,
 *                 socket creation failure, bind failure)
 */
void init_ifs(struct ifs_data *ifs, int mip_addr) {
    struct ifaddrs *ifaces, *ifa;
    int idx = 0;

    ifs->ifn = 0;
    ifs->local_mip_addr = mip_addr;

    if (getifaddrs(&ifaces) != 0) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaces; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;

        struct sockaddr_ll *sll = (struct sockaddr_ll*)ifa->ifa_addr;
        memcpy(ifs->macs[idx], sll->sll_addr, 6);

        ifs->addr[idx].sll_family = AF_PACKET;
        ifs->addr[idx].sll_protocol = htons(ETH_P_MIP);
        ifs->addr[idx].sll_ifindex = sll->sll_ifindex;
        ifs->addr[idx].sll_halen = 6;
        memcpy(ifs->addr[idx].sll_addr, sll->sll_addr, 6);

        printf("[MIPD] Found interface %s, ifindex %d, MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
            ifa->ifa_name, sll->sll_ifindex,
            sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2],
            sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);

        idx++;
        ifs->ifn = idx;
        if (idx >= MAX_IF) break;
    }

    freeifaddrs(ifaces);

    if (ifs->ifn == 0) {
        fprintf(stderr, "No network interfaces found!\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < ifs->ifn; i++) {
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP));
        if (sock < 0) {
            perror("socket RAW");
            exit(1);
        }
        if (bind(sock, (struct sockaddr*)&ifs->addr[i], sizeof(struct sockaddr_ll)) < 0) {
            perror("bind");
            close(sock);
            exit(1);
        }

        ifs->rsock[i] = sock;
    }

    // DEBUG: print interface info
    for (int i = 0; i < ifs->ifn; i++) {
        printf("[MIPD] Interface %d has RAW socket fd %d\n", i, ifs->rsock[i]);
    }
}