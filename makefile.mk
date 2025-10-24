CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LDFLAGS = 

# Object files
MIPD_OBJS = mipd.o #mip_utils.o mip_network.o mip_arp.o mip_unix.o
PING_CLIENT_OBJS = ping_client.o
PING_SERVER_OBJS = ping_server.o

# Targets
all: mipd ping_client ping_server

mipd: $(MIPD_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

ping_client: $(PING_CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

ping_server: $(PING_SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Object file rules
%.o: %.c mipd.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o mipd ping_client ping_server

.PHONY: all clean