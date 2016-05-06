/*
	What is it: Zero Copy packet buffer utilizing mmap and io vectors
	to
	https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
	gcc -Wall -O2 packet_mmap.c -o packet_mmap
	sudo ./packet_mmap eth0
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

struct block_desc {
	uint32_t version;
	uint32_t offset_to_priv;
	struct tpacket_hdr_v1 h1;
};

struct ring {
	struct iovec *rd;
	uint8_t *map;
	struct tpacket_req3 req;
};

static unsigned long packets_total = 0, bytes_total = 0;
static sig_atomic_t sigint = 0;

/*
	sighandler: Sets a flag that says application should stop receiving.
*/
static void sighandler(int num)
{
	sigint = 1;
}
/*
	setup_socket: Opens socket on device for reading
*/
static int setup_socket(struct ring *ring, char *netdev)
{
	int err, i, fd, v = TPACKET_V3;
	struct sockaddr_ll ll;
	unsigned int blocksiz = 1 << 22, framesiz = 1 << 11;
	unsigned int blocknum = 64;

	// Use Raw Sock...which may change to avoid manual UDP parse.
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	// Use TPACKET_V3 for packet versioning
	err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
	if (err < 0) {
		perror("setsockopt");
		exit(1);
	}

	// Set the requirements for the ring buffer (This gives 256MB buffer space)
	memset(&ring->req, 0, sizeof(ring->req));
	ring->req.tp_block_size = blocksiz;
	ring->req.tp_frame_size = framesiz;
	ring->req.tp_block_nr = blocknum;
	ring->req.tp_frame_nr = (blocksiz * blocknum) / framesiz;
	ring->req.tp_retire_blk_tov = 60;
	ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

	// Set socket to use PACKET_RX_RING
	err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring->req,
			 sizeof(ring->req));
	if (err < 0) {
		perror("setsockopt");
		exit(1);
	}

	// Map the socket into virtual memory with the desired buffer size
	ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
			 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
	if (ring->map == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	// Create an IO Vector for each block in the ring.
	// The trick here is to figure out how to offset the iovs to only write
	// the v49 Info
	ring->rd = malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
	assert(ring->rd);
	for (i = 0; i < ring->req.tp_block_nr; ++i) {
		ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
		ring->rd[i].iov_len = ring->req.tp_block_size;
	}

	// Bind the socket for listening
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_protocol = htons(ETH_P_ALL);
	ll.sll_ifindex = if_nametoindex(netdev);
	ll.sll_hatype = 0;
	ll.sll_pkttype = 0;
	ll.sll_halen = 0;

	err = bind(fd, (struct sockaddr *) &ll, sizeof(ll));
	if (err < 0) {
		perror("bind");
		exit(1);
	}

	return fd;
}

/*
	display: Opens Header from a packet and displays source and dest IP
	Warning:  For the first ~1 second, this shows that other packets are in this
	buffer.
*/
static void display(struct tpacket3_hdr *ppd)
{
	struct ethhdr *eth = (struct ethhdr *) ((uint8_t *) ppd + ppd->tp_mac);
	struct iphdr *ip = (struct iphdr *) ((uint8_t *) eth + ETH_HLEN);

	// If we have an IP layer header...
	if (eth->h_proto == htons(ETH_P_IP)) {
		struct sockaddr_in ss, sd;
		char sbuff[NI_MAXHOST], dbuff[NI_MAXHOST];

		// Lookup source from packet header
		memset(&ss, 0, sizeof(ss));
		ss.sin_family = PF_INET;
		ss.sin_addr.s_addr = ip->saddr;
		getnameinfo((struct sockaddr *) &ss, sizeof(ss),
			    sbuff, sizeof(sbuff), NULL, 0, NI_NUMERICHOST);

		// Lookup destination from packet header
		memset(&sd, 0, sizeof(sd));
		sd.sin_family = PF_INET;
		sd.sin_addr.s_addr = ip->daddr;
		getnameinfo((struct sockaddr *) &sd, sizeof(sd),
			    dbuff, sizeof(dbuff), NULL, 0, NI_NUMERICHOST);

		printf("%s -> %s, ", sbuff, dbuff);
	}

	printf("rxhash: 0x%x\n", ppd->hv1.tp_rxhash);
}

/* Walk block:  Iterates over every packet within this block */
static void walk_block(struct block_desc *pbd, const int block_num)
{

	// Init a packet header pointer, and find out how many packets are in this
	// block
	int num_pkts = pbd->h1.num_pkts, i;
	unsigned long bytes = 0;
	struct tpacket3_hdr *ppd;

	// Load first packet (header is at the front of each packet)
	ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd +
				       pbd->h1.offset_to_first_pkt);
	for (i = 0; i < num_pkts; ++i) {

		// tally bytes, print out header info using display()
		bytes += ppd->tp_snaplen;
		display(ppd);

		// Go to the next packet.
		ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd +
					       ppd->tp_next_offset);
	}

	packets_total += num_pkts;
	bytes_total += bytes;
}

/*
	flush_block: Frees this block so it can be filled by the kernel.
	Notes:
		1) The buffer looks for TP_STATUS_KERNEL to know it can fill this block.
*/
static void flush_block(struct block_desc *pbd)
{
	pbd->h1.block_status = TP_STATUS_KERNEL;
}

/*
	teardown_socket: Unmaps ring buffer mem, destroys ring, closes socket fd
*/
static void teardown_socket(struct ring *ring, int fd)
{
	munmap(ring->map, ring->req.tp_block_size * ring->req.tp_block_nr);
	free(ring->rd);
	close(fd);
}

int main(int argc, char **argp)
{
	int fd, err;
	socklen_t len;
	struct ring ring;
	struct pollfd pfd;
	unsigned int block_num = 0, blocks = 64;
	struct block_desc *pbd;
	struct tpacket_stats_v3 stats;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s INTERFACE\n", argp[0]);
		return EXIT_FAILURE;
	}

	signal(SIGINT, sighandler);

	// Zero our ring struct so setup_socket can initialize
	memset(&ring, 0, sizeof(ring));

	// Open a socket with ring buffer
	fd = setup_socket(&ring, argp[argc - 1]);
	assert(fd > 0);

	// Set up polling mechanism to check if blocks can be read
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLERR;
	pfd.revents = 0;

	// While not interrupted...
	while (likely(!sigint)) {

		// Grab the io vector, casting buffer as block_descriptor
		pbd = (struct block_desc *) ring.rd[block_num].iov_base;

		// Can we read this block?
		if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
			// Note that a -1 timeout says that poll blocks indefinitely until there
			// is something read.
			poll(&pfd, 1, -1);
			// Now there is a block to read, so re run the loop. (continue)
			continue;
		}

		// Do something with the block
		walk_block(pbd, block_num);

		// Release the block
		flush_block(pbd);
		block_num = (block_num + 1) % blocks;
	}

	// After done listening, print status about what happened.
	// Note, pretty cool that PACKET_STATISTICS is a SOL_PACKET option...
	len = sizeof(stats);
	err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
	if (err < 0) {
		perror("getsockopt");
		exit(1);
	}

	fflush(stdout);
	printf("\nReceived %u packets, %lu bytes, %u dropped, freeze_q_cnt: %u\n",
	       stats.tp_packets, bytes_total, stats.tp_drops,
	       stats.tp_freeze_q_cnt);

	// Free the ring
	teardown_socket(&ring, fd);
	return 0;
}
