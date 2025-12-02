#include <asm-generic/errno-base.h>
#include <emmintrin.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <xdp/xsk.h>
#include <errno.h>
#include <poll.h>
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <ucl.h>
#include <assert.h>

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define MAX_SOCK           4
#define REFILL_BATCH       256

uint64_t free_frames[REFILL_BATCH];
int free_cnt = 0;

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	uint32_t outstanding_tx;
};

struct gtpuhdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 version:3,
		protocol_type:1,
        reserved:1,
        is_next_header_exists:1,
        is_seq_number_present:1,
        is_n_pdu_present:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8 is_n_pdu_present:1
        is_seq_number_present:1,
        is_next_header_exists:1,
        reserved:1,
		protocol_type:1,
        version:3;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u8 message_type;
    __u16 length;
    __u32 teid;
    __u16 sequence;
    __u8 __no_used;
    __u8 pdu_session;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u32 extension_header_length:8,
        pdu_session_container:24;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u32 pdu_session_container:24,
        extension_header_length:8;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
};

struct dns_query_key {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
} __attribute__((packed));;

static bool parse_dns_qname(const uint8_t *dns, size_t len, size_t offset, char *out, size_t outlen)
{
    size_t i = 0;
    size_t pos = offset;
    size_t written = 0;

    while (pos < len) {
        uint8_t label_len = dns[pos++];
        if (label_len == 0)
            break;
        if (pos + label_len > len || written + label_len + 1 >= outlen)
            return false;

        if (written > 0)
            out[written++] = '.';

        memcpy(&out[written], &dns[pos], label_len);
        written += label_len;
        pos += label_len;
    }

    out[written] = '\0';
    return true;
}

static struct xsk_umem_info* configure_xsk_umem(void *buffer, uint64_t size){
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));
    
    if (!umem){
		return NULL;
    }

    struct xsk_umem_config ucfg = {
      .fill_size = NUM_FRAMES,
      .comp_size = NUM_FRAMES,
      .frame_size = FRAME_SIZE,
      .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
      .flags = 0,
    };
    
    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &ucfg);

    if (ret) {
		errno = -ret;
		return NULL;
	}

    umem->buffer = buffer;
    return umem;
}

static struct xsk_socket_info* configure_xsk_socket(struct xsk_umem_info *umem){
  struct xsk_socket_info* socket;
  
  socket = calloc(1, sizeof(*socket));

  if(!socket) {
    fprintf(stderr, "ERROR: Failed to create socket info.");
    exit(EXIT_FAILURE);
  }

  socket->umem = umem;

  struct xsk_socket_config cfg = {
    .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
    .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
    .xdp_flags   = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
    .bind_flags  = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY,
    .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD
  };

  int ret = xsk_socket__create(&socket->xsk, "enp1s0f0", 5, umem->umem, &socket->rx, &socket->tx, &cfg);

  if(ret){
    fprintf(stderr, "ERROR: Failed to create socket");
    exit(EXIT_FAILURE);
  }

  return socket;
}

static inline void refill_fq(struct xsk_socket_info *socket,
                             uint64_t *frames, int *cnt)
{
    if (*cnt == 0)
        return;

    uint32_t idx_fq;
    int n = xsk_ring_prod__reserve(&socket->umem->fq, *cnt, &idx_fq);
    if (n > 0) {
        for (int i = 0; i < n; i++)
            *xsk_ring_prod__fill_addr(&socket->umem->fq, idx_fq + i) = frames[i];
        xsk_ring_prod__submit(&socket->umem->fq, n);

        if (n < *cnt) {
            memmove(frames, frames + n, (*cnt - n) * sizeof(uint64_t));
        }
        *cnt -= n;
    }
}

static void ban_trie_init(ucl_object_t **root){
    *root = ucl_object_typed_new(UCL_OBJECT);
}

static void reverse_domain(const char *in, char *out, size_t outlen) {
    char buf[256];
    strncpy(buf, in, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    for (char *p = buf; *p; p++)
        if (*p >= 'A' && *p <= 'Z') *p = *p - 'A' + 'a';

    char *labels[64];
    int count = 0;
    char *tok = strtok(buf, ".");
    while (tok && count < 64) {
        labels[count++] = tok;
        tok = strtok(NULL, ".");
    }

    out[0] = '\0';
    for (int i = count - 1; i >= 0; i--) {
        strncat(out, labels[i], outlen - strlen(out) - 1);
        if (i > 0)
            strncat(out, ".", outlen - strlen(out) - 1);
    }
}

static void ban_trie_add(ucl_object_t **root, char *domain, int len) {
    char r[256];
    reverse_domain(domain, r, sizeof(r));

    ucl_object_insert_key(*root, ucl_object_fromint(1),
                          r, len, true);
}

static int ban_trie_check(ucl_object_t **root, char *qname) {
    char r[256];
    reverse_domain(qname, r, sizeof(r));

    if (ucl_object_lookup(*root, r)) {
        return 1;
    }

    char *p = r;
    while ((p = strchr(p, '.')) != NULL) {
        p++;
        if (ucl_object_lookup(*root, p)) {
            return 1;
        }
    }

    return 0;
}

static void ban_trie_load(ucl_object_t **root, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("ban list open failed");
        exit(1);
    }

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = strtok(line, "\n");
        if (!p || p[0] == '#') continue;
        count += 1;
        ban_trie_add(root, p, strlen(p));
    }

    printf("Load %d black list items.\n", count);
    fclose(f);
}

int main(int argc, char* argv[]){
    void *packet_buffer;
    int packet_buffer_size = NUM_FRAMES * FRAME_SIZE;

    ucl_object_t *root = NULL;

    ban_trie_init(&root);
    ban_trie_load(&root, "ban.list");

    if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) {
      fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    struct xsk_umem_info *umem = configure_xsk_umem(packet_buffer, packet_buffer_size);

    if (umem == NULL) {
      fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
        strerror(errno));
      exit(EXIT_FAILURE);
    }
    
    struct xsk_socket_info *socket = configure_xsk_socket(umem);

    int fd = bpf_obj_get("/sys/fs/bpf/xsks_map");
    int qid = 5, xfd = xsk_socket__fd(socket->xsk);
    printf("socket fd=%d\n", xfd);
    if (bpf_map_update_elem(fd, &qid, &xfd, BPF_ANY) < 0) perror("update xsks_map");

    int allow_map_fd = bpf_obj_get("/sys/fs/bpf/dns_allow_map");

    struct pollfd fds[1];

    fds[0].fd = xsk_socket__fd(socket->xsk);
    fds[0].events = POLLIN;

    uint32_t idx;
    int n = xsk_ring_prod__reserve(&umem->fq, NUM_FRAMES, &idx);
    for (int i = 0; i < n; i++)
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&umem->fq, n);

    int loop_cnt = 0;
    for (;;) {
        uint32_t idx_rx;
        int rcvd = xsk_ring_cons__peek(&socket->rx, 64, &idx_rx);

        if (rcvd == 0) {
            _mm_pause();

            if ((++loop_cnt & 0xFF) == 0) {
                poll(fds, 1, 100);
            }else {
                usleep(200);
            }
            continue;
        }

        if ((loop_cnt++ & 0xFFF) == 0) {
            printf("[DEBUG] FQ avail=%u CQ avail=%u RX avail=%u TX avail=%u free_cnt=%d\n",
                xsk_prod_nb_free(&socket->umem->fq, NUM_FRAMES),
                xsk_cons_nb_avail(&socket->umem->cq, NUM_FRAMES),
                xsk_cons_nb_avail(&socket->rx, XSK_RING_CONS__DEFAULT_NUM_DESCS),
                xsk_prod_nb_free(&socket->tx, XSK_RING_PROD__DEFAULT_NUM_DESCS),
                free_cnt);
        }

        unsigned tx_enqueued = 0;

        for (int i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&socket->rx, idx_rx + i);
            uint64_t addr = xsk_umem__extract_addr(desc->addr);
            uint32_t len  = desc->len;

            uint8_t *pkt = xsk_umem__get_data(socket->umem->buffer, addr);

            struct ethhdr *eth = (struct ethhdr *)pkt;
            if (ntohs(eth->h_proto) != ETH_P_IP)
                goto recycle;

            struct iphdr *outer_ip = (struct iphdr *)(eth + 1);
            if (outer_ip->protocol != IPPROTO_UDP)
                goto recycle;

            struct udphdr *outer_udp = (struct udphdr *)((uint8_t *)outer_ip + outer_ip->ihl * 4);
            if (ntohs(outer_udp->dest) != 2152)
                goto recycle;

            struct gtpuhdr *gtpu = (struct gtpuhdr *)(outer_udp + 1);

            struct iphdr *inner_ip = (struct iphdr *)(gtpu + 1);
            if (inner_ip->protocol != IPPROTO_UDP)
                goto recycle;

            struct udphdr *inner_udp = (struct udphdr *)((uint8_t *)inner_ip + inner_ip->ihl * 4);
            if (ntohs(inner_udp->dest) != 53 && ntohs(inner_udp->source) != 53)
                goto recycle;

            uint8_t *dns_hdr = (uint8_t *)(inner_udp + 1);
            size_t dns_len = pkt + len - dns_hdr;
            if (dns_len < 12)
              goto recycle;

            char qname[256];
            if (!parse_dns_qname(dns_hdr, dns_len, 12, qname, sizeof(qname)))
              goto recycle;

            uint16_t txid = ntohs(*(uint16_t *)dns_hdr);

            bool pass = true;

            if (ban_trie_check(&root, qname)){
                pass = false;
                printf("Invalid request: %s\n", qname);
            }

            if (pass) {
              struct flow_key {
                uint32_t src_ip;
                uint32_t dst_ip;
                uint16_t src_port;
                uint16_t dst_port;
              } __attribute__((packed)) key = {
                .src_ip = inner_ip->saddr,
                .dst_ip = inner_ip->daddr,
                .src_port = inner_udp->source,
                .dst_port = inner_udp->dest,
              };

              if (bpf_map_update_elem(allow_map_fd, &key, &txid, BPF_ANY) < 0)
                  perror("bpf_map_update_elem");
              
              uint32_t idx_tx;
              if (xsk_ring_prod__reserve(&socket->tx, 1, &idx_tx) == 1) {
                  struct xdp_desc *txd = xsk_ring_prod__tx_desc(&socket->tx, idx_tx);
                  txd->addr = addr;
                  txd->len  = len;
                  xsk_ring_prod__submit(&socket->tx, 1);
                  tx_enqueued++;
              } else {
                  uint32_t idx_fq;
                  if (xsk_ring_prod__reserve(&socket->umem->fq, 1, &idx_fq) == 1) {
                      *xsk_ring_prod__fill_addr(&socket->umem->fq, idx_fq) = addr;
                      xsk_ring_prod__submit(&socket->umem->fq, 1);
                  }
              }
            } else {
recycle:
                uint32_t idx_fq;
                if (xsk_ring_prod__reserve(&socket->umem->fq, 1, &idx_fq) == 1) {
                    *xsk_ring_prod__fill_addr(&socket->umem->fq, idx_fq) = addr;
                    xsk_ring_prod__submit(&socket->umem->fq, 1);
                }
            }
        }

        xsk_ring_cons__release(&socket->rx, rcvd);

        if (tx_enqueued)
            (void)sendto(xsk_socket__fd(socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

        uint32_t idx_cq;
        unsigned int completed = xsk_ring_cons__peek(&socket->umem->cq, 64, &idx_cq);
        for (unsigned int i = 0; i < completed; i++) {
            uint64_t caddr = *xsk_ring_cons__comp_addr(&socket->umem->cq, idx_cq + i);
            free_frames[free_cnt++] = caddr;

            if (free_cnt == REFILL_BATCH)
                refill_fq(socket, free_frames, &free_cnt);
        }

        if (completed) {
            xsk_ring_cons__release(&socket->umem->cq, completed);
        }
        refill_fq(socket, free_frames, &free_cnt);
    }
}