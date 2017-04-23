#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "cmdline.h"
#include "in_cksum.h"

extern const char *__progname;

static const u_int PRECISION = PCAP_TSTAMP_PRECISION_NANO;

#pragma pack(push, 1)
typedef struct {
    uint32_t seq;
    uint64_t timestamp;
    char data[60];
} message_t;

typedef struct {
    struct ether_header eth;
    struct ip ip;
    struct udphdr udp;
    message_t message;
    char trailer[16];
} packet_t;
#pragma pack(pop)

typedef struct {
    struct gengetopt_args_info args_info;
    pcap_t *pcap;
    pcap_dumper_t *dumper;
} context_t;


pcap_t *open_input(context_t *context)
{
    const char *filename = context->args_info.readfile_arg;
    struct bpf_program filter;

    char errbuf[PCAP_ERRBUF_SIZE];
    context->pcap =
        pcap_open_offline_with_tstamp_precision(filename, PRECISION, errbuf);

    if (!context->pcap)
        fprintf(stderr, "%s: %s\n", __progname, errbuf);

    pcap_compile(context->pcap, &filter, "udp", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(context->pcap, &filter);

    return context->pcap;
}

pcap_dumper_t *open_output(context_t *context)
{
    const char *filename = context->args_info.savefile_arg;
    context->dumper = pcap_dump_open(context->pcap, filename);

    if (!context->dumper)
        fprintf(stderr, "%s: %s\n", __progname, pcap_geterr(context->pcap));

    return context->dumper;
}

void close_all(context_t *context)
{
    if (context->pcap) {
        pcap_close(context->pcap);
        context->pcap = NULL;
    }
    if (context->dumper) {
        pcap_dump_close(context->dumper);
        context->dumper = NULL;
    }
}

void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *data)
{
    context_t *context = (context_t *)user;
    const char *ident = context->args_info.identifier_arg;
    packet_t packet;

    u_int32_t phdr[1];
    vec_t v[5];
    int32_t c;

    if (h->caplen == sizeof packet) {
        memcpy(&packet, data, sizeof packet);
        memset(packet.message.data, 0, sizeof packet.message.data);
        memcpy(packet.message.data, ident, strlen(ident));

        v[0].ptr = (uint8_t *)&packet.ip.ip_src;
        v[0].len = sizeof(packet.ip.ip_src);

        v[1].ptr = (uint8_t *)&packet.ip.ip_dst;
        v[1].len = sizeof(packet.ip.ip_dst);

        phdr[0] = htonl((packet.ip.ip_p << 16) | ntohs(packet.udp.uh_ulen));
        v[2].ptr = (u_int8_t *)&phdr;
        v[2].len = 4;

        packet.udp.uh_sum = 0;
        v[3].ptr = (u_int8_t *)&packet.udp;
        v[3].len = sizeof(packet.udp);

        v[4].ptr = (u_int8_t *)&packet.message;
        v[4].len = sizeof(packet.message);

        c = in_cksum(v, 5);
        packet.udp.uh_sum = c;
       
        pcap_dump((u_char *)context->dumper, h, (u_char *)&packet);
    }
}

int main(int argc, char *argv[])
{
    context_t context = {};
    struct gengetopt_args_info *args_info = &context.args_info;

    printf("%lu\n", sizeof(message_t));

    if (cmdline_parser(argc, argv, args_info) != 0)
        exit(2);

    if (open_input(&context)) {
        open_output(&context);
        pcap_loop(context.pcap, -1, process_packet, (u_char *)&context);
        close_all(&context);
    }

    return 0;
}
