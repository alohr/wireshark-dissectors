#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#ifdef __linux__
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#endif

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef __MACH__
#include <err.h>
#include <mach/clock.h>
#include <mach/mach.h>
#else
#endif

#include "cmdline.h"

extern const char *__progname;

static const char BEACON_GROUP[] = "239.0.0.1";
static const int BEACON_PORT = 4000;
static const int POLL_TIMEOUT_MS = 10;

typedef struct {
    const char *name;
    int value;
} dscp_t;

static const dscp_t DSCP[] = {
    { "cs0", 0b000000 },
    { "cs1", 0b001000 },
    { "cs2", 0b010000 },
    { "cs3", 0b011000 },
    { "cs4", 0b100000 },
    { "cs5", 0b101000 },
    { "cs6", 0b110000 },
    { "cs7", 0b111000 },
    { NULL, 0 }
};

#pragma pack(push, 1)
typedef struct {
    uint32_t seq;
    uint64_t timestamp;
    char data[60];
} message_t;
#pragma pack(pop)

typedef struct {
    struct gengetopt_args_info args_info;
    int verbose;
    int sock;
    char *ifname;
    struct sockaddr ifaddr;

} context_t;


int get_interface(context_t *context)
{
    struct ifaddrs *ifaddrs, *ifa;
    int match = -1;

    if (getifaddrs(&ifaddrs) < 0) {
        perror("getifaddrs");
        return -1;
    }

    ifa = ifaddrs;
    while (ifa != NULL) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            if (context->verbose) {
                printf("%s: %s\n",
                       ifa->ifa_name,
                       inet_ntoa(((struct sockaddr_in *) ifa->ifa_addr)->sin_addr));
            }
            if (strcmp(context->args_info.interface_arg, ifa->ifa_name) == 0) {
                context->ifname = strdup(ifa->ifa_name);
                context->ifaddr = *ifa->ifa_addr;
                match = 0;
                break;
            }
        }
        ifa = ifa->ifa_next;
    }

    freeifaddrs(ifaddrs);
    return match;
}

int get_dscp(const char *name)
{
    const dscp_t *dscp = DSCP;

    while (dscp->name) {
        if (strcmp(dscp->name, name) == 0)
            return dscp->value;
        dscp++;
    }

    return 0;
}

#ifdef __MACH__
static int init_hwts(context_t *context)
{
    return -1;
}
#else
static int init_hwts(context_t *context)
{
    struct ifreq ifreq = {};
    struct hwtstamp_config req = {}, cfg = {};

    strncpy(ifreq.ifr_name, context->ifname, sizeof(ifreq.ifr_name) - 1);
    ifreq.ifr_data = (void *) &req;

    cfg.tx_type = HWTSTAMP_TX_ON;

    req = cfg;

    if (ioctl(context->sock, SIOCSHWTSTAMP, &ifreq))
        err(1, "ioctl(SIOCSHWTSTAMP, %s)", ifreq.ifr_name);

    if (memcmp(&cfg, &req, sizeof(cfg))) {
        // from linux ptp
        printf("driver changed our HWTSTAMP options");
        printf("tx_type   %d not %d", cfg.tx_type, req.tx_type);

        if (cfg.tx_type != req.tx_type)
            return -1;
    }

    printf("HWTS: ioctl(SIOCSHWTSTAMP) ok\n");

    return 0;


}
#endif

#ifdef __linux__
int init_timestamping(context_t *context)
{
    int flags = SOF_TIMESTAMPING_TX_HARDWARE |
                SOF_TIMESTAMPING_TX_SOFTWARE |
                SOF_TIMESTAMPING_RAW_HARDWARE;

    if (init_hwts(context) < 0)
        return -1;

    if (setsockopt(context->sock, SOL_SOCKET, SO_TIMESTAMPING,
                   &flags, sizeof flags) < 0) {
        err(1, "setsockopt(SO_TIMESTAMPING)");
    }


    printf("HWTS: setsockopt(SO_TIMESTAMPING) ok\n");

    flags = 1;
    if (setsockopt(context->sock, SOL_SOCKET, SO_SELECT_ERR_QUEUE,
                   &flags, sizeof flags) < 0) {
        err("setsockopt(SO_SELECT_ERR_QUEUE)");
    }
    printf("HWTS: setsockopt(SO_SELECT_ERR_QUEUE) ok\n");

    return 0;
}
#else
int init_timestamping(context_t *context)
{
    err(1, "hardware timestamping not supported");
}
#endif


int create_socket(context_t *context)
{
    struct in_addr *addr = NULL;

    context->sock = 0;
    if ((context->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        err(1, "socket");

    addr = &((struct sockaddr_in *) &context->ifaddr)->sin_addr;
    if (setsockopt(context->sock, IPPROTO_IP, IP_MULTICAST_IF,
                   addr, sizeof *addr) != 0) {
        err(1, "setsockopt(IPPROTO_IP, IP_MULTICAST_IF)");
    }

    if (context->args_info.hwts_flag) {
        if (init_timestamping(context) < 0)
            return -1;

        printf("hardware timestamp enabled\n");
    }

    if (context->args_info.dscp_given) {
        const int dscp = get_dscp(context->args_info.dscp_arg);
        const int tos = dscp << 2;

        printf("setting dscp value 0x%02x (tos 0x%02x)\n", dscp, tos);

        if (setsockopt(context->sock, IPPROTO_IP, IP_TOS,
                       &tos, sizeof tos) < 0) {
            err(1, "setsockopt(IPPROTO_IP, IP_TOS)");
        }
    }


    return context->sock;
}

uint64_t create_timestamp(void)
{
    struct timespec ts;

#ifdef __MACH__
    // https://gist.github.com/jbenet/1087739
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts.tv_sec = mts.tv_sec;
    ts.tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, &ts);
#endif

    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

void udpsend(const message_t *message)
{

}

#ifdef __linux__
int sk_receive(void *buf, int buflen, context_t *context)
{
    char control[256];
    int level, type;
    struct cmsghdr *cm;
    struct iovec iov = { buf, buflen };
    struct msghdr msg;
    struct timespec *sw, *ts = NULL;

    memset(control, 0, sizeof(control));
    memset(&msg, 0, sizeof(msg));

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct pollfd pfd = { context->sock, POLLPRI | POLLERR, 0 };
    int n = poll(&pfd, 1, POLL_TIMEOUT_MS);
    printf("poll returned %d\n", n);

    if (n < 0) {
        err(1, "poll for tx timestamp failed");
    } else if (n == 0) {
        errx(1, "timed out while polling for tx timestamp");
    } else if (!(pfd.revents & POLLPRI)) {
        errx(1, "poll for tx timestamp woke up on non ERR event");
    }

    n = recvmsg(context->sock, &msg, MSG_ERRQUEUE);
    if (n < 0)
        err(1, "recvmsg for tx timestamp");

    for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
        level = cm->cmsg_level;
        type  = cm->cmsg_type;
        if (SOL_SOCKET == level && SO_TIMESTAMPING == type) {
            if (cm->cmsg_len < sizeof(*ts) * 3) {
                warnx("short SO_TIMESTAMPING message");
                return -1;
            }
            ts = (struct timespec *) CMSG_DATA(cm);
        }
    }

    printf("timespec[0] = %lu.%u\n", ts[0].tv_sec, ts[0].tv_nsec);
    printf("timespec[1] = %lu.%u\n", ts[1].tv_sec, ts[1].tv_nsec);
    printf("timespec[2] = %lu.%u\n", ts[2].tv_sec, ts[2].tv_nsec);

    return n;
}
#else
int sk_receive(void *buf, int buflen, context_t *context)
{
    return 0;
}
#endif


void sendloop(context_t *context)
{
    struct sockaddr_in dst;
    socklen_t dstlen = sizeof dst;
    message_t message;
    unsigned char junk[1600];

    useconds_t delay = (useconds_t)context->args_info.delay_arg * 1000U;
    int n = 0;

    assert(sizeof message == 72);
    memset(&message, 0, sizeof message);

    if (context->verbose) {
        printf("count = %d\n", context->args_info.count_arg);
        printf("delay = %lums\n", (unsigned long)context->args_info.delay_arg);
        printf("identifier = \"%s\"\n", context->args_info.identifier_arg);
    }

    if (context->args_info.identifier_arg) {
        snprintf(message.data, sizeof message.data, "%s",
                 context->args_info.identifier_arg);
    }

    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr(BEACON_GROUP);
    dst.sin_port = htons(BEACON_PORT);

    for (;;) {
        message.seq++;
        message.timestamp = create_timestamp();

        if (sendto(context->sock, &message, sizeof message, 0,
                   (struct sockaddr *) &dst, dstlen) < 0)
            err(1, "sendto");

        if (context->args_info.hwts_flag) {
            sk_receive(junk, sizeof message, context);
        }

        if (context->args_info.count_arg != -1 &&
            context->args_info.count_arg == message.seq) {
            break;
        }

        usleep(delay);
    }
}

int main(int argc, char *argv[])
{
    context_t context = {};
    struct gengetopt_args_info *args_info = &context.args_info;

    if (cmdline_parser(argc, argv, args_info) != 0)
        exit(2);

    context.verbose = context.args_info.verbose_flag;

    if (get_interface(&context) < 0) {
        fprintf(stderr, "%s: did not find interface \"%s\"\n",
                __progname, context.args_info.interface_arg);
        exit(1);
    }

    printf("using interface %s: %s\n",
           context.ifname,
           inet_ntoa(((struct sockaddr_in *) &context.ifaddr)->sin_addr));

    if (create_socket(&context) < 0)
        exit(1);

    sendloop(&context);

    return 0;
}
