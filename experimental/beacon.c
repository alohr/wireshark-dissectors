#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#else
#endif

#include "cmdline.h"

extern const char *__progname;

#define BEACON_GROUP "239.0.0.1"
#define BEACON_PORT 4000

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
    struct sockaddr ifaddr;

} context_t;


int get_interface(context_t *context)
{
    struct ifaddrs *ifaddrs, *ifa;
    int match = -1;

    if (getifaddrs(&ifaddrs) < 0) {
        perror("getifaddrs");
    }

    ifa = ifaddrs;
    while (ifa != NULL) {
        if (ifa->ifa_addr->sa_family == AF_INET) {
            if (context->verbose) {
                printf("%s: %s\n",
                       ifa->ifa_name,
                       inet_ntoa(((struct sockaddr_in *) ifa->ifa_addr)->sin_addr));
            }
            if (strcmp(context->args_info.interface_arg, ifa->ifa_name) == 0) {
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

int create_socket(context_t *context)
{
    struct in_addr *addr;

    context->sock = 0;

    if ((context->sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    addr = &((struct sockaddr_in *) &context->ifaddr)->sin_addr;
    if (setsockopt(context->sock, IPPROTO_IP, IP_MULTICAST_IF,
                   addr, sizeof *addr) != 0) {
        perror("setsockopt");
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

void sendloop(context_t *context)
{
    struct sockaddr_in dst;
    socklen_t dstlen = sizeof dst;
    message_t message;
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

    memset(&dst, 9, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr(BEACON_GROUP);
    dst.sin_port = htons(BEACON_PORT);

    for (;;) {
        message.seq++;
        message.timestamp = create_timestamp();

        n = sendto(context->sock, &message, sizeof message, 0,
                   (struct sockaddr *) &dst, dstlen);
        if (n < 0) {
 	    perror("sendto");
	    exit(1);
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
           context.args_info.interface_arg,
           inet_ntoa(((struct sockaddr_in *) &context.ifaddr)->sin_addr));

    if (create_socket(&context) < 0)
        exit(1);

    sendloop(&context);

    return 0;
}
