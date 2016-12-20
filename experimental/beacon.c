#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#define BEACON_GROUP "239.0.0.1"
#define BEACON_PORT 4000

#pragma pack(push, 1)
typedef struct {
    uint32_t seq;
    uint64_t timestamp;
} message_t;
#pragma pack(pop)

int create_socket(void)
{
    int sock = 0;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    return sock;
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

void sendloop(int sock)
{
    struct sockaddr_in dst;
    socklen_t dstlen = sizeof dst;
    message_t message = { 0, 0 };
    int n = 0;

    assert(sizeof message == 12);

    memset(&dst, 9, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr(BEACON_GROUP);
    dst.sin_port = htons(BEACON_PORT);

    for (;;) {
        message.seq++;
        message.timestamp = create_timestamp();

        n = sendto(sock, &message, sizeof message, 0,
                   (struct sockaddr *) &dst, dstlen);
        if (n < 0) {
 	    perror("sendto");
	    exit(1);
        }
        // 100ms
        usleep(100000);
    }
}

int main(int argc, char *argv[])
{
    int sock = 0;

    sock = create_socket();

    sendloop(sock);
    
    return 0;
}
