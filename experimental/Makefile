DEBUGFLAGS = -g
CFLAGS = $(DEBUGFLAGS) -Wall
LDFLAGS = $(DEBUGFLAGS)

GENGETOPT = /usr/local/bin/gengetopt

SRCS = beacon.c
OBJS = cmdline.o $(SRCS:.c=.o)

LIBS = -lpcap

PROG = beacon 

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

all:: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

cmdline.c: beacon.ggo
	$(GENGETOPT) < $<

cmdline.o: cmdline.c

clean::
	/bin/rm -f $(PROG) $(OBJS) core *~

