CFLAGS = -g -Wall

GENGETOPT = /usr/bin/gengetopt

SRCS = beacon.c
OBJS = cmdline.o $(SRCS:.c=.o)

LIBS = -lpcap

PROG = beacon 

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

.cpp.o:
	$(CXX) -c $(CXXFLAGS) -o $@ $<

all:: $(PROG)

$(PROG): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

cmdline.c: beacon.ggo
	$(GENGETOPT) < $<

cmdline.o: cmdline.c

clean::
	/bin/rm -f $(OBJS) *~

