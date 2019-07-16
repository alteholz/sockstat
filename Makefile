SRCS = sockstat.c
OBJS = ${SRCS:.c=.o}

sockstat: ${OBJS}
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) ${OBJS}

install:
	install -m 755 -c sockstat ${DESTDIR}/usr/bin

clean:
	rm -f *.o sockstat

distclean: clean

all: sockstat
build: sockstat
