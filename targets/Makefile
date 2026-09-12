CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra

.PHONY: all clean
all: dummy sctp_send

dummy: dummy.c
	$(CC) $(CFLAGS) -o $@ $<

sctp_send: sctp_send.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f dummy sctp_send
