CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra
CFLAGS += -I./asn/asn1c -I./asn/ngap -ffunction-sections -fdata-sections
LDFLAGS ?= -Wl,--gc-sections

# converter-example.c is the optional asn1c demo and intentionally has no PDU.
ASN1C_SRCS := $(filter-out asn/asn1c/converter-example.c,$(wildcard asn/asn1c/*.c))
NGAP_SRCS  := $(wildcard asn/ngap/*.c)
OBJS := $(ASN1C_SRCS:.c=.o) $(NGAP_SRCS:.c=.o) main.o

.PHONY: all clean
all: encode_ngsetup

encode_ngsetup: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f encode_ngsetup main.o $(OBJS)
