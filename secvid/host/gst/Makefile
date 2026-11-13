CC         ?= $(CROSS_COMPILE)gcc
PKG_CONFIG ?= pkg-config

GST_PKGS = gstreamer-1.0 gstreamer-base-1.0 gstreamer-allocators-1.0

OBJS = gstsecvid.o secvid_tee.o

CFLAGS += -Wall -fPIC -I../../ta/include -I$(TEEC_EXPORT)/include
CFLAGS += $(shell $(PKG_CONFIG) --cflags $(GST_PKGS))
LDADD += -lteec -L$(TEEC_EXPORT)/lib $(shell $(PKG_CONFIG) --libs $(GST_PKGS))

LIBRARY = libgstsecvid.so

.PHONY: all
all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	$(CC) -shared $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

secvid_tee.o: ../secvid_tee.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(LIBRARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
