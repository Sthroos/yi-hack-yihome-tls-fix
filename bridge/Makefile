# Normally driven by build.sh. Manual use:
#   make CC=arm-linux-gnueabihf-gcc MBEDTLS=/path/to/mbedtls MBEDTLS_LIB=/path/to/libs
MBEDTLS     ?= ../build/mbedtls
MBEDTLS_LIB ?= $(MBEDTLS)/library
CC          ?= cc
CFLAGS      ?= -Os -Wall -Wextra -Werror -ffunction-sections -fdata-sections
LDFLAGS     ?= -static -Wl,--gc-sections -s
INC          = -I$(MBEDTLS)/include -DMBEDTLS_USER_CONFIG_FILE='"$(CURDIR)/config/mbedtls_user_config.h"'
LIBS         = $(MBEDTLS_LIB)/libmbedtls.a $(MBEDTLS_LIB)/libmbedx509.a $(MBEDTLS_LIB)/libmbedcrypto.a

yi-tls-bridge: src/yi-tls-bridge.c config/mbedtls_user_config.h
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LIBS) $(LDFLAGS)

clean:
	rm -f yi-tls-bridge
.PHONY: clean
