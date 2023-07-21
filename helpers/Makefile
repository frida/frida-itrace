ios_cc := $(shell xcrun --sdk iphoneos -f clang)
ios_sdkroot := $(shell xcrun --sdk iphoneos --show-sdk-path)
cflags := -Wall -Werror -pipe -Oz -g
ldflags := -Wl,-dead_strip

all: itracebuffer.dylib itracebuffer_write.dylib itracebuffer_read.dylib

itracebuffer.dylib: itracebuffer.c
	$(ios_cc) \
		-isysroot $(ios_sdkroot) \
		-arch arm64 \
		$(cflags) \
		$< \
		-o $@ \
		-dynamiclib \
		$(ldflags)

%.dylib: %.s
	$(ios_cc) \
		-isysroot $(ios_sdkroot) \
		-arch arm64 \
		-shared \
		-o $@ \
		$<

.PHONY: all
