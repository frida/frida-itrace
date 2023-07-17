macos_cc := $(shell xcrun --sdk macosx -f clang)
macos_sdkroot := $(shell xcrun --sdk macosx --show-sdk-path)
cflags := -Wall -Werror -pipe -Oz -g
ldflags := -Wl,-dead_strip

all: itracebuffer.dylib itracebuffer_write.dylib itracebuffer_read.dylib

itracebuffer.dylib: itracebuffer.c
	$(macos_cc) \
		-isysroot $(macos_sdkroot) \
		-arch arm64 \
		$(cflags) \
		$< \
		-o $@ \
		-dynamiclib \
		$(ldflags)

%.dylib: %.s
	$(macos_cc) \
		-isysroot $(macos_sdkroot) \
		-arch arm64 \
		-shared \
		-o $@ \
		$<

.PHONY: all
