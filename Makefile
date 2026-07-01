SC_BYPASS_VERSION := 0.5.1

ifndef KP_DIR
KP_DIR = ../_refs/selinux_hook/KernelPatch
endif

OS_NAME = $(shell uname | tr A-Z a-z)
MACHINE = $(shell uname -m)
NDK_BIN_DIR := toolchains/llvm/prebuilt/$(OS_NAME)-$(MACHINE)/bin

NDK_PATH =
ifdef ANDROID_NDK_LATEST_HOME
NDK_PATH = $(ANDROID_NDK_LATEST_HOME)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK
NDK_PATH = $(ANDROID_NDK)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK_HOME
NDK_PATH = $(ANDROID_NDK_HOME)/$(NDK_BIN_DIR)
endif

CC =
LD =
OBJCOPY =
ifdef TARGET_COMPILE
CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld
OBJCOPY = $(TARGET_COMPILE)objcopy
else ifdef NDK_PATH
CC = $(NDK_PATH)/aarch64-linux-android31-clang
LD = $(NDK_PATH)/ld.lld
OBJCOPY = $(NDK_PATH)/llvm-objcopy
endif

CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-stack-protector -fno-common -std=gnu99
CFLAGS += -DMODULE_VERSION=\"$(SC_BYPASS_VERSION)\"

INCLUDE_DIRS := . include patch/include linux linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := sidechannel_bypass.o

all: sidechannel_bypass_$(SC_BYPASS_VERSION).kpm

sidechannel_bypass_$(SC_BYPASS_VERSION).kpm: ${objs}
	$(CC) -r -nostdlib -o $@.tmp $^
	if [ -n "$(OBJCOPY)" ]; then $(OBJCOPY) --remove-section=.comment --remove-section=.note.GNU-stack $@.tmp $@; else mv $@.tmp $@; fi

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

clean:
	rm -rf *.kpm *.kpm.tmp *.o

.PHONY: all clean
