#
#  secd Makefile
#
  
#

memory=384
uart=2020
packet_port=2000
linux_path=${OCTEON_ROOT}/linux

kernel=-ld0x11000000:${linux_path}/kernel/linux/vmlinux.64
filesystem=-ld0x40000000:${linux_path}/embedded_rootfs/rootfs.ext2

#  default target

default: application-target

#  standard common Makefile fragment

include $(OCTEON_ROOT)/common.mk

#  include needed component Makefile fragments




dir := $(OCTEON_ROOT)/sec-fw/dataplane/src/decode
include $(dir)/decode.mk

dir := $(OCTEON_ROOT)/sec-fw/dataplane/src/flow
include $(dir)/flow.mk

dir := $(OCTEON_ROOT)/sec-fw/dataplane/src/L7
include $(dir)/l7.mk

dir := $(OCTEON_ROOT)/sec-fw/dataplane/src/common
include $(dir)/com.mk

dir := $(OCTEON_ROOT)/sec-fw/dataplane/src/acl
include $(dir)/acl.mk

dir := $(OCTEON_ROOT)/sec-fw/dataplane/src/route
include $(dir)/route.mk

dir := $(OCTEON_ROOT)/sec-fw/dataplane/src/attack
include $(dir)/attack.mk

dir := $(OCTEON_ROOT)/sec-fw/dataplane/src/plugin/stream-tcp
include $(dir)/stream-tcp.mk

dir := $(OCTEON_ROOT)/sec-fw/dataplane/src/output
include $(dir)/output.mk

dir := $(OCTEON_ROOT)/sec-fw/ipc
include $(dir)/ipc.mk

dir := $(OCTEON_ROOT)/sec-fw/rule
include $(dir)/rule.mk

dir := $(OCTEON_ROOT)/sec-fw/dataplane/src/platform
include $(dir)/oct.mk

dir := $(OCTEON_ROOT)/executive
include $(dir)/cvmx.mk



#  application specification

TARGET := secd$(PREFIX)

OBJS = $(OBJ_DIR)/main.o

INCLUDE_DIR := \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/include \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/decode \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/acl \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/platform \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/flow \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/common \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/L7 \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/plugin/stream-tcp \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/route \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/attack \
	-I$(OCTEON_ROOT)/sec-fw/include



CFLAGS_LOCAL = -g -O2 -W -Wall -Wno-unused-parameter $(INCLUDE_DIR) -lpthread



include $(OCTEON_ROOT)/application.mk

#  clean target

clean:
	rm -f $(TARGET) config/cvmx-config.h
	rm -fr $(OBJ_DIR)

run: $(TARGET)
	oct-sim $(TARGET) ${kernel} ${filesystem} -envfile=u-boot-env -memsize=${memory} -uart0=${uart} -serve=${packet_port} -quiet -noperf -numcores=2

