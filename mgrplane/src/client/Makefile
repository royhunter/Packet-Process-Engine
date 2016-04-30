TOP=../..
include $(TOP)/mk/env.mk

DIR=client
TARGET=$(TOP)/lib/lib$(DIR).a
BUILD_DIR=$(TOP)/build/$(DIR)

SOURCES:=$(Y_SOURCES) $(L_SOURCES)
SOURCES+=$(wildcard *.c) cparser_tree.c

OBJS:=$(addprefix $(BUILD_DIR)/,$(subst .c,.o,$(SOURCES)))
DEPS:=$(addprefix $(BUILD_DIR)/,$(subst .c,.d,$(SOURCES)))

PROJ_CFLAGS += -I.  -I$(TOP)/src/common  -I$(TOP)/../include

CLI_FLAGS += -D TEST_LABEL1

.PHONY: all clean


all:$(TARGET)


include $(TOP)/mk/rule.mk


cparser_tree.c: sec-fw.cli rule_included.cli octeon_included.cli firewall_included.cli
	./mk_parser.py $(CLI_FLAGS) sec-fw.cli