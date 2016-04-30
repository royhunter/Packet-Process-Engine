TOP=../mgrplane
include $(TOP)/mk/env.mk


DIR=ipc
TARGET=$(TOP)/lib/lib$(DIR).a
BUILD_DIR=$(TOP)/build/$(DIR)
SOURCES:=$(wildcard *.c)
OBJS:=$(addprefix $(BUILD_DIR)/,$(subst .c,.o,$(SOURCES)))
DEPS:=$(addprefix $(BUILD_DIR)/,$(subst .c,.d,$(SOURCES)))

PROJ_CFLAGS += -I.  -I$(TOP)/../include

.PHONY: all clean

all:$(TARGET)

include $(TOP)/mk/rule.mk
