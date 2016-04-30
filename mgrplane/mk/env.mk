PLATFORM = MIPS



ifeq ($(PLATFORM), HOST)
	CROSS_COMPILE =
else
	CROSS_COMPILE = mips64-octeon-linux-gnu-
endif


CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CROSS_COMPILE)ld
STRIP = $(CROSS_COMPILE)strip
OBJDUMP = $(CROSS_COMPILE)objdump
NM = $(CROSS_COMPILE)nm


BUILD_VERBOSE = n
DEBUG_VERSION = y

ifeq ($(BUILD_VERBOSE),y)
    Q =
	MAKE_DEBUG = 
else
    Q = @
	MAKE_DEBUG = -s
endif

ifeq ($(DEBUG_VERSION),y)
    DEBUG_FLAGS = -g
else
    DEBUG_FLAGS = -Os
endif



PROJ_CFLAGS = -I$(TOP)/include  -I$(TOP)/src/common/include


CFLAGS += $(DEBUG_FLAGS) -Wall -Werror $(PROJ_CFLAGS)






