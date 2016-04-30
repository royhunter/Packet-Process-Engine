TOP=.
include $(TOP)/mk/env.mk
export PROJ_DIR=$(PWD)


################DIRS##################
SRV_DIRS = $(TOP)/src/srv/srvcore
SRV_DIRS += $(TOP)/src/srv/srvnet
SRV_DIRS += $(TOP)/src/srv/srvpow
CLIENT_DIRS = $(TOP)/src/client
COMMON_DIRS = $(TOP)/src/common
IPC_DIRS = $(TOP)/../ipc

SRC_DIRS = $(SRV_DIRS) $(CLIENT_DIRS) $(COMMON_DIRS) $(IPC_DIRS)

################PROGS USE LOCAL LIBS##################
COMMON_LDFLAGS = $(TOP)/lib/libcommon.a

PROG_SRV_LDFLAGS = $(TOP)/lib/libsrvcore.a
PROG_SRV_LDFLAGS += $(TOP)/lib/libsrvnet.a
PROG_SRV_LDFLAGS += $(TOP)/lib/libsrvpow.a
PROG_SRV_LDFLAGS += $(TOP)/lib/libipc.a
PROG_SRV_LDFLAGS += $(COMMON_LDFLAGS)


PROG_CLIENT_LDFLAGS = $(TOP)/lib/libclient.a
PROG_CLIENT_LDFLAGS += $(COMMON_LDFLAGS)

################PROGS##################
PROGS = $(TOP)/bin/srv  $(TOP)/bin/cli 

export PROG_SRV_LDFLAGS PROG_CLIENT_LDFLAGS


all: $(SRC_DIRS) $(PROGS) 


$(SRC_DIRS):
	@mkdir -p $(TOP)/bin $(TOP)/lib
	$(Q) $(MAKE) $(MAKE_DEBUG) --directory=$@

$(TOP)/bin/srv: $(SRV_DIRS)
	$(Q) $(MAKE) $(MAKE_DEBUG) -f $(TOP)/mk/prog.mk srv
	
$(TOP)/bin/cli: $(CLIENT_DIRS)
	$(Q) $(MAKE) $(MAKE_DEBUG) -f $(TOP)/mk/prog.mk cli


.PHONY: all $(SRC_DIRS) clean



clean:
	$(Q) for d in $(SRC_DIRS); \
	do \
	$(MAKE) clean --directory=$$d; \
	done \
 
	$(Q) -rm -f $(PROGS)


