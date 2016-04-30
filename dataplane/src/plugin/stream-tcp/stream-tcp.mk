#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_STREAMTCP := $(OBJ_DIR)/streamtcp.a


LIBSTREAMTCP_OBJ_$(d)  :=  \
	$(OBJ_DIR)/stream-tcp.o \
	$(OBJ_DIR)/stream-tcp-reassemble.o \
	$(OBJ_DIR)/stream-tcp-session.o  \
	$(OBJ_DIR)/stream-tcp-segment.o
	

INCLUDE_DIR := \
	-I$(d) \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/decode \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/include \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/platform \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/flow \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/output \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/attack \
	-I$(OCTEON_ROOT)/sec-fw/include

	

$(LIBSTREAMTCP_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Wundef -G0 $(INCLUDE_DIR)
$(LIBSTREAMTCP_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL))	


#  standard component Makefile rules

LIBSTREAMTCP_DEPS_$(d)   :=  $(LIBSTREAMTCP_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_STREAMTCP)

LIBSTREAMTCP_CLEAN_LIST  :=  $(LIBSTREAMTCP_CLEAN_LIST) $(LIBSTREAMTCP_OBJ_$(d)) $(LIBSTREAMTCP_DEPS_$(d)) $(LIBRARY_STREAMTCP)

-include $(LIBSTREAMTCP_DEPS_$(d))

$(LIBRARY_STREAMTCP): $(LIBSTREAMTCP_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o:	$(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))