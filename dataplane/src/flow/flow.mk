#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_FLOW := $(OBJ_DIR)/libflow.a


LIBFLOW_OBJ_$(d)  :=  \
	$(OBJ_DIR)/flow.o
	

INCLUDE_DIR := \
	-I$(d) \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/decode \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/include \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/platform \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/acl \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/common \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/output \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/attack \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/plugin/stream-tcp \
	-I$(OCTEON_ROOT)/sec-fw/include

	

$(LIBFLOW_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Wundef -G0 $(INCLUDE_DIR)
$(LIBFLOW_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL))	


#  standard component Makefile rules

LIBFLOW_DEPS_$(d)   :=  $(LIBFLOW_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_FLOW)

LIBFLOW_CLEAN_LIST  :=  $(LIBFLOW_CLEAN_LIST) $(LIBFLOW_OBJ_$(d)) $(LIBFLOW_DEPS_$(d)) $(LIBRARY_FLOW)

-include $(LIBFLOW_DEPS_$(d))

$(LIBRARY_FLOW): $(LIBFLOW_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o:	$(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))