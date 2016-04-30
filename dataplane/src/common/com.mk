#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_COMMON := $(OBJ_DIR)/libcommon.a


LIBCOMMON_OBJ_$(d)  :=  \
	$(OBJ_DIR)/dp_cmd.o \
	$(OBJ_DIR)/mbuf.o \
	$(OBJ_DIR)/watchdog.o \
	$(OBJ_DIR)/sos_malloc.o \
	$(OBJ_DIR)/dp_log.o
    

INCLUDE_DIR := \
	-I$(d) \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/include \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/decode \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/platform \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/plugin/stream-tcp \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/flow \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/acl \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/attack \
    -I$(OCTEON_ROOT)/sec-fw/include
    


$(LIBCOMMON_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Wundef -G0 $(INCLUDE_DIR)
$(LIBCOMMON_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL)) 


#  standard component Makefile rules

LIBCOMMON_DEPS_$(d)   :=  $(LIBCOMMON_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_COMMON)

LIBCOMMON_CLEAN_LIST  :=  $(LIBCOMMON_CLEAN_LIST) $(LIBCOMMON_OBJ_$(d)) $(LIBCOMMON_DEPS_$(d)) $(LIBRARY_COMMON)

-include $(LIBCOMMON_DEPS_$(d))

$(LIBRARY_COMMON): $(LIBCOMMON_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o: $(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o: $(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))