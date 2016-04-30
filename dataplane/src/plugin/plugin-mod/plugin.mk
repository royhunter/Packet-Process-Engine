#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_L7 := $(OBJ_DIR)/libl7.a


LIBL7_OBJ_$(d)  :=  \
	$(OBJ_DIR)/l7.o		\
	$(OBJ_DIR)/l7-util-hashlist.o		\
	$(OBJ_DIR)/l7-dcerpc.o					\
	$(OBJ_DIR)/l7-dcerpc-comm.o			\
	$(OBJ_DIR)/l7-dcerpc-opc.o
	

INCLUDE_DIR := \
	-I$(d) \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/decode \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/include \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/platform \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/flow \
	-I$(OCTEON_ROOT)/sec-fw/include

	

$(LIBL7_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Wundef -G0 $(INCLUDE_DIR)
$(LIBL7_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL))	


#  standard component Makefile rules

LIBL7_DEPS_$(d)   :=  $(LIBL7_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_L7)

LIBL7_CLEAN_LIST  :=  $(LIBL7_CLEAN_LIST) $(LIBL7_OBJ_$(d)) $(LIBL7_DEPS_$(d)) $(LIBRARY_L7)

-include $(LIBL7_DEPS_$(d))

$(LIBRARY_L7): $(LIBL7_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o:	$(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))