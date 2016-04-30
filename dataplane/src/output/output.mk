#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_OUTPUT := $(OBJ_DIR)/liboutput.a


LIBOUTPUT_OBJ_$(d)  :=  \
	$(OBJ_DIR)/output.o
	

INCLUDE_DIR := \
	-I$(d) \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/decode \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/include \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/platform \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/flow \
	-I$(OCTEON_ROOT)/sec-fw/include

	

$(LIBOUTPUT_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Wundef -G0 $(INCLUDE_DIR)
$(LIBOUTPUT_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL))	


#  standard component Makefile rules

LIBOUTPUT_DEPS_$(d)   :=  $(LIBOUTPUT_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_OUTPUT)

LIBOUTPUT_CLEAN_LIST  :=  $(LIBOUTPUT_CLEAN_LIST) $(LIBOUTPUT_OBJ_$(d)) $(LIBOUTPUT_DEPS_$(d)) $(LIBRARY_OUTPUT)

-include $(LIBOUTPUT_DEPS_$(d))

$(LIBRARY_OUTPUT): $(LIBOUTPUT_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o:	$(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))