#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_ATTACK := $(OBJ_DIR)/libattack.a


LIBATTACK_OBJ_$(d)  :=  \
    $(OBJ_DIR)/dp_attack.o \
	$(OBJ_DIR)/dp_portscan.o
    

INCLUDE_DIR := \
    -I$(d) \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/include \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/decode \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/platform \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/common \
    -I$(OCTEON_ROOT)/sec-fw/include
    


$(LIBATTACK_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Wundef -G0 $(INCLUDE_DIR)
$(LIBATTACK_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL))    


#  standard component Makefile rules

LIBATTACK_DEPS_$(d)   :=  $(LIBATTACK_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_ATTACK)

LIBATTACK_CLEAN_LIST  :=  $(LIBATTACK_CLEAN_LIST) $(LIBATTACK_OBJ_$(d)) $(LIBATTACK_DEPS_$(d)) $(LIBRARY_ATTACK)

-include $(LIBATTACK_DEPS_$(d))

$(LIBRARY_ATTACK): $(LIBATTACK_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o: $(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o: $(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))