#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_ACL := $(OBJ_DIR)/libacl.a


LIBACL_OBJ_$(d)  :=  \
    $(OBJ_DIR)/dp_acl.o \
	$(OBJ_DIR)/acl64.o
#    $(OBJ_DIR)/acl.o
    

INCLUDE_DIR := \
    -I$(d) \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/include \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/decode \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/platform \
    -I$(OCTEON_ROOT)/sec-fw/include
    


$(LIBACL_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Wundef -G0 $(INCLUDE_DIR)
$(LIBACL_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL))    


#  standard component Makefile rules

LIBACL_DEPS_$(d)   :=  $(LIBACL_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_ACL)

LIBACL_CLEAN_LIST  :=  $(LIBACL_CLEAN_LIST) $(LIBACL_OBJ_$(d)) $(LIBACL_DEPS_$(d)) $(LIBRARY_ACL)

-include $(LIBACL_DEPS_$(d))

$(LIBRARY_ACL): $(LIBACL_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o: $(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o: $(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))