#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_ROUTE := $(OBJ_DIR)/libroute.a


LIBROUTE_OBJ_$(d)  :=  \
    $(OBJ_DIR)/route.o 
    

INCLUDE_DIR := \
    -I$(d) \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/include \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/decode \
    -I$(OCTEON_ROOT)/sec-fw/dataplane/src/platform \
    -I$(OCTEON_ROOT)/sec-fw/include
    


$(LIBROUTE_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Wundef -G0 $(INCLUDE_DIR)
$(LIBROUTE_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL))    


#  standard component Makefile rules

LIBROUTE_DEPS_$(d)   :=  $(LIBROUTE_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_ROUTE)

LIBROUTE_CLEAN_LIST  :=  $(LIBROUTE_CLEAN_LIST) $(LIBROUTE_OBJ_$(d)) $(LIBROUTE_DEPS_$(d)) $(LIBRARY_ROUTE)

-include $(LIBROUTE_DEPS_$(d))

$(LIBRARY_ROUTE): $(LIBROUTE_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o: $(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o: $(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))