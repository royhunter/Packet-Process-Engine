#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_RULE := $(OBJ_DIR)/librule.a


LIBRULE_OBJ_$(d)  :=  \
	$(OBJ_DIR)/rule.o
	

INCLUDE_DIR := \
	-I$(d) \
	-I$(OCTEON_ROOT)/sec-fw/include

	

$(LIBRULE_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Wundef -G0 $(INCLUDE_DIR)
$(LIBRULE_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL))	


#  standard component Makefile rules

LIBRULE_DEPS_$(d)   :=  $(LIBRULE_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_RULE)

LIBRULE_CLEAN_LIST  :=  $(LIBRULE_CLEAN_LIST) $(LIBRULE_OBJ_$(d)) $(LIBRULE_DEPS_$(d)) $(LIBRARY_RULE)

-include $(LIBRULE_DEPS_$(d))

$(LIBRARY_RULE): $(LIBRULE_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o:	$(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))