#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_IPC := $(OBJ_DIR)/libipc.a


LIBIPC_OBJ_$(d)  :=  \
	$(OBJ_DIR)/msgque.o
	

INCLUDE_DIR := \
	-I$(d) \
	-I$(OCTEON_ROOT)/sec-fw/include

	

$(LIBIPC_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Wundef -G0 $(INCLUDE_DIR)
$(LIBIPC_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL))	


#  standard component Makefile rules

LIBIPC_DEPS_$(d)   :=  $(LIBIPC_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_IPC)

LIBIPC_CLEAN_LIST  :=  $(LIBIPC_CLEAN_LIST) $(LIBIPC_OBJ_$(d)) $(LIBIPC_DEPS_$(d)) $(LIBRARY_IPC)

-include $(LIBIPC_DEPS_$(d))

$(LIBRARY_IPC): $(LIBIPC_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o:	$(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))