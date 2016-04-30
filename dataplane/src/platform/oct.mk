#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)



#  component specification

LIBRARY_PLATFORM := $(OBJ_DIR)/libplatform.a


LIBPLATFORM_OBJ_$(d)  :=  \
	$(OBJ_DIR)/oct-rxtx.o \
	$(OBJ_DIR)/oct-init.o \
	$(OBJ_DIR)/mem_pool.o \
	$(OBJ_DIR)/oct-sched.o \
	$(OBJ_DIR)/oct-time.o \
	$(OBJ_DIR)/oct-thread.o

INCLUDE_DIR := \
	-I$(d) \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/include \
	-I$(OCTEON_ROOT)/sec-fw/dataplane/src/decode \
	-I$(OCTEON_ROOT)/sec-fw/include

	

$(LIBPLATFORM_OBJ_$(d)):  CFLAGS_LOCAL := -O2 -g -W -Wall -Werror -Wno-unused-parameter -Werror -Wundef -G0 $(INCLUDE_DIR)
$(LIBPLATFORM_OBJ_$(d)):  CFLAGS_GLOBAL := $(filter-out -fprofile-%,$(CFLAGS_GLOBAL))	


#  standard component Makefile rules

LIBPLATFORM_DEPS_$(d)   :=  $(LIBPLATFORM_OBJ_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY_PLATFORM)

LIBPLATFORM_CLEAN_LIST  :=  $(LIBPLATFORM_CLEAN_LIST) $(LIBPLATFORM_OBJ_$(d)) $(LIBPLATFORM_DEPS_$(d)) $(LIBRARY_PLATFORM)

-include $(LIBPLATFORM_DEPS_$(d))

$(LIBRARY_PLATFORM): $(LIBPLATFORM_OBJ_$(d))
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)


$(OBJ_DIR)/%.o:	$(d)/%.S
	$(ASSEMBLE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))