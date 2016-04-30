include $(PROJ_DIR)/mk/env.mk
TOP = ..


PROG_SRV_LDFLAGS += -lrt -lpthread

srv:FORCE
	@echo [LD] $@
	$(Q) $(CC) -o $(PROJ_DIR)/bin/$@ $(PROG_SRV_LDFLAGS) 


PROG_CLIENT_LDFLAGS += 

cli:FORCE
	@echo [LD] $@
	$(Q) $(CC) -o $(PROJ_DIR)/bin/$@ $(PROG_CLIENT_LDFLAGS)



.PHONY:srv cli FORCE