$(TARGET):$(OBJS)
	@echo [AR] $(notdir $@)
	$(Q) $(AR) cr $@ $(OBJS)


$(BUILD_DIR)/%.o:%.c
	@echo [CC] $(notdir $@)
	$(Q) mkdir -p $(@D)
	$(Q) $(CC) -o $@ $(CFLAGS) -c $<
	
$(BUILD_DIR)/%.d:%.c
	@echo [DEP] $(notdir $@)
	$(Q) mkdir -p $(@D)
	$(Q) $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	sed -n "H;$$ {g;s@\(.*\)\.o[ :]\(.*\)@$(BUILD_DIR)/$*.o $@: \$$\(wildcard\2\)@;p}" < $@.$$$$ > $@; \
	rm -f $@.$$$$	
	

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif	
	
clean:
	-rm -rf $(BUILD_DIR)/* $(TARGET)