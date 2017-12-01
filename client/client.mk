# Experimental client requires libedit

ifeq ($(HAS_libedit), yes)
kresc_SOURCES := client/kresc.c
kresc_CFLAGS += -fPIE $(libedit_CFLAGS)
kresc_LIBS += $(contrib_TARGET) $(libedit_LIBS)
kresc_DEPEND := $(libkres) $(contrib)
$(eval $(call make_sbin,kresc,client,yes))
client: $(kresc)
client-install: kresc-install
client-clean: kresc-clean

.PHONY: client client-install client-clean
endif
