etc_SOURCES := icann-ca.pem \
	config.cluster \
	config.isp \
	config.personal \
	config.splitview

etc-install: $(DESTDIR)$(ETCDIR)
	$(INSTALL) -m 0640 $(addprefix etc/,$(etc_SOURCES)) $(DESTDIR)$(ETCDIR)

.PHONY: etc-install
