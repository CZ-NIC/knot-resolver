etc_SOURCES := icann-ca.pem \
	config.cluster \
	config.isp \
	config.personal \
	config.splitview \
	root.hints

etc-install: $(DESTDIR)$(ETCDIR)
	$(INSTALL) -m 0640 $(addprefix etc/,$(etc_SOURCES)) $(DESTDIR)$(ETCDIR)

etc: etc/root.hints

etc/root.hints:
	wget -O $@  https://www.internic.net/domain/named.root

.PHONY: etc-install
