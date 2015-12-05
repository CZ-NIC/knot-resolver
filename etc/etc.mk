etc_SOURCES := icann-ca.pem

etc-install: etcdir
	$(INSTALL) -m 0640 $(addprefix etc/,$(etc_SOURCES)) $(PREFIX)/$(ETCDIR)

.PHONY: etc-install
