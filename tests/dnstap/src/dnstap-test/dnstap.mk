# dnstap tests
GOPATH := $(abspath tests/dnstap)
DNSTAP_TEST := dnstap-test
DNSTAP_PATH := $(GOPATH)/src/$(DNSTAP_TEST)
CONFIG := $(DNSTAP_PATH)/config
CMD := daemon/kresd
ZONES := "fake1.localdomain,fake2.localdomain,fake3.localdomain"
TIMEOUT := 60s
check-dnstap: daemon
	@echo "Checking dnstap functionality"
	GOPATH=$(GOPATH) go get -u github.com/FiloSottile/gvt
	cd $(DNSTAP_PATH) && $(GOPATH)/bin/gvt restore
	GOPATH=$(GOPATH) go install $(DNSTAP_TEST)
	$(GOPATH)/bin/$(DNSTAP_TEST) -c $(CONFIG) -cmd $(CMD) -q $(ZONES) -t $(TIMEOUT)

clean-dnstap:
	rm -rf $(GOPATH)/bin $(GOPATH)/pkg

.PHONY: check-dnstap clean-dnstap
