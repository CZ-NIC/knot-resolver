# Config
deckard_DIR := tests/deckard
TESTS := sets/resolver
TEMPLATE := template/kresd.j2

# Synchronize submodules
$(deckard_DIR):
	@git submodule update --init

# Test using Deckard
deckard: check-integration
check-integration: $(deckard_DIR)
	make -C $(deckard_DIR) TESTS=$(TESTS) DAEMON=$(abspath daemon/kresd) TEMPLATE=$(TEMPLATE)

.PHONY: deckard check-integration
