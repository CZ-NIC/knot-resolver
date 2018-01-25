ifeq ($(HAS_doxygen)|$(HAS_sphinx-build), yes|yes)
doc-doxygen:
	@cd doc && $(doxygen_BIN)
doc-html: doc-doxygen
	@cd doc && $(sphinx-build_BIN) $(SPHINXFLAGS) -b html . html
else
doc-html:
	$(error doxygen and sphinx must be installed)
endif
doc-clean:
	rm -rf doc/doxyxml doc/*.db doc/html

.PHONY: doc-doxygen doc-html doc-clean

