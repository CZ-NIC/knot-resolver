doc-doxygen:
	@cd doc && $(doxygen_BIN) 
doc-html: doc-doxygen
	@cd doc && $(sphinx-build_BIN) -b html . html
doc-clean:
	@rm -rf doc/doxyxml doc/*.db doc/html

.PHONY: doc-doxygen doc-html doc-clean

