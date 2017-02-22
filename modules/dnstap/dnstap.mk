dnstap_CFLAGS := -fvisibility=hidden -fPIC
dnstap_SOURCES := modules/dnstap/dnstap.c modules/dnstap/dnstap.pb-c.c
dnstap_DEPEND := $(libkres)
dnstap_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS) $(libprotobuf-c_LIBS) $(libfstrm_LIBS)
$(call make_c_module,dnstap)

modules/dnstap/dnstap.pb-c.c: modules/dnstap/dnstap.proto
	protoc-c $< --c_out=.
dnstap-clean-extra:
	@$(call quiet,RM,modules/dnstap/dnstap.pb-c.*) modules/dnstap/dnstap.pb-c.*
dnstap-clean: dnstap-clean-extra
.PHONY: dnstap-clean-extra
