dnstap_CFLAGS := -fvisibility=hidden -fPIC
dnstap_SOURCES := modules/dnstap/dnstap.pb-c.c modules/dnstap/dnstap.c
dnstap_DEPEND := $(libkres) modules/dnstap/dnstap.pb-c.c # because of generated *.h
dnstap_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS) $(libprotobuf-c_LIBS) $(libfstrm_LIBS)
$(call make_c_module,dnstap)

modules/dnstap/dnstap.pb-c.c: modules/dnstap/dnstap.proto
	protoc-c $< --c_out=.
