dnstap_CFLAGS := -fvisibility=hidden -fPIC
dnstap_SOURCES := modules/dnstap/dnstap.c
dnstap_DEPEND := $(libkres)
dnstap_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS) $(libprotobuf-c_LIBS) $(libfstrm_LIBS)
$(call make_c_module,dnstap)
