bogus_log_CFLAGS := -fPIC
# We use a symbol that's not in libkres but the daemon.
# On darwin this isn't accepted by default.
bogus_log_LDFLAGS := -Wl,-undefined -Wl,dynamic_lookup
bogus_log_SOURCES := modules/bogus_log/bogus_log.c
bogus_log_DEPEND := $(libkres)
bogus_log_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,bogus_log)
