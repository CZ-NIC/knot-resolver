hints_CFLAGS := -fvisibility=hidden -fPIC
# We use a symbol that's not in libkres but the daemon.
# On darwin this isn't accepted by default.
hints_LDFLAGS := -Wl,-undefined -Wl,dynamic_lookup
hints_SOURCES := modules/hints/hints.c
hints_DEPEND := $(libkres)
hints_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,hints)
