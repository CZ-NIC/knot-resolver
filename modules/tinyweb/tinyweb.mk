tinyweb_SOURCES := modules/tinyweb/tinyweb.go
tinyweb_INSTALL := $(wildcard modules/tinyweb/tinyweb/*)
tinyweb_DEPEND := $(libkres)
tinyweb_LIBS := $(libkres_TARGET) $(libkres_LIBS)
$(call make_go_module,tinyweb)
