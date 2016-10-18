client_subnet_CFLAGS := -fvisibility=hidden -fPIC
client_subnet_SOURCES := modules/client_subnet/client_subnet.c
client_subnet_DEPEND := $(libkres)
client_subnet_LIBS := $(libkres_TARGET) $(libkres_LIBS) $(libmaxminddb_LIBS)
$(call make_c_module,client_subnet)
