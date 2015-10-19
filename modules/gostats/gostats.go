package main

/*
#include "lib/layer.h"
#include "lib/module.h"
int begin(knot_layer_t *, void *);
int finish(knot_layer_t *);
static inline const knot_layer_api_t *_layer(void)
{
	static const knot_layer_api_t api = {
		.begin = &begin,
		.finish = &finish
	};
	return &api;
}
*/
import "C"
import "unsafe"
import "fmt"

//export gostats_api
func gostats_api() C.uint32_t {
	return C.KR_MODULE_API
}

//export gostats_init
func gostats_init(module *C.struct_kr_module) int {
	return 0
}

//export gostats_deinit
func gostats_deinit(module *C.struct_kr_module) int {
	return 0
}

//export begin
func begin(ctx *C.knot_layer_t, param unsafe.Pointer) C.int {
	ctx.data = param
	return 0
}

//export finish
func finish(ctx *C.knot_layer_t) C.int {
	var param *C.struct_kr_request = (*C.struct_kr_request)(ctx.data)
	fmt.Printf("[gostats] resolved %d queries\n", C.list_size(&param.rplan.resolved))
	return 0
}

//export gostats_layer
func gostats_layer(module *C.struct_kr_module) *C.knot_layer_api_t {
	return C._layer()
}

func main() {}