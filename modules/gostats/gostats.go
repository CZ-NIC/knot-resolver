package gostats

/*
#include "lib/layer.h"
#include "lib/module.h"
extern int gostats_begin(knot_layer_t *, void *);
extern int gostats_finish(knot_layer_t *);
static inline const knot_layer_api_t *_gostats_layer(void)
{
	static const knot_layer_api_t _module = {
		.begin = &gostats_begin,
		.finish = &gostats_finish
	};
	return &_module;
}
*/
import "C"
import "unsafe"
import "fmt"

//export gostats_init
func gostats_init(module *C.struct_kr_module) C.int {
	fmt.Println("go_init()")
	return 0
}

//export gostats_deinit
func gostats_deinit(module *C.struct_kr_module) C.int {
	fmt.Println("go_deinit()")
	return 0
}

//export gostats_begin
func gostats_begin(ctx *C.knot_layer_t, param unsafe.Pointer) C.int {
	fmt.Println("go_begin()")
	return 0
}

//export gostats_finish
func gostats_finish(ctx *C.knot_layer_t) C.int {
	fmt.Println("go_finish()")
	return 0
}

//export gostats_layer
func gostats_layer() *C.knot_layer_api_t {
	return C._gostats_layer()
}