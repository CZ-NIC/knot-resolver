package main

/*
#include "lib/layer.h"
#include "lib/module.h"
extern int Begin(knot_layer_t *, void *) __asm__ ("main.Begin");
extern int Finish(knot_layer_t *) __asm__ ("main.Finish");
static inline const knot_layer_api_t *_layer(void)
{
	static const knot_layer_api_t api = {
		.begin = &Begin,
		.finish = &Finish
	};
	return &api;
}
*/
import "C"
import "unsafe"
import "fmt"

func Api() C.uint32_t {
	return C.KR_MODULE_API
}

func Init(module *C.struct_kr_module) C.int {
	return 0
}

func Deinit(module *C.struct_kr_module) C.int {
	return 0
}

func Begin(ctx *C.knot_layer_t, param unsafe.Pointer) C.int {
	ctx.data = param
	return 0
}

func Finish(ctx *C.knot_layer_t) C.int {
	var param *C.struct_kr_layer_param = (*C.struct_kr_layer_param)(ctx.data)
	fmt.Printf("[gostats] resolved %d queries", C.list_size(&param.rplan.resolved))
	return 0
}

func Layer() *C.knot_layer_api_t {
	return C._layer()
}
