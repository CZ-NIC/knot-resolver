package main

/*
#include "lib/layer.h"
#include "lib/module.h"
extern int begin(knot_layer_t *, void *) __asm__ ("main.Begin");
extern int finish(knot_layer_t *) __asm__ ("main.Finish");
static inline const knot_layer_api_t *_gostats_layer(void)
{
	static const knot_layer_api_t _module = {
		.begin = &begin,
		.finish = &finish
	};
	return &_module;
}
*/
import "C"
import "unsafe"
import "fmt"

func Api() C.uint32_t {
	return C.KR_MODULE_API
}

func Init(module *C.struct_kr_module) C.int {
	fmt.Printf("go_init(%s)\n", C.GoString((*C.char)(module.data)))
	return 0
}

func Deinit(module *C.struct_kr_module) C.int {
	fmt.Println("go_deinit()")
	return 0
}

func Begin(ctx *C.knot_layer_t, param unsafe.Pointer) C.int {
	fmt.Println("go_begin()")
	return 0
}

func Finish(ctx *C.knot_layer_t) C.int {
	fmt.Println("go_finish()")
	return 0
}

func Layer() *C.knot_layer_api_t {
	return C._gostats_layer()
}