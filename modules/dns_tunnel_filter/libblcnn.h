#ifndef TORCH_WRAPPER_H
#define TORCH_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef void* TorchModule;

TorchModule load_model(const char *nn_file);
uint8_t get_model_version(TorchModule model);
float predict_packet(TorchModule model, const unsigned char *data, size_t size);
void free_model(TorchModule model);

#ifdef __cplusplus
}
#endif

#endif
