#ifndef TORCH_WRAPPER_H
#define TORCH_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void* TorchModule;

TorchModule load_model(void);
float predict_packet(TorchModule model, const unsigned char *data, size_t size);
void free_model(TorchModule model);

#ifdef __cplusplus
}
#endif

#endif
