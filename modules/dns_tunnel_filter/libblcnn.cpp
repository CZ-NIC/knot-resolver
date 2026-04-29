#include <torch/script.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <random>
#include <filesystem>
#include "libblcnn.h"

constexpr int MAX_PACKET_SIZE = 300;

struct TorchModuleWrapper {
	torch::jit::script::Module model;
	uint8_t version;
};

TorchModule load_model(const char *nn_file) {
	auto *wrapper = new TorchModuleWrapper();
	try {
		wrapper->model = torch::jit::load(nn_file);
		wrapper->model.to(torch::kCPU);
		wrapper->model.eval();

		if (wrapper->model.hasattr("expected_len")) {
			wrapper->version = 2;
		} else {
			wrapper->version = 1;
		}

		return static_cast<TorchModule>(wrapper);
	} catch (const c10::Error &e) {
		std::cerr << "Error loading model: " << e.what() << std::endl;
		delete wrapper;
		return nullptr;
	}
}

uint8_t get_model_version(TorchModule model) {
	if (!model) return 0;
	return reinterpret_cast<TorchModuleWrapper*>(model)->version;
}

float predict_packet(TorchModule module, const unsigned char *data, size_t size) {
	if (!module) return -1;
	auto* wrapper = reinterpret_cast<TorchModuleWrapper*>(module);

	uint32_t max_packet_size = wrapper->version == 1 ? MAX_PACKET_SIZE : 253;

	torch::Tensor one_hot = torch::zeros({1, max_packet_size}, torch::kLong);

	for (size_t i = 0; i < size && i < max_packet_size; i++) {
		one_hot[0][i] = data[i];
	}
	for (size_t i = size; i < max_packet_size; i++) {
		one_hot[0][i] = 256;
	}

	torch::Tensor output = wrapper->model.forward({one_hot}).toTensor();
	torch::Tensor tensor_prob = torch::softmax(output, 1);

	return tensor_prob[0][1].item<float>();
}

void free_model(TorchModule model) {
	delete static_cast<TorchModuleWrapper*>(model);
}

