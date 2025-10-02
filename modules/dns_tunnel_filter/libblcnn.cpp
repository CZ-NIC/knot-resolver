#include <torch/script.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <random>
#include <filesystem>
#include "libblcnn.h"

constexpr int MAX_PACKET_SIZE = 300;
constexpr int ONE_HOT_SIZE = 257;

struct TorchModuleWrapper {
	torch::jit::script::Module model;
};

TorchModule load_model(const char *nn_file) {
	auto *wrapper = new TorchModuleWrapper();
	try {
		wrapper->model = torch::jit::load(nn_file);
		wrapper->model.to(torch::kCPU);
		wrapper->model.eval();

		return static_cast<TorchModule>(wrapper);
	} catch (const c10::Error &e) {
		std::cerr << "Error loading model: " << e.what() << std::endl;
		delete wrapper;
		return nullptr;
	}
}

float predict_packet(TorchModule module, const unsigned char *data, size_t size) {
	if (!module) return -1;
	auto* wrapper = reinterpret_cast<TorchModuleWrapper*>(module);

	torch::Tensor one_hot = torch::zeros({1, MAX_PACKET_SIZE}, torch::kLong);

	for (size_t i = 0; i < size && i < MAX_PACKET_SIZE; i++) {
		one_hot[0][i] = data[i];
	}
	for (size_t i = size; i < MAX_PACKET_SIZE; i++) {
		one_hot[0][i] = 256;
	}

	torch::Tensor output = wrapper->model.forward({one_hot}).toTensor();
	torch::Tensor tensor_prob = torch::softmax(output, 1);
	
	return tensor_prob[0][0].item<float>();
}

void free_model(TorchModule model) {
	delete static_cast<TorchModuleWrapper*>(model);
}

