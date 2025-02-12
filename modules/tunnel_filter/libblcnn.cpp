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

TorchModule load_model(const char *model_path) {
	try {
		namespace fs = std::filesystem;
		auto *wrapper = new TorchModuleWrapper();

		fs::path file_path = fs::relative(__FILE__, "../");
		fs::path absolute_path = fs::absolute(file_path.parent_path()) / model_path;
		wrapper->model = torch::jit::load(absolute_path);
		wrapper->model.to(torch::kCPU);
		wrapper->model.eval();

		return static_cast<TorchModule>(wrapper);
	} catch (const c10::Error &e) {
		std::cerr << "Error loading model: " << e.what() << std::endl;

		return nullptr;
	}
}

int predict_packet(TorchModule module, const unsigned char *data, size_t size) {
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

	int predicted_class = std::get<1>(torch::max(output, 1)).item<int>();
	return predicted_class;
}

void free_model(TorchModule model) {
	delete static_cast<TorchModuleWrapper*>(model);
}
