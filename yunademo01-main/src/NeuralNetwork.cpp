#include "NeuralNetwork.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <random>
#include <cmath>

using json = nlohmann::json;

double NeuralNetwork::sigmoid(double x) {
    return 1.0 / (1.0 + std::exp(-x));
}

double NeuralNetwork::sigmoidDerivative(double x) {
    return x * (1.0 - x);
}

std::vector<double> NeuralNetwork::applyDropout(const std::vector<double>& layer, double dropoutRate) {
    std::vector<double> dropped = layer;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    for (auto& val : dropped) {
        if (dis(gen) < dropoutRate) {
            val = 0.0;
        } else {
            val /= (1.0 - dropoutRate);
        }
    }
    return dropped;
}

NeuralNetwork::NeuralNetwork(int input, int hidden1, int hidden2, int output)
    : inputSize(input), hiddenSize1(hidden1), hiddenSize2(hidden2), outputSize(output) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-0.5, 0.5);

    weightsInputHidden1.resize(inputSize, std::vector<double>(hiddenSize1));
    for (int i = 0; i < inputSize; ++i) {
        for (int j = 0; j < hiddenSize1; ++j) {
            weightsInputHidden1[i][j] = dis(gen);
        }
    }

    weightsHidden1Hidden2.resize(hiddenSize1, std::vector<double>(hiddenSize2));
    for (int i = 0; i < hiddenSize1; ++i) {
        for (int j = 0; j < hiddenSize2; ++j) {
            weightsHidden1Hidden2[i][j] = dis(gen);
        }
    }

    weightsHidden2Output.resize(hiddenSize2, std::vector<double>(outputSize));
    for (int i = 0; i < hiddenSize2; ++i) {
        for (int j = 0; j < outputSize; ++j) {
            weightsHidden2Output[i][j] = dis(gen);
        }
    }

    biasHidden1.resize(hiddenSize1);
    for (auto& b : biasHidden1) b = dis(gen);

    biasHidden2.resize(hiddenSize2);
    for (auto& b : biasHidden2) b = dis(gen);

    biasOutput.resize(outputSize);
    for (auto& b : biasOutput) b = dis(gen);

    outputLayer.resize(outputSize, 0.0);
    hidden1Layer.resize(hiddenSize1, 0.0);
    hidden2Layer.resize(hiddenSize2, 0.0);
}

void NeuralNetwork::forwardPropagate(const std::vector<double>& inputs, double dropoutRate) {
    std::fill(hidden1Layer.begin(), hidden1Layer.end(), 0.0);
    for (int j = 0; j < hiddenSize1; ++j) {
        for (int i = 0; i < inputSize; ++i) {
            hidden1Layer[j] += inputs[i] * weightsInputHidden1[i][j];
        }
        hidden1Layer[j] += biasHidden1[j];
        hidden1Layer[j] = sigmoid(hidden1Layer[j]);
    }
    hidden1Layer = applyDropout(hidden1Layer, dropoutRate);

    std::fill(hidden2Layer.begin(), hidden2Layer.end(), 0.0);
    for (int j = 0; j < hiddenSize2; ++j) {
        for (int i = 0; i < hiddenSize1; ++i) {
            hidden2Layer[j] += hidden1Layer[i] * weightsHidden1Hidden2[i][j];
        }
        hidden2Layer[j] += biasHidden2[j];
        hidden2Layer[j] = sigmoid(hidden2Layer[j]);
    }
    hidden2Layer = applyDropout(hidden2Layer, dropoutRate);

    for (int j = 0; j < outputSize; ++j) {
        outputLayer[j] = 0.0;
        for (int i = 0; i < hiddenSize2; ++i) {
            outputLayer[j] += hidden2Layer[i] * weightsHidden2Output[i][j];
        }
        outputLayer[j] += biasOutput[j];
        outputLayer[j] = sigmoid(outputLayer[j]);
    }
}

void NeuralNetwork::backpropagate(const std::vector<double>& inputs, const std::vector<double>& targets, double learningRate) {
    std::vector<double> outputErrors(outputSize);
    for (int j = 0; j < outputSize; ++j) {
        outputErrors[j] = (targets[j] - outputLayer[j]) * sigmoidDerivative(outputLayer[j]);
    }

    std::vector<double> hidden2Errors(hiddenSize2, 0.0);
    for (int j = 0; j < hiddenSize2; ++j) {
        for (int k = 0; k < outputSize; ++k) {
            hidden2Errors[j] += outputErrors[k] * weightsHidden2Output[j][k];
        }
        hidden2Errors[j] *= sigmoidDerivative(hidden2Layer[j]);
    }

    std::vector<double> hidden1Errors(hiddenSize1, 0.0);
    for (int j = 0; j < hiddenSize1; ++j) {
        for (int k = 0; k < hiddenSize2; ++k) {
            hidden1Errors[j] += hidden2Errors[k] * weightsHidden1Hidden2[j][k];
        }
        hidden1Errors[j] *= sigmoidDerivative(hidden1Layer[j]);
    }

    for (int i = 0; i < hiddenSize2; ++i) {
        for (int j = 0; j < outputSize; ++j) {
            weightsHidden2Output[i][j] += learningRate * outputErrors[j] * hidden2Layer[i];
        }
    }
    for (int j = 0; j < outputSize; ++j) {
        biasOutput[j] += learningRate * outputErrors[j];
    }

    for (int i = 0; i < hiddenSize1; ++i) {
        for (int j = 0; j < hiddenSize2; ++j) {
            weightsHidden1Hidden2[i][j] += learningRate * hidden2Errors[j] * hidden1Layer[i];
        }
    }
    for (int j = 0; j < hiddenSize2; ++j) {
        biasHidden2[j] += learningRate * hidden2Errors[j];
    }

    for (int i = 0; i < inputSize; ++i) {
        for (int j = 0; j < hiddenSize1; ++j) {
            weightsInputHidden1[i][j] += learningRate * hidden1Errors[j] * inputs[i];
        }
    }
    for (int j = 0; j < hiddenSize1; ++j) {
        biasHidden1[j] += learningRate * hidden1Errors[j];
    }
}

void NeuralNetwork::train(const std::vector<std::vector<double>>& inputData, const std::vector<std::vector<double>>& targetData, int epochs, double learningRate, double dropoutRate) {
    if (inputData.size() != targetData.size() || inputData.empty()) {
        Logger::log("Invalid training data size.", Logger::ERROR);
        return;
    }
    size_t numSamples = inputData.size();
    for (int epoch = 0; epoch < epochs; ++epoch) {
        double totalError = 0.0;
        for (size_t sample = 0; sample < numSamples; ++sample) {
            forwardPropagate(inputData[sample], dropoutRate);
            backpropagate(inputData[sample], targetData[sample], learningRate);
            for (int j = 0; j < outputSize; ++j) {
                totalError += std::pow(targetData[sample][j] - outputLayer[j], 2);
            }
        }
        totalError /= numSamples;
        if (epoch % 50 == 0) {
            Logger::log("Epoch " + std::to_string(epoch) + "/" + std::to_string(epochs) + " - Average Error: " + std::to_string(totalError), Logger::DEBUG);
        }
    }
    Logger::log("Training completed.", Logger::INFO);
}

bool NeuralNetwork::detectThreat() {
    return outputLayer[0] > THREAT_THRESHOLD;
}

void NeuralNetwork::saveModel(const std::string& filename) {
    json j;
    j["inputSize"] = inputSize;
    j["hiddenSize1"] = hiddenSize1;
    j["hiddenSize2"] = hiddenSize2;
    j["outputSize"] = outputSize;
    j["weightsInputHidden1"] = weightsInputHidden1;
    j["weightsHidden1Hidden2"] = weightsHidden1Hidden2;
    j["weightsHidden2Output"] = weightsHidden2Output;
    j["biasHidden1"] = biasHidden1;
    j["biasHidden2"] = biasHidden2;
    j["biasOutput"] = biasOutput;
    std::ofstream file(filename);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
        Logger::log("Model saved to " + filename, Logger::INFO);
    } else {
        Logger::log("Failed to save model.", Logger::ERROR);
    }
}

void NeuralNetwork::loadModel(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        Logger::log("Failed to open model file " + filename, Logger::ERROR);
        return;
    }
    json j;
    try {
        file >> j;
        inputSize = j["inputSize"];
        hiddenSize1 = j["hiddenSize1"];
        hiddenSize2 = j["hiddenSize2"];
        outputSize = j["outputSize"];
        weightsInputHidden1 = j["weightsInputHidden1"].get<std::vector<std::vector<double>>>();
        weightsHidden1Hidden2 = j["weightsHidden1Hidden2"].get<std::vector<std::vector<double>>>();
        weightsHidden2Output = j["weightsHidden2Output"].get<std::vector<std::vector<double>>>();
        biasHidden1 = j["biasHidden1"].get<std::vector<double>>();
        biasHidden2 = j["biasHidden2"].get<std::vector<double>>();
        biasOutput = j["biasOutput"].get<std::vector<double>>();
        outputLayer.resize(outputSize, 0.0);
        Logger::log("Model loaded from " + filename, Logger::INFO);
    } catch (const std::exception& e) {
        Logger::log("Error loading model: " + std::string(e.what()), Logger::ERROR);
    }
    file.close();
}
