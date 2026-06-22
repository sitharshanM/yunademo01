#ifndef NEURAL_NETWORK_H
#define NEURAL_NETWORK_H

#include "Common.h"
#include <vector>
#include <string>

class NeuralNetwork {
private:
    int inputSize;
    int hiddenSize1;
    int hiddenSize2;
    int outputSize;
    std::vector<std::vector<double>> weightsInputHidden1;
    std::vector<std::vector<double>> weightsHidden1Hidden2;
    std::vector<std::vector<double>> weightsHidden2Output;
    std::vector<double> biasHidden1;
    std::vector<double> biasHidden2;
    std::vector<double> biasOutput;
    std::vector<double> hidden1Layer;
    std::vector<double> hidden2Layer;

    double sigmoid(double x);
    double sigmoidDerivative(double x);
    std::vector<double> applyDropout(const std::vector<double>& layer, double dropoutRate);

public:
    std::vector<double> outputLayer;
    
    int getInputSize() const { return inputSize; }
    NeuralNetwork(int input, int hidden1, int hidden2, int output);
    void forwardPropagate(const std::vector<double>& inputs, double dropoutRate = 0.0);
    void backpropagate(const std::vector<double>& inputs, const std::vector<double>& targets, double learningRate);
    void train(const std::vector<std::vector<double>>& inputData, const std::vector<std::vector<double>>& targetData, int epochs, double learningRate, double dropoutRate = DROPOUT_RATE);
    bool detectThreat();
    void saveModel(const std::string& filename);
    void loadModel(const std::string& filename);
};

#endif // NEURAL_NETWORK_H
