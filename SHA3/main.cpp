#include <iostream>
#include <chrono>
#include "SHA3.h"

int main()
{
    SHA3 instance;
    instance.enterMessage();
    instance.enterBitDigest();
    auto start = std::chrono::high_resolution_clock::now();
    instance.calculateHash();
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << "Result: " << instance.getHash();
    std::cout << "\nCalculation time: " << duration.count() << " microseconds";
    return 0;
}
