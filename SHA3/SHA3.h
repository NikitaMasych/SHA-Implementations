#ifndef SHA3_H_INCLUDED
#define SHA3_H_INCLUDED

#include <vector>

class SHA3{
private:
    std::string messageDigest;
    size_t bitsDigest;
    std::vector<unsigned char> message;
    void padding();
    void absorbing();
    void squeezing();
    size_t r, c;
    size_t b = 1600;
    size_t rounds = 24;
    size_t w = 64;
    std::vector<uint_fast8_t> state;
    std::vector<std::vector<uint_fast64_t> > keccakF(std::vector<std::vector<uint_fast64_t> > A);
    std::vector<uint_fast64_t> RC; // round constants
    void round(std::vector<std::vector<uint_fast64_t> > &A,  uint_fast64_t rc);
    void keccakF(std::vector<std::vector<uint_fast64_t> > &A);

public:
    SHA3();
    void enterMessage();
    void enterBitDigest();
    void calculateHash();
    std::string getHash();
    void initialiseRC();
};

#endif // SHA3_H_INCLUDED
