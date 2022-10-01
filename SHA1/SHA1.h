#ifndef SHA1_INCLUDED_H
#define SHA1_INCLUDED_H

#include <vector>

class SHA1{

private:
    std::string messageDigest;
    std::vector <unsigned char> message;
    std::vector <uint_fast32_t> messageSchedule(const size_t& pos);
    void messageProcessing();
    void hashForChunk(uint_fast32_t& h0, uint_fast32_t&  h1,
                        uint_fast32_t& h2, uint_fast32_t&  h3,
                        uint_fast32_t& h4, const size_t& pos);
public:
    void enterMessage();
    void calculateHash();
    std::string getHash();
};

#endif
