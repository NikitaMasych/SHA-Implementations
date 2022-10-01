#include <iostream>
#include <iomanip>
#include "SHA1.h"


uint_fast32_t leftRotate(uint_fast32_t a, unsigned int c){
    // implements c bits circular left shift for value a
    unsigned int INT_BITS = 32;
    return (a << c)|(a >> (INT_BITS - c));
}

std::vector<unsigned char> slice(std::vector<unsigned char> const &v,
                                 size_t m, size_t n){
    // gets vector v slice from [m,n)
    auto first = v.cbegin() + m;
    auto last =  v.cbegin() + n;

    std::vector<unsigned char> subvector(first, last);
    return subvector;
}

uint_fast32_t binaryNumber(std::vector<unsigned char> str){
    // converts 4 character string to 32 binary
    return (int(str[0]) << 24) | (int(str[1]) << 16) | (int(str[2]) << 8) | int(str[3]);
};

std::string binaryString(uint_fast64_t a){
    // converts 64 binary to 8 character string
    std::string str = "";
    for (size_t shift = 56; shift != -8; shift -=8 )
        str += static_cast<char>( (a >> shift) & 0xFF);
    return str;
}

std::string hexString(uint_fast32_t a){
    // converts 32 binary to hexadecimal string

    std::stringstream stream;
    // with respect to leading zeros
    stream << std::setw(8) << std::setfill('0') << std::hex << a;

    std::string str = stream.str();

    return str;
}

std::string hashLinker(uint_fast32_t h0, uint_fast32_t h1,
                       uint_fast32_t h2, uint_fast32_t h3,
                       uint_fast32_t h4){
    // concatenates hashes into hexadecimal-represented string
    std::string str = "";

    str += hexString(h0);
    str += hexString(h1);
    str += hexString(h2);
    str += hexString(h3);
    str += hexString(h4);

    return str;
}

std::vector <uint_fast32_t> SHA1::messageSchedule(const size_t& pos){
    std::vector <uint_fast32_t> words;
    // get 16 words 4 character each = 32 bites
    for(size_t i = 0; i != 64; i += 4){
        uint_fast32_t word = binaryNumber(slice(message, pos+i, pos+i+4));
        words.push_back(word);
    }
    // get another 64 words based on those 16
    for (size_t i = 16; i != 80; ++i){
        uint_fast32_t word = leftRotate((words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i - 16]), 1);
        words.push_back(word);
    }
    return words;
}

void conductVals(uint_fast32_t& a, uint_fast32_t& b,
                 uint_fast32_t& c, uint_fast32_t& d,
                 uint_fast32_t& e, const std::vector <uint_fast32_t> &words){
    // conducts values through loop
    uint_fast32_t k, f, temp;

    for (size_t i = 0; i != 80; ++i){
        if (i < 20){
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        }
        else if (i < 40){
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if (i < 60){
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else{
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        temp = leftRotate(a, 5) + f + e + k + words[i];
        e = d;
        d = c;
        c = leftRotate(b, 30);
        b = a;
        a = temp;
    }
}

void SHA1::hashForChunk(uint_fast32_t& h0, uint_fast32_t&  h1,
                        uint_fast32_t& h2, uint_fast32_t&  h3,
                        uint_fast32_t& h4, const size_t& pos){
    // break chunk into 16 + 64 words:
    std::vector <uint_fast32_t> words = messageSchedule(pos);

    // initialize hash values for this chunk:
    uint_fast32_t a, b, c, d, e;
    a = h0;
    b = h1;
    c = h2;
    d = h3;
    e = h4;

    conductVals(a, b, c, d, e, words);

    // add this chunk's hash to result so far:
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;

}

void SHA1::messageProcessing(){
    // due to storing message in chars, which are one byte
    // adding 1 is possible only as whole 0b10000000
    message.push_back(static_cast<unsigned char>(0b10000000));

    size_t zerosAmount;
    size_t non512Characters = message.size() % 64; // including "0b10000000"

    // if enough space without additional block
    if (non512Characters <= 56) zerosAmount = 448 - non512Characters * 8;
    // if additional block required
    else zerosAmount = 512 - (non512Characters) * 8 // in penultimate
                     + 512 - 64;                    // in additional

    for (size_t i = 0; i != zerosAmount; i += 8)
        message.push_back(static_cast<unsigned char>(0b00000000));

    // 64 bit length of the initial message
    uint_fast64_t len = (message.size() - 1) * 8 - zerosAmount; // in bits
    std::string l = binaryString(len);
    for (unsigned char c: l) message.push_back(c);
}

void SHA1::calculateHash(){
    uint_fast32_t h0, h1, h2, h3, h4;
    h0 = 0x67452301;
    h1 = 0xEFCDAB89;
    h2 = 0x98BADCFE;
    h3 = 0x10325476;
    h4 = 0xC3D2E1F0;

    messageProcessing();

    // 512 bit chunk consists of 64 characters, therefore:
    for (size_t pos = 0; pos != message.size(); pos += 64)
        hashForChunk(h0, h1, h2, h3, h4, pos);

    messageDigest = hashLinker(h0, h1, h2, h3, h4);
}

void SHA1::enterMessage(){
    std::cout << "Enter ASCII string to hash: ";
    std::string str;
    std::getline(std::cin, str);
    for (unsigned char c: str) {
        // check whether symbol is not ASCII:
        if (c > 127){
            std::cout << "Inappropriate input!\n";
            message.clear();
            enterMessage();
            break;
        }
        message.push_back(c);
    }
}

std::string SHA1::getHash(){
    return messageDigest;
}
