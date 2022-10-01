#include <iostream>
#include <iomanip>
#include "SHA3.h"


void SHA3::initialiseRC(){
    // sets round constants
    std::vector<uint_fast64_t> RC(24);
    RC[0]  = 0x0000000000000001; RC[12] = 0x000000008000808B;
    RC[1]  = 0x0000000000008082; RC[13] = 0x800000000000008B;
    RC[2]  = 0x800000000000808A; RC[14] = 0x8000000000008089;
    RC[3]  = 0x8000000080008000; RC[15] = 0x8000000000008003;
    RC[4]  = 0x000000000000808B; RC[16] = 0x8000000000008002;
    RC[5]  = 0x0000000080000001; RC[17] = 0x8000000000000080;
    RC[6]  = 0x8000000080008081; RC[18] = 0x000000000000800A;
    RC[7]  = 0x8000000000008009; RC[19] = 0x800000008000000A;
    RC[8]  = 0x000000000000008A; RC[20] = 0x8000000080008081;
    RC[9]  = 0x0000000000000088; RC[21] = 0x8000000000008080;
    RC[10] = 0x0000000080008009; RC[22] = 0x0000000080000001;
    RC[11] = 0x000000008000000A; RC[23] = 0x8000000080008008;
    SHA3::RC = RC;
}

uint_fast64_t leftRotate(uint_fast64_t a, unsigned int c){
    // implements c bits circular left shift for value a
    unsigned int INT_BITS = 64;
    return (a << c)|(a >> (INT_BITS - c));
}

std::string hexString(uint_fast8_t a){
    // converts 8 binary to hexadecimal string

    std::stringstream stream;
    // with respect to leading zeros
    // cast need to make sure we won't output as char
    stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(a);

    std::string str = stream.str();

    return str;
}

std::vector<std::vector<uint_fast64_t> > calculateStateArray(const std::vector<uint_fast8_t> &state){
    // converts state to state array
    std::vector<std::vector<uint_fast64_t> > stateArray(5, std::vector <uint_fast64_t> (5, 0));
    uint_fast64_t word;
    size_t pos = 0;

    for (size_t j = 0; j != 5; ++j){
         for (size_t i = 0; i != 5; ++i){
            uint_fast64_t word = 0;
            for (size_t k = 0; k != 8; ++k){
                // to achieve correct shift by more than 32 bits
                uint_fast64_t tmp = state[pos+k];
                word = word | (tmp << (8*k));
            }
            pos += 8;
            stateArray[i][j] = word;
         }
    }

    return stateArray;
}

std::vector<uint_fast8_t> calculateState(const std::vector<std::vector<uint_fast64_t> > &A){
    //converts state array to state
    std::vector<uint_fast8_t> state;
    for (size_t j = 0; j != 5; ++ j){
        for (size_t i = 0; i != 5; ++ i){
            for (size_t shift = 0; shift != 64; shift += 8)
            state.push_back( (A[i][j] >> shift) & 0xFF); // 8 bytes of 64 bit element
        }
    }
    return state;
}

void theta(std::vector<std::vector<uint_fast64_t> > &A){
    std::vector<uint_fast64_t> C(5);
    for (size_t i = 0; i != 5; ++i)
        C[i] = (A[i][0] ^ A[i][1] ^ A[i][2] ^ A[i][3] ^ A[i][4]);

    std::vector<uint_fast64_t> D(5);
    for (size_t i = 0; i != 5; ++i)
        D[i] = (C[(i+4) % 5] ^ leftRotate(C[(i+1) % 5], 1));

    for (size_t i = 0; i != 5; ++i){
        for (size_t j = 0; j != 5; ++j)
            A[i][j] = (A[i][j] ^ D[i]);
    }
}

void rhoAndPi(std::vector<std::vector<uint_fast64_t> > &A){
    size_t i = 1, j = 0;
    uint_fast64_t previous = A[i][j];
    for(size_t t = 0; t != 24; ++t){
        uint_fast64_t r = ((t+1)*(t+2)/2)%64;
        size_t tmp = (2*i+3*j)%5;
        i = j; j = tmp;
        uint_fast64_t temp = A[i][j];
        A[i][j] = leftRotate(previous, r);
        previous = temp;
    }
}

void chi(std::vector <std::vector <uint_fast64_t> > &A){
    std::vector<uint_fast64_t> tmp(5);
    for(size_t j = 0; j != 5; ++j){
        for(size_t i = 0; i != 5; ++i)
            tmp[i] = A[i][j];
        for(size_t i = 0; i != 5; ++i)
            A[i][j] = (tmp[i] ^ ((~tmp[(i+1) % 5]) & tmp[(i+2) % 5]));
    }
}

void iota(std::vector <std::vector <uint_fast64_t> > &A, uint_fast64_t rc){
    A[0][0] = A[0][0] ^ rc;
}

void SHA3::round(std::vector<std::vector<uint_fast64_t> > &A, uint_fast64_t rc){
    theta(A);
    rhoAndPi(A);
    chi(A);
    iota(A, rc);
}

std::vector<std::vector<uint_fast64_t> > SHA3::keccakF(std::vector<std::vector<uint_fast64_t> > A){
    for(size_t i = 0; i != 24; ++i){
        round(A, RC[i]);
    }

    return A;
}

void SHA3::padding(){
    c = bitsDigest * 2; // capacity
    r = 1600 - c; // rate
    // total number of appended bytes
    size_t q = (r/8) - (message.size() % (r/8));

    switch(q){
    case 1:
        message.push_back(static_cast<unsigned char>(0x86));
        break;
    case 2:
    {
        message.push_back(static_cast<unsigned char>(0x06));
        message.push_back(static_cast<unsigned char>(0x80));
        break;
    }
    default:
    {
        message.push_back(static_cast<unsigned char>(0x06));
        for (size_t i = 0; i != q - 2; ++i)
            message.push_back(static_cast<unsigned char>(0x00));
        message.push_back(static_cast<unsigned char>(0x80));
    }
    }
}

void SHA3::absorbing(){
    // initializing state array:

    std::vector<uint_fast8_t> state(200,0);
    size_t n = message.size() * 8 / r; // amount of blocks

    for (size_t i = 0; i != n; ++i){
        for (size_t j = 0; j != (r / 8); ++j) // r/8 = number of characters in one block
            state[j] ^= message[j + (r/8)*i];
        state = calculateState(keccakF(calculateStateArray(state)));
    }

    SHA3::state = state;

}

void SHA3::squeezing(){
    std::string res = "";
    for (size_t i = 0; i != bitsDigest/8; ++i){
        res += hexString(state[i]);
    }
    messageDigest = res;
}

void SHA3::calculateHash(){
    padding();
    absorbing();
    squeezing();
}

void SHA3::enterMessage(){
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

size_t convertBitLength(std::string str){
    if (str.length() != 3) throw std::invalid_argument("Invalid input!\n");
    if (!std::isdigit(str[0]) || !std::isdigit(str[1]) || !std::isdigit(str[2]))
        throw std::invalid_argument("Invalid input!\n");
    size_t num = std::stoul(str);
    if (num != 224 && num != 256 && num != 384 && num != 512)
        throw std::invalid_argument("Invalid input!\n");
    return num;
}

void SHA3::enterBitDigest(){
    std::cout << "Enter desired digest length (in bits): ";
    std::string str;
    std::getline(std::cin, str);
    try{
        bitsDigest = convertBitLength(str);
    }
    catch (std::invalid_argument& e){
        std::cerr << e.what();
        enterBitDigest();
    }
}

std::string SHA3::getHash(){
    return messageDigest;
}

SHA3::SHA3(){
    initialiseRC();
}
