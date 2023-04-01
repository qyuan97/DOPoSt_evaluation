#include <iostream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <cstring>
#include <sys/time.h>
#include <sstream>
#include <math.h>
#include<cryptopp/rsa.h>
#include<cryptopp/osrng.h>
#include<cryptopp/hex.h>
#include<cryptopp/hmac.h>
#include<cryptopp/sha3.h>
#include<cryptopp/modarith.h>
#include<cryptopp/files.h>
#include<cryptopp/modes.h>
#include<fstream>

std::string sha3_256(std::string msg)
{
    std::string digest;
    std::string hex_digest;

    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_digest));

    CryptoPP::SHA3_256 hash;
    hash.Update((const byte*)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));
    return hex_digest;
}

int main()
{

    std::ofstream os;    
    os.open("../shares.txt", std::fstream::out);

    uint64_t fileSize = 64;
    fileSize *= 1048576ul;

    std::string file(4 * 1024, 'F');
    file += "h";
    CryptoPP::Integer g(file.c_str());

    std::cout << "file size: " << file.size() << std::endl;

    uint64_t file_n = atoi(file.c_str());
    // std::cout << file_n << std::endl;

    std::string file_shares_1 = sha3_256(file);
    // std::string file_shares_2 = std::to_string((stoi(file) - stoi(file_shares_1)));

    std::cout << "file_shares_1: " << file_shares_1 << std::endl;
    // std::cout << "file_shares_2: " << file_shares_2 << std::endl;

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(32);
    prng.GenerateBlock(key, key.size());

    std::string c_1;
    c_1.resize(key.size());
    std::memcpy(&c_1[0], &key[0], c_1.size());

    std::string c1_encoded;
    CryptoPP::StringSource ss3(c_1, true,
                               new CryptoPP::HexEncoder(
                                   new CryptoPP::StringSink(c1_encoded)));

    std::cout << "c1_encoded: " << c1_encoded << std::endl;

    std::string c1_encoded_output = c1_encoded + "\n";
    os << c1_encoded_output;

    const int n_bits = 1024;

    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, n_bits);
    const CryptoPP::Integer &p = params.GetPrime1();
    const CryptoPP::Integer &q = params.GetPrime2();
    CryptoPP::Integer tdf_pk = p * q;
    CryptoPP::Integer one(1);
    CryptoPP::Integer tdf_sk = (p - one) * (q - one);
    std::cout << "tdf_pk: " << tdf_pk << std::endl;
    std::cout << "tdf_sk: " << tdf_sk << std::endl;

    uint64_t t = 51;
    CryptoPP::Integer two = CryptoPP::Integer::Two();
    CryptoPP::Integer big_s(t);
    auto e = a_exp_b_mod_c(two, big_s, tdf_sk);

    std::cout << "e: " << e << std::endl;

    os.close();

    return 0;
}