//
// Created by qyxie on 16/1/2022.
//
#include<string>
#include<cryptopp/rsa.h>
#include<cryptopp/osrng.h>
#include<iostream>
#include <sstream>

int main (int argc, char* argv[]){
    using namespace CryptoPP;
    AutoSeededRandomPool rng;

    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 4096);

    const Integer& n = params.GetModulus();
    const Integer& p = params.GetPrime1();
    const Integer& q = params.GetPrime2();
    const Integer& d = params.GetPrivateExponent();
    const Integer& e = params.GetPublicExponent();

    std::cout << "RSA Parameters:" << std::endl;
    std::cout << " n: " << n << std::endl;
    std::cout << " p: " << p << std::endl;
    std::cout << " q: " << q << std::endl;
    std::cout << " d: " << d << std::endl;
    std::cout << " e: " << e << std::endl;
    std::cout << std::endl;

    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);

    std::stringstream ss;
    ss << n;
    std::string n_d = ss.str();
    std::cout << n_d.length() << std::endl;

}

