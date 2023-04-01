//
// Created by qyxie on 16/1/2022.
//
#include<stdint.h>
#include<toolkit.h>
#include<math.h>
#include<cryptopp/rsa.h>
#include<cryptopp/osrng.h>
#include<cryptopp/hex.h>
#include<cryptopp/hmac.h>
#include<cryptopp/sha3.h>
#include<cryptopp/modarith.h>
#include<cryptopp/files.h>
#include<cryptopp/modes.h>
#include<time.h>
#include<iostream>
#include<vector>
#include <sstream>

std::string sha3_256(std::string msg){
    std::string digest;
    // CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
    std::string hex_digest;

    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_digest));

    CryptoPP::SHA3_256 hash;
    hash.Update((const CryptoPP::byte*)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&digest[0]);

    CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));
    return hex_digest;
    // return digest;
}

std::string hmac_sha3(std::string key, std::string msg){
    std::string mac, encoded;
    CryptoPP::SecByteBlock key_hmac(reinterpret_cast<const CryptoPP::byte*>(&key[0]), key.size());
    try
    {
        CryptoPP::HMAC<CryptoPP::SHA3_256> hmac(key_hmac, key_hmac.size());

        CryptoPP::StringSource ss2(msg, true,
                         new CryptoPP::HashFilter(hmac,
                                        new CryptoPP::StringSink(mac)
                         ) // HashFilter
        ); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    encoded.clear();
    CryptoPP::StringSource ss3(mac, true,
                     new CryptoPP::HexEncoder(
                             new CryptoPP::StringSink(encoded)
                     ) // HexEncoder
    ); // StringSource
    return encoded;
}

std::string aes(CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv, std::string msg) {
    std::string cipher;
    try{
        CryptoPP::CBC_Mode <CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
        CryptoPP::StringSource s(msg, true,
                                 new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(cipher)));
    } catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    return cipher;
}

std::pair<CryptoPP::Integer, CryptoPP::Integer> setup(int n_bits){
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, n_bits);

    const CryptoPP::Integer& p = params.GetPrime1();
    const CryptoPP::Integer& q = params.GetPrime2();

    return std::make_pair(p, q);
}

void PoR_setup(std::string PoR_sk[], int n){
    for(int i = 0; i < n; i++){
        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::SecByteBlock key(32);
        prng.GenerateBlock(key, key.size());

        std::string s;
        s.resize(key.size());
        std::memcpy(&s[0], &key[0], s.size());

        PoR_sk[i] = s;
    }
}

std::pair<CryptoPP::Integer, CryptoPP::Integer> TDF_setup(CryptoPP::Integer p, CryptoPP::Integer q){
    CryptoPP::Integer pk = p * q;
    CryptoPP::Integer one(1);
    CryptoPP::Integer sk = (p - one) * (q - one);
    return std::make_pair(pk,sk);
}

CryptoPP::Integer TDF_TrapEval(std::string msg, int t, CryptoPP::Integer pk, CryptoPP::Integer sk, uint64_t &s){

    // std::cout << "msg.size(): " << msg.size() << std::endl;
    msg += "h";

    CryptoPP::Integer g(msg.c_str());
    // std::cout << "g: " << g << std::endl;

    clock_t start_time = clock();
    auto result = ((g * g) % pk);
    clock_t end_time = clock();
    clock_t unit_operation_time = (end_time - start_time);

    // std::cout << "unit_operation_time: " << unit_operation_time << std::endl;

    if(unit_operation_time == 0){
        unit_operation_time = 1;
    }
    s = floor(t * 60 * CLOCKS_PER_SEC / unit_operation_time);
    // std::cout << "s: " << s << std::endl;

    CryptoPP::Integer two = CryptoPP::Integer::Two();
    CryptoPP::Integer big_s(s);

    auto r = a_exp_b_mod_c(two, big_s, sk);
    // std::cout << "r: " << r << std::endl;

    CryptoPP::Integer y = a_exp_b_mod_c(g, r, pk);
    // std::cout << "y: " << y << std::endl;

    return y;
}

CryptoPP::Integer TDF_Eval(std::string msg, int s, CryptoPP::Integer pk){

    msg += "h";

    CryptoPP::Integer g(msg.c_str());
    std::cout << "g: " << g << std::endl;


    CryptoPP::Integer result(1);
    std::cout << "s: " << s << std::endl;
    for(uint64_t i = 0; i < s; i++){
        g = ((g * g) % pk);
    }

    std::cout << "g: " << g << std::endl;

    return g;
}


// TODO store procedure
std::pair<std::vector<std::string>, std::vector<std::string>> store(std::string Por_sk[], std::string file, CryptoPP::Integer pk, CryptoPP::Integer sk, int post_k, std::vector<std::string> &challenge_set, std::vector<std::string> &verify_set){

    challenge_set.clear();
    verify_set.clear();

    std::string challenge = Por_sk[0];
    // std::cout << "challenge size: " << challenge.size() << std::endl;
    int j = 0;
    for(; j < post_k; j++){
        // clock_t s_total = clock();
        challenge_set.emplace_back(challenge);
        // clock_t por_time_s = clock();
        std::string verify = hmac_sha3(challenge, file);
        // clock_t por_time_e = clock();
        verify_set.emplace_back(verify);
        std::string u = sha3_256(verify);
        uint64_t s;
        CryptoPP::Integer d_value = TDF_TrapEval(u, 25, pk, sk, s);
        std::stringstream ss;
        ss << d_value;
        std::string d = ss.str();
        challenge = sha3_256(d);
        std::cout << "j: " << j << " " << challenge << " " << verify << std::endl;
        // clock_t e_total = clock();
        // if(j == 10) {
        //    std::cout << "PoR Time: " << (double)(por_time_e - por_time_s) / CLOCKS_PER_SEC << "s." << std::endl;
        //    std::cout << "Total Time: " << (double )(e_total - s_total) / CLOCKS_PER_SEC << "s." << std::endl;
        // }
    }
    challenge_set.emplace_back(challenge);
    std::string verify = hmac_sha3(challenge, file);
    verify_set.emplace_back(verify);
    std::cout << "j: " << j << " " << challenge << " " << verify << std::endl;
    std::cout << std::endl;
    return std::make_pair(challenge_set, verify_set);
}

// TODO prove procedure
std::pair<std::vector<std::string>, std::vector<std::string>> prove(std::string challenge, std::string file, int post_k, CryptoPP::Integer pk, CryptoPP::Integer sk){
    std::vector<std::string> challenge_set;
    std::vector<std::string> prove_set;
    for(int i = 0; i < post_k; i++){

        challenge_set.emplace_back(challenge);
        std::string prove = hmac_sha3(challenge, file);
        prove_set.emplace_back(prove);
        std::string u = sha3_256(prove);

        CryptoPP::Integer d_value = TDF_Eval(u, 12, pk);
        std::stringstream ss;
        ss << d_value;
        std::string d = ss.str();

        challenge = sha3_256(d);
    }
    return std::make_pair(challenge_set, prove_set);
}

int main (int argc, char* argv[])
{
    const int n_bits = 1024;
    const int PoR_n = 32;

    std::string PoR_sk[PoR_n] = {""};
    PoR_setup(PoR_sk, PoR_n);

    auto pq = setup(n_bits);
    const CryptoPP::Integer p = pq.first;
    const CryptoPP::Integer q = pq.second;

//    std::cout << "PoR_sk[0]: " << PoR_sk[0] << std::endl;

//    std::cout << "p: " << p << std::endl;
//    std::cout << "q: " << q << std::endl;

    // Test of sha3_256
//    std::string msg = "Yoda said, Do or do not. There is no try.";
//    std::string dig = sha3_256(msg);
//    std::cout << dig << std::endl;

    // Test of hmac with sha3_256
//    std::string msg = "Yoda said, Do or do not. There is no try.";
//    std::string cipher = hmac_sha3(PoR_sk[0], msg);
//    std::cout << cipher << std::endl;

    auto keys = TDF_setup(p, q);
    const CryptoPP::Integer pk = keys.first;
    const CryptoPP::Integer sk = keys.second;

//    uint64_t s;
//
//    // Test of Trapdoor delay function implementation
//    std::string msg = "8D42573DD240FE7C9CEC39EF92298128B98BA92B44B9FC9A7369CED7FDA9B1CA";
//    clock_t trap_start = clock();
//    auto trap_re = TDF_TrapEval(msg, 2, pk, sk, s);
//    clock_t trap_finish = clock();
//    std::cout << "Trapdoor evaluation Time: " << (trap_finish - trap_start) << " CPU" << std::endl;
//    clock_t eval_start = clock();
//    CryptoPP::Integer re = TDF_Eval(msg, s, pk);
//    std::cout << "re: " << trap_re << std::endl;
//    std::cout << "re: " << re << std::endl;
//    clock_t eval_finish = clock();
//    std::cout << "CLOCKS_PER_SEC: " << CLOCKS_PER_SEC << std::endl;
//    std::cout << "Evaluation Time: " << (eval_finish - eval_start)/CLOCKS_PER_SEC << "s." << std::endl;
//    if(trap_re == re){
//        std::cout << "Evaluation Success." << std::endl;
//    }
//
//    return 1;

    uint64_t fileSize = 8;
    fileSize *= 1024ul;
    // fileSize *= 1048576ul;

    // std::ifstream in("128mb");
    // std::ostringstream tmp;
    // tmp << in.rdbuf();
    // std::string file = tmp.str();

    // std::string file(32 * 1024 * 1024, 'F');
    std::string file(8 * 1024, 'F');

    std::cout << "original fileSize: " << fileSize << std::endl;
    // std::cout << "fileSize: " << file.length() << std::endl;
//
    int post_k = 6912;

    // std::string file(64*1024*1024, 'F');

    // std::cout << "file size: " << file.size() << std::endl;

    std::vector<std::string> challenge_set;
    std::vector<std::string> verify_set;

    clock_t store_start = clock();
    auto tag= store(PoR_sk, file, pk, sk, post_k, challenge_set, verify_set);

    std::string c_total;
    c_total[0] = 0;
    for (uint64_t i = 0; i < post_k; i++) {
        // std::cout << "challenge " << i << " " << challenge_set[i] << std::endl;
        c_total = c_total + challenge_set[i];
    }
    std::string c_hash = sha3_256(c_total);

    std::string v_total;
    v_total[0] = 0;
    for(uint64_t i = 0; i < post_k; i++) {
        // std::cout << "verify " << i << " " << verify_set[i] << std::endl;
        v_total = v_total + verify_set[i];
    }
    std::string v_hash = sha3_256(v_total);

    std::string tg = sha3_256(c_hash + v_hash);

    std::cout << "tg: " << tg << std::endl;

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock aes_key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock aes_iv(CryptoPP::AES::BLOCKSIZE);
    prng.GenerateBlock(aes_key, aes_key.size());
    prng.GenerateBlock(aes_iv, aes_iv.size());
    std::string C = aes(aes_key, aes_iv, c_hash);
    std::string c_hex;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(c_hex));
    encoder.Put((const CryptoPP::byte *)&C[0], C.size());
    encoder.MessageEnd();
    std::cout << "C: " << c_hex << std::endl;
    clock_t store_end = clock();
    std::cout << "original fileSize: " << fileSize << std::endl;
    std::cout << "Store Time: " << (double)(store_end - store_start) / CLOCKS_PER_SEC << "s." << std::endl;

//    free(raw_row);
//    close(fd);

    return 0;
}