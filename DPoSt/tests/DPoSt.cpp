//
// Created by qyxie on 16/1/2022.
//
#include<stdint.h>
#include<math.h>
#include<cryptopp/rsa.h>
#include<cryptopp/osrng.h>
#include<cryptopp/hex.h>
#include<cryptopp/hmac.h>
#include<cryptopp/sha3.h>
#include<cryptopp/shake.h>
#include<cryptopp/modarith.h>
#include<cryptopp/files.h>
#include<time.h>
#include<iostream>
#include<vector>
#include<sstream>
#include<tinymt64.h>
#include<cryptopp/eccrypto.h>
#include<cryptopp/osrng.h>
#include<cryptopp/nbtheory.h>
#include<cryptopp/cryptlib.h>
#include<cryptopp/algebra.h>
#include<sys/random.h>
#include<vector>
#include<random>
#include<cryptopp/modes.h>
#include<bitset>

#include "muhash.h"

#define ROW_SIZE_BYTES (4194304) // 4MB

struct CHPublicKey{
    CryptoPP::Integer p;
    CryptoPP::Integer q;
    CryptoPP::Integer g;
    CryptoPP::Integer y;
};

struct CHSecretKey{
    CryptoPP::Integer sk;
};

std::string sha3_256(std::string msg){
    std::string digest;
    std::string hex_digest;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_digest));
    CryptoPP::SHA3_256 hash;
    hash.Update((const CryptoPP::byte*)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&digest[0]);
    CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));
    return hex_digest;
}

std::string shake_128(std::string msg){
    std::string digest;
    std::string hex_digest;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_digest));
    CryptoPP::SHAKE128 hash;
    hash.Update((const CryptoPP::byte*)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&digest[0]);
    CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));
    return hex_digest;
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

std::pair<CHPublicKey, CHSecretKey> Keygen(int delta, int n_bits){
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::Integer p, q;
    CryptoPP::PrimeAndGenerator pg(1, prng, 1024);

    p = pg.Prime();
    // q = (p - 1) / 2
    q = pg.SubPrime();

    // g [0, p]  BigInteger
    // g = g ^ 2 % p
    CryptoPP::Integer g(prng, 0, p);
    g = a_exp_b_mod_c(g, CryptoPP::Integer::Two(), p);

    // sk [0, q] BigInteger
    CryptoPP::Integer sk(prng, 0, q);
    // y = g ^ sk % p
    CryptoPP::Integer y = a_exp_b_mod_c(g, sk, p);

    CHPublicKey PK{p, q, g, y};
    CHSecretKey SK{sk};

    return std::make_pair(PK, SK);
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
    if(unit_operation_time == 0){
        unit_operation_time = 1;
    }

    // std::cout << "unit_operation_time: " << unit_operation_time << std::endl;

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

CryptoPP::Integer chameleonHash(std::string msg, CHPublicKey pk, CHSecretKey sk, CryptoPP::Integer r){
    std::string digest;
    std::string hex_digest;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_digest));
    CryptoPP::SHA3_256 hash;
    hash.Update((const CryptoPP::byte*)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&digest[0]);
    CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));
    hex_digest += 'h';
    CryptoPP::Integer m(hex_digest.c_str());
    CryptoPP::Integer ch_digest;
    CryptoPP::Integer tmp_1 = a_exp_b_mod_c(pk.g, m, pk.p);
    CryptoPP::Integer tmp_2 = a_exp_b_mod_c(pk.y, r, pk.p);
    ch_digest = a_times_b_mod_c(tmp_1, tmp_2, pk.p);
    return ch_digest;
}

// TODO forge
// CH=g^m*h^r =g^m'*h^r' mod p，可得m+rx=m'+r'x mod q，继而可计算出r'=(m-m'+rx)*x^(-1) mod q
CryptoPP::Integer forge(std::string ori_msg, std::string new_msg, CHPublicKey pk, CHSecretKey sk, CryptoPP::Integer r){
    CryptoPP::Integer new_r;
    std::string hex_digest_ori;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_digest_ori));
    std::string hex_digest_new;
    CryptoPP::HexEncoder encoder_new(new CryptoPP::StringSink(hex_digest_new));
    std::string ori_digest;
    CryptoPP::SHA3_256 ori_hash;
    ori_hash.Update((const CryptoPP::byte*)ori_msg.data(), ori_msg.size());
    ori_digest.resize(ori_hash.DigestSize());
    ori_hash.Final((CryptoPP::byte*)&ori_digest[0]);
    CryptoPP::StringSource(ori_digest, true, new CryptoPP::Redirector(encoder));
    std::string new_digest;
    CryptoPP::SHA3_256 new_hash;
    new_hash.Update((const CryptoPP::byte*)new_msg.data(), new_msg.size());
    new_digest.resize(new_hash.DigestSize());
    new_hash.Final((CryptoPP::byte*)&new_digest[0]);
    CryptoPP::StringSource(new_digest, true, new CryptoPP::Redirector(encoder_new));
    hex_digest_ori += 'h';
    hex_digest_new += 'h';
    CryptoPP::Integer m(hex_digest_ori.c_str());
    CryptoPP::Integer new_m(hex_digest_new.c_str());
    CryptoPP::Integer diff = m - new_m;
    CryptoPP::Integer inverse = sk.sk.InverseMod(pk.q);
    CryptoPP::Integer tmp = diff * inverse;
    new_r = (tmp + r) % pk.q;
    return new_r;
}

// TODO store procedure
std::pair<std::vector<std::string>, std::vector<std::string>> store(std::string Por_sk[], std::string file, CryptoPP::Integer pk, CryptoPP::Integer sk, CHPublicKey ch_pk, CHSecretKey ch_sk, int post_k, clock_t time_for_seprate){
    std::vector<std::string> challenge_set;
    std::vector<std::string> verify_set;
    challenge_set.clear();
    verify_set.clear();
    std::string challenge = Por_sk[0];
    std::cout << "challenge size: " << challenge.size() << std::endl;
    std::string previous_final_proof;
    std::string final_proof;

    for(int j = 0; j < post_k; j++){

        challenge_set.emplace_back(challenge);
        std::string verify = hmac_sha3(challenge, file);
        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::Integer r(prng, 0, ch_pk.q);
        CryptoPP::Integer ch = chameleonHash(verify, ch_pk, ch_sk, r);
        std::stringstream ss_ch;
        ss_ch << ch;
        std::string d_verify = ss_ch.str();
        

        std::string u = sha3_256(d_verify);
        uint64_t s;
        CryptoPP::Integer d_value = TDF_TrapEval(u, 51, pk, sk, s);
        std::stringstream ss;
        ss << d_value;
        std::string d = ss.str();
        challenge = sha3_256(d);
        
        // separate chain computation
        clock_t start_time = clock();
        if (j == 0) {
            final_proof = verify;
        }
        if (j != 0) {
            CryptoPP::Integer s_value = TDF_TrapEval(previous_final_proof, 51, pk, sk, s);
            std::stringstream ss_2;
            ss_2 << s_value;
            std::string s = ss_2.str();
            std::string final_proof = sha3_256(verify + s);
        }
        clock_t end_time = clock();
        time_for_seprate += (end_time - start_time);

        std::cout << "j: " << j << " " << challenge << " " << verify << std::endl;
        verify_set.emplace_back(final_proof);
        previous_final_proof = final_proof;
    }
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

std::string GetBinaryStringFromHexString (std::string strHex)
{
    std::string sReturn = "";
    unsigned int len = strHex.length();
    for (unsigned int i = 0; i<len; i++)
    {
        switch ( strHex[i])
        {
            case '0': sReturn.append ("0000"); break;
            case '1': sReturn.append ("0001"); break;
            case '2': sReturn.append ("0010"); break;
            case '3': sReturn.append ("0011"); break;
            case '4': sReturn.append ("0100"); break;
            case '5': sReturn.append ("0101"); break;
            case '6': sReturn.append ("0110"); break;
            case '7': sReturn.append ("0111"); break;
            case '8': sReturn.append ("1000"); break;
            case '9': sReturn.append ("1001"); break;
            case 'A': case 'a': sReturn.append ("1010"); break;
            case 'B': case 'b': sReturn.append ("1011"); break;
            case 'C': case 'c': sReturn.append ("1100"); break;
            case 'D': case 'd': sReturn.append ("1101"); break;
            case 'E': case 'e': sReturn.append ("1110"); break;
            case 'F': case 'f': sReturn.append ("1111"); break;
        }
    }
    return sReturn;
}

std::string GetHexStringFromBinaryString (std::string strBinary)
{
    std::string sReturn = "";
    unsigned int len = strBinary.length();
    unsigned int i = 0;
    while(i < len){
        std::string middle = strBinary.substr(i, 4);
        std::string hex;
        std::stringstream ss;
        ss << std::hex << stoi(middle, nullptr, 2);
        ss >> hex;
        sReturn.append(ss.str());
        i = i + 4;
    }
    // std::cout << "sReturn.size(): " << sReturn.size() << std::endl;
    return sReturn;
}

std::string stringXor(std::string str_1, std::string str_2) {
    std::string str1 = GetBinaryStringFromHexString(str_1);
    std::string str2 = GetBinaryStringFromHexString(str_2);
    std::string result;
    for(int i = 0; i < str1.length(); i++){
        char c;
        if(str1[i] == str2[i]) {
            c = '0';
        }else{
            c = '1';
        }
        result += c;
    }
    return result;
}

int main (int argc, char* argv[])
{
    clock_t store_start = clock();
    const int n_bits = 1024;
    const int PoR_n = 32;

    std::string PoR_sk[PoR_n] = {""};
    PoR_setup(PoR_sk, PoR_n);

    auto pq = setup(n_bits);
    const CryptoPP::Integer p = pq.first;
    const CryptoPP::Integer q = pq.second;

    auto keys = TDF_setup(p, q);
    const CryptoPP::Integer pk = keys.first;
    const CryptoPP::Integer sk = keys.second;

    auto [ch_pk, ch_sk] = Keygen(1, 1024);

    // fileSize *= 1048576ul;

    // std::ifstream in("128mb");
    // std::ostringstream tmp;
    // tmp << in.rdbuf();
    // std::string file = tmp.str();

    // std::string file(32 * 1024 * 1024, 'F');
    uint64_t fileSize = 2;
    fileSize *= 1024ul;
    std::string file(2 * 1024, 'F');

    std::cout << "original fileSize: " << fileSize << std::endl;

    int block_number;

    // const static uint64_t ROW_SIZE_64 = ROW_SIZE_BYTES / 8;

    block_number = ceil(fileSize / 64);

    std::vector<std::string> data_blocks;
    std::cout << "Generate Blocks: " << block_number << std::endl;
    for (int i = 0; i < block_number; i++) {
        std::string str = file.substr(i * 64, 64);
        data_blocks.push_back(str);
    }
    auto indices = std::vector<int>();
    for (int i = 0; i < block_number; i++)
        indices.emplace_back(i);
    std::cout << "Blocks generate over." << std::endl;

    int k = 847;

    int r_b = ceil(1 * block_number);

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock W(CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::SecByteBlock Z(CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

    prng.GenerateBlock(W, W.size());
    prng.GenerateBlock(Z, Z.size());
    prng.GenerateBlock(iv, iv.size());

    CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption e;
    e.SetKeyWithIV(W, W.size(), iv);

    std::string permutation;
    std::string challenge_nonce;

    CryptoPP::StringSource s_p("0", true,
                   new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(permutation)
                   ) // StreamTransformationFilter
    ); // StringSource
    e.SetKeyWithIV(Z, Z.size(), iv);
    CryptoPP::StringSource s_c("0", true,
                             new CryptoPP::StreamTransformationFilter(e,
                                                                      new CryptoPP::StringSink(challenge_nonce)
                                                                      ) // StreamTransformationFilter
    ); // StringSource

    std::string hex_challenge;
    std::string hex_permutation;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_challenge));
    encoder.Put((const CryptoPP::byte*)&challenge_nonce[0],challenge_nonce.size());
    encoder.MessageEnd();
    std::cout << "HEX CHALLENGE: " << hex_challenge << " " << hex_challenge.size() << std::endl;
    CryptoPP::HexEncoder encoder_p(new CryptoPP::StringSink(hex_permutation));
    encoder_p.Put((const CryptoPP::byte*)&permutation[0],permutation.size());
    encoder_p.MessageEnd();
    std::cout << "HEX PERMUTATION: " << hex_permutation << std::endl;


    std::vector<std::string> challenge_set;
    std::vector<std::string> permutation_set;
    std::vector<std::string> verify_set;
    std::vector<CryptoPP::Integer> r_set;

    challenge_set.clear();
    permutation.clear();
    verify_set.clear();

    challenge_set.emplace_back(challenge_nonce);
    permutation_set.emplace_back(permutation);

    clock_t time_for_seprate = 0;
    std::string previous_final_proof;
    std::string final_proof;

    for(int j = 0; j < k; j++) {
        char *ptr;
        std::mt19937 mt(std::strtoul(permutation.c_str(), &ptr, permutation.size()));
        shuffle(indices.begin(), indices.end(), mt);
        std::string verify;
        for(int i = 0; i < r_b; i++){
            std::string plain = challenge_nonce + std::to_string(indices[i]) + data_blocks[indices[i]];
            std::string single_re = sha3_256(plain);
            if(i == 0){
                verify = single_re;
            }else{
                verify = stringXor(verify, single_re);
                verify = GetHexStringFromBinaryString(verify);
            }
        }
        verify_set.emplace_back(verify);
        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::Integer r(prng, 0, ch_pk.q);
        r_set.push_back(r);
        CryptoPP::Integer ch = chameleonHash(verify, ch_pk, ch_sk, r);
        std::stringstream ss_ch;
        ss_ch << ch;
        std::string d_verify = ss_ch.str();
        std::string u = sha3_256(d_verify);
        uint64_t s;
        CryptoPP::Integer d_value = TDF_TrapEval(u, 51, pk, sk, s);
        std::stringstream ss;
        ss << d_value;
        std::string d = ss.str();
        challenge_nonce = shake_128(d);
        challenge_set.push_back(challenge_nonce);
        CryptoPP::Integer d_u = TDF_TrapEval(permutation, 51, pk, sk, s);
        std::stringstream ss_permutation;
        ss_permutation << d_u;
        std::string d_permutation = ss.str();
        permutation = shake_128(d_permutation);
        // separate chain computation
        clock_t start_time = clock();
        if (j == 0) {
            final_proof = verify;
        }
        if (j != 0) {
            CryptoPP::Integer s_value = TDF_TrapEval(previous_final_proof, 51, pk, sk, s);
            std::stringstream ss_2;
            ss_2 << s_value;
            std::string s = ss_2.str();
            std::string final_proof = sha3_256(verify + s);
        }
        clock_t end_time = clock();
        time_for_seprate += (end_time - start_time);
        verify_set.emplace_back(final_proof);
        previous_final_proof = final_proof;
        std::cout << "j: " << j << " " << challenge_nonce << " " << permutation << " " << verify << std::endl;
    }

    std::string tag;
    for (uint64_t i = 0; i < k; i++) {
        if (i == 0) {
            tag = sha3_256(challenge_set[i] + std::to_string(i) + verify_set[i]);
        } else {
            std::string single_hash = sha3_256(challenge_set[i] + std::to_string(i) + verify_set[i]);
            tag = stringXor(tag, single_hash);
            tag = GetHexStringFromBinaryString(tag);
        }
    }

    std::cout << "Tag: " << tag << std::endl;

    // std::string c_total;
    // for (uint64_t i = 0; i < k; i++) {
    //     c_total = c_total + challenge_set[i];
    // }
    // std::string c_hash = sha3_256(c_total);
    // std::cout << "c_total: " << c_hash << std::endl;

    // std::string v_total = verify_set[0];
    // auto mh = MuHash3072((unsigned char*)(v_total.data()), v_total.length());
    // for(uint64_t i = 0; i < k; i++) {
    //     mh.Insert((unsigned char *)verify_set[i].data(), verify_set[i].length());
    //     // std::cout << "i: " << i << " Hex: " << mh.FinalizeBase64() << std::endl;
    // }
    // std::cout << "Final hex: " << mh.FinalizeBase64() << std::endl;

    clock_t store_end = clock();
    std::cout << "Store Time: " << (double)(store_end - store_start) / CLOCKS_PER_SEC << "s." << std::endl;

    std::cout << "Seprate compute Time: " << (double)(time_for_seprate) / CLOCKS_PER_SEC << "s." << std::endl;

    int update_number = ceil(0.6 * block_number);
    
    std::string original_db = data_blocks[10];
    std::string new_db = std::string(64, '8');
    std::cout << "original length: " << original_db.length() << " Now length: " << new_db.length() << std::endl;
    std::string plain = challenge_nonce + std::to_string(10) + original_db;
    std::string original_re = sha3_256(plain);
    std::string plain_new = challenge_nonce + std::to_string(10) + new_db;
    std::string new_re = sha3_256(plain_new);

    clock_t update_start = clock();
    for(int j = 0; j < k; j++){
        std::string ori_verify = verify_set[j];
        std::string verify = verify_set[j];

        for(int i = 0; i < update_number; i++) {
            std::string middle = stringXor(verify, original_re);
            middle = GetHexStringFromBinaryString(middle);
            std::string final = stringXor(middle, new_re);
            final = GetHexStringFromBinaryString(final);

            CryptoPP::Integer ori_r = r_set[j];
            CryptoPP::Integer new_r = forge(ori_verify, final, ch_pk, ch_sk, ori_r);

            clock_t r_ = clock();

            std::string hash_1 = sha3_256(challenge_set[j] + std::to_string(j) + ori_verify);
            std::string hash_2 = sha3_256(challenge_set[j] + std::to_string(j) + final);

            std::string middle_2 = stringXor(tag, hash_1);
            middle_2 = GetHexStringFromBinaryString(middle_2);
            std::string tag = stringXor(tag, middle_2);
            tag = GetHexStringFromBinaryString(tag);
        }
        
        // mh.Remove((unsigned char *)ori_verify.data(), ori_verify.size());
        // if(j==0){
        //     clock_t e_2 = clock();
        //     std::cout << "single time: " << (double)(e_2 - s_) /CLOCKS_PER_SEC << std::endl;
        //     std::cout << "single remove time: " << (double)(e_2 - r_) /CLOCKS_PER_SEC << std::endl;
        // }
        // mh.Insert((unsigned char *)final.data(), final.size());
        // if(j==0){
        //     clock_t e_ = clock();
        //     std::cout << "single time: " << (double)(e_ - s_) /CLOCKS_PER_SEC << std::endl;
        // }
        // std::cout << "j: " << j << " ori_verify: " << ori_verify << " new_verify: " << final << std::endl;
    }
    clock_t update_end = clock();
    std::cout << "Update Time: " << (double)(update_end - update_start) / CLOCKS_PER_SEC << "s." << std::endl;

    return 0;
}