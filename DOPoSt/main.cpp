#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "abycore/aby/abyparty.h"
#include "dpost.h"
#include<stdint.h>
#include<math.h>
#include<cryptopp/rsa.h>
#include<cryptopp/osrng.h>
#include<cryptopp/hex.h>
#include<cryptopp/hmac.h>
#include<cryptopp/sha3.h>
#include<cryptopp/modarith.h>
#include<cryptopp/files.h>
#include<time.h>
#include<iostream>
#include<vector>
#include<sstream>
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


#define ROW_SIZE_BYTES (4194304) // 4MB

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, std::string* address,
		uint16_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;

	parsing_ctx options[] =
			{ { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false }, {
					(void*) nvals, T_NUM, "n",
					"Number of parallel operation elements", false, false }, {
					(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false,
					false }, { (void*) secparam, T_NUM, "s",
					"Symmetric Security Bits, default: 128", false, false }, {
					(void*) address, T_STR, "a",
					"IP-address, default: localhost", false, false }, {
					(void*) &int_port, T_NUM, "p", "Port, default: 7766", false,
					false }, { (void*) test_op, T_NUM, "t",
					"Single test (leave out for all operations), default: off",
					false, false } };

	if (!parse_options(argcp, argvp, options,
			sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	return 1;
}

// std::string sha3_256(std::string msg){
//     std::string digest;
//     // CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
//     std::string hex_digest;

//     CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_digest));

//     CryptoPP::SHA3_256 hash;
//     hash.Update((const byte*)msg.data(), msg.size());
//     digest.resize(hash.DigestSize());
//     hash.Final((byte*)&digest[0]);

//     CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));
//     return hex_digest;
//     // return digest;
// }

int main(int argc, char** argv) {

    e_role role;
	uint32_t bitlen = 32, nvals = 64, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
		&port, &test_op);

	seclvl seclvl = get_sec_lvl(secparam);

	// uint64_t fileSize = 32;
    // fileSize *= 1048576ul;
    // std::string file(32 * 1024 * 1024, 'F');
	
	// CryptoPP::AutoSeededRandomPool prng;
    // CryptoPP::Integer p, q;
    // CryptoPP::PrimeAndGenerator pg(1, prng, 128);
    // p = pg.Prime();
    // // q = (p - 1) / 2
    // q = pg.SubPrime();

	// // TDF Setup
	// CryptoPP::Integer tdf_pk = p * q;
    // CryptoPP::Integer one(1);
    // CryptoPP::Integer tdf_sk = (p - one) * (q - one);
	// uint64_t t = 28;
	// CryptoPP::Integer e = a_exp_b_mod_c(CryptoPP::Integer::Two(), t, tdf_sk);

	// // Chameleon Hash Setup
    // // g [0, p]  BigInteger
    // // g = g ^ 2 % p
    // CryptoPP::Integer g(prng, 0, p);
    // g = a_exp_b_mod_c(g, CryptoPP::Integer::Two(), p);
    // // sk [0, q] BigInteger
    // CryptoPP::Integer ch_sk(prng, 0, q);
    // // y = g ^ sk % p
    // CryptoPP::Integer ch_y = a_exp_b_mod_c(g, ch_sk, p);

    // int block_number;
    // const static uint64_t ROW_SIZE_64 = ROW_SIZE_BYTES / 8;
    // block_number = ceil(fileSize / ROW_SIZE_64);

	// std::cout << block_number << std::endl;

    // std::cout << "Generate Blocks: " << block_number << std::endl;
	
	uint64_t file_shares_1 = 64;
	uint64_t file_shares_2 = 63;

    uint64_t e_shares_1 = 1000;
    uint64_t e_shares_2 = 1500;

    uint64_t re = test_DPoSt_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, file_shares_1, file_shares_2, e_shares_1, e_shares_2);

	return 0;
}