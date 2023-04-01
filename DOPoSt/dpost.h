#include "abycore/circuit/arithmeticcircuits.h"
#include "abycore/circuit/circuit.h"
#include "abycore/aby/abyparty.h"
#include <math.h>
#include <cassert>
#include <cryptopp/integer.h>
#include <iostream>
#include <sstream>

#define ALICE 	"ALICE"
#define BOB 	"BOB"

/**
 \param		role 		role played by the program which can be server or client part.
 \param 	address 	IP Address
 \param 	seclvl 		Security level
 \param 	bitlen		Bit length of the inputs
 \param 	nthreads	Number of threads
 \param		mt_alg		The algorithm for generation of multiplication triples
 \param 	sharing		Sharing type object
 \param     file_shares Sharing of file
 \param     c_shares    Sharing of the c_1
 \param     e_shares    Sharing of the e
 \brief		This function is used for running a testing environment for solving PoSt problem
 */
uint64_t test_DPoSt_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t file_shares_1, uint64_t file_shares_2, uint64_t e_shares_1, uint64_t e_shares_2);

uint64_t test_mimc_imple_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t msg_shares_1, uint64_t msg_shares_2);

uint64_t test_exp_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t b_shares_1, uint64_t b_shares_2, uint64_t a_shares_1, uint64_t a_shares_2);

uint64_t Product(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t a_shares_1, uint64_t a_shares_2, uint64_t b_shares_1, uint64_t b_shares_2);

uint64_t test_exp_b_a_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t b, uint64_t a_shares_1, uint64_t a_shares_2);

uint64_t Product_inv(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t b_shares_1, uint64_t b_shares_2, uint64_t n);

uint64_t test_xor_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t a_shares_1, uint64_t a_shares_2, uint64_t b_shares_1, uint64_t b_shares_2);

uint64_t test_chameleon_hash_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t m_shares_1, uint64_t m_shares_2, uint64_t h, uint64_t r, uint64_t g);

uint64_t test_sub_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t a_shares_1, uint64_t a_shares_2, uint64_t b_shares_1, uint64_t b_shares_2);

uint64_t test_add_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t a_shares_1, uint64_t a_shares_2, uint64_t b_shares_1, uint64_t b_shares_2);

uint64_t find_collision_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		    uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t ori_re_shares_1, uint64_t ori_re_shares_2, uint64_t curr_re_shares_1, uint64_t curr_re_shares_2, uint64_t r, uint64_t g, uint64_t x_shares_1, uint64_t x_shares_2);