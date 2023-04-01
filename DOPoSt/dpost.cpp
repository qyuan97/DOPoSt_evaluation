#include "dpost.h"
#include "abycore/circuit/arithmeticcircuits.h"
#include "abycore/circuit/booleancircuits.h"
#include "abycore/sharing/sharing.h"


uint64_t test_DPoSt_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t file_shares_1, uint64_t file_shares_2, uint64_t e_shares_1, uint64_t e_shares_2)
{
        int k = 1;

        clock_t exp_start_time = clock();
        uint64_t block_number = 2;

        std::vector<uint64_t> challenge_set;
        std::vector<uint64_t> verify_set;
        std::vector<uint64_t> r_set;

        uint64_t max_number = pow(2, 64);
        std::cout << "max_number: " << max_number << std::endl;

        for(int j = 0; j < k; j++) {
            // DPDP
            uint64_t challenge_nonce = 0;
            uint64_t verify = 0;
            for(int i = 0; i < block_number; i++) 
            {
                // std::string plain = std::to_string(challenge_nonce) + std::to_string(indices[i]) + data_blocks[indices[i]];
                srand(time(NULL));
                uint64_t plain_shares_1 = rand() % 2 + 1;
                uint64_t plain_shares_2 = rand() % 3 + 4;
                // uint64_t plain_shares_1 = 3;
                // uint64_t plain_shares_2 = 4;
                std::cout << "plain shares 1: " << plain_shares_1 << std::endl;
                std::cout << "plain_shares_2: " << plain_shares_2 << std::endl;
                uint64_t single_re = test_mimc_imple_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, plain_shares_1, plain_shares_2);
                std::cout << "single_re: " << single_re << std::endl;
                if(i == 0){
                    verify = single_re;
                } else {
                    uint64_t verify_shares_1  = (rand()) % (verify - 1) + 1;
                    uint64_t verify_shares_2 = verify - verify_shares_1;
                    uint64_t single_re_shares_1 = (rand()) % (single_re - 1) + 1;
                    uint64_t single_re_shares_2 = single_re - single_re_shares_1;
                    std::cout << "verify_shares_1:" << verify_shares_1 << std::endl;
                    std::cout << "verify_shares_2:" << verify_shares_2 << std::endl;
                    std::cout << "single_re_shares_1:" << single_re_shares_1 << std::endl;
                    std::cout << "single_re_shares_2:" << single_re_shares_2 << std::endl;
                    verify = test_xor_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_BOOL, verify_shares_1, verify_shares_2, single_re_shares_1, single_re_shares_2);
                    std::cout << "final verify: " << verify << std::endl;
                }
            }

            std::cout << "verify: " << verify << std::endl;

            verify_set.push_back(verify);
            // Chameleon Hash
            // uint64_t r = (rand()) % (verify) + 1;
            uint64_t r = 3;
            r_set.push_back(r);

            srand(time(NULL));
            uint64_t verify_shares_1  = (rand()) % (verify - 1) + 1;
            uint64_t verify_shares_2 = verify - verify_shares_1;
            std::cout << "verify_shares_1: " << verify_shares_1 << std::endl;
            std::cout << "verify_shares_2: " << verify_shares_2 << std::endl;

            uint64_t h = 3;
            uint64_t g = 3;
            uint64_t ch = test_chameleon_hash_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, verify_shares_1, verify_shares_2, h, r, g);

            std::cout << "ch: " << ch << std::endl;

            uint64_t ch_shares_1  = (rand()) % (ch - 1) + 1;
            uint64_t ch_shares_2 = ch - ch_shares_1;
            uint64_t tdf_out = test_exp_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, ch_shares_1, ch_shares_2, e_shares_1, e_shares_2);

            // CryptoPP::Integer big_ch(ch);
            // CryptoPP::Integer big_e(e_shares_1 + e_shares_2);
            // // max_number = pow(2, 63);
            // // std::ostringstream os;
            // // os << max_number;
            // // CryptoPP::Integer big_max_number(os.str().c_str());
            // CryptoPP::Integer x = a_exp_b_mod_c(big_ch, big_e, big_max_number);
            // uint64_t = (uint64_t)pow(ch, e);
            // std::cout << "x: " << x << std::endl;

            std::cout << "tdf_out: " << tdf_out << std::endl;
            // Hash
            uint64_t tdf_shares_1  = (rand()) % (tdf_out - 1) + 1;
            uint64_t tdf_shares_2 = tdf_out - tdf_shares_1;
            uint64_t challenge = test_mimc_imple_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, tdf_shares_1, tdf_shares_2);
            std::cout << "challenge: " << challenge << std::endl;
        }
        clock_t exp_end_time = clock();
	    std::cout << "execute here 2. " << std::endl;
        clock_t exp_time = exp_end_time - exp_start_time;
        std::cout << "total time: " << (double)exp_time / (CLOCKS_PER_SEC) << " s." << std::endl;
        std::cout << "execute here 2. " << std::endl;

        uint64_t tag =  rand() % 1000 + 1;
        uint64_t origin_verify =  rand() % 500 + 1;
        // uint64_t update_number = 0.3 * 256;
        uint64_t update_number = 1;
        exp_start_time = clock();
        for(int i = 0; i < update_number; i++) {
             srand(time(NULL));
             uint64_t plain_shares_1 = rand() % 2 + 1;
             uint64_t plain_shares_2 = rand() % 3 + 4;
             uint64_t current_re = test_mimc_imple_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, plain_shares_1, plain_shares_2);
             std::cout << "current_re: " << current_re << std::endl;

            uint64_t ori_re_shares_1   = (rand()) % (origin_verify - 1) + 1;
            uint64_t ori_re_shares_2 = origin_verify - ori_re_shares_1;
            uint64_t curr_re_shares_1 = (rand()) % (current_re - 1) + 1;
            uint64_t curr_re_shares_2 = current_re - curr_re_shares_1;
            uint64_t middle = test_xor_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_BOOL, ori_re_shares_1, ori_re_shares_2, curr_re_shares_1, curr_re_shares_2);

            uint64_t tag_shares_1  = (rand()) % (tag - 1) + 1;
            uint64_t tag_shares_2 = tag - tag_shares_1;
            uint64_t middle_shares_1  = (rand()) % (middle - 1) + 1;
            uint64_t middle_shares_2 = middle - middle_shares_1;

            uint64_t final_tag = test_xor_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_BOOL, tag_shares_1, tag_shares_2, middle_shares_1, middle_shares_2);

            uint64_t g  = 50;
            uint64_t r = 60;
            uint64_t x_shares_1 = 5;
            uint64_t x_shares_2 = 7;

            uint64_t new_r = find_collision_circuit(role, address, port, seclvl, bitlen, nthreads, mt_alg, sharing, ori_re_shares_1, ori_re_shares_2, curr_re_shares_1, curr_re_shares_2, r, g, x_shares_1, x_shares_2);

            std::cout << "final tag: " << final_tag << std::endl;
            std::cout << "new r: " << new_r << std::endl;
        }
        exp_end_time = clock();
	    std::cout << "execute here 2. " << std::endl;
        exp_time = (exp_end_time - exp_start_time);
        std::cout << "update total time: " << (double)exp_time / (CLOCKS_PER_SEC) << " s." << std::endl;
        std::cout << "execute here 2. " << std::endl;
        return 0;
}
	

uint64_t test_mimc_imple_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t msg_shares_1, uint64_t msg_shares_2)
{
    ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
	share *s_msg_shares_1, *s_msg_shares_2, *s_out;
	uint64_t output;
    if(role == SERVER) {
		s_msg_shares_1 = circ->PutINGate(msg_shares_1, bitlen, SERVER);
		s_msg_shares_2 = circ->PutDummyINGate(bitlen);
	} else { //role == CLIENT
		s_msg_shares_2 = circ->PutINGate(msg_shares_2, bitlen, CLIENT);
		s_msg_shares_1 = circ->PutDummyINGate(bitlen);
	}
    ArithmeticCircuit* ac = (ArithmeticCircuit*)circ;
    share *tmp = ac->PutADDGate(s_msg_shares_1, s_msg_shares_2);
    share *tp, *tp_2;
    uint64_t mimc_r = 73;
    for(int i = 0; i < mimc_r; i++){ 
        tp = ac->PutMULGate(tmp, tmp);
        tp_2 = ac->PutMULGate(tp, tmp);
        tmp = tp_2;
    }
	s_out = circ->PutOUTGate(tp_2, ALL);
	party->ExecCircuit();
	output = s_out->get_clear_value<uint32_t>();
    delete party;
    return output;
}


uint64_t test_exp_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t b_shares_1, uint64_t b_shares_2, uint64_t a_shares_1, uint64_t a_shares_2)
{
           srand(time(NULL));
           uint64_t g  = (rand()) % (b_shares_1 + b_shares_2 - 1) + 1;
           uint64_t r = (rand()) % (a_shares_1 + a_shares_2 - 1) + 1;
           uint64_t r_shares_1  = (rand()) % (r - 1) + 1;
           uint64_t r_shares_2 = r - r_shares_1;
           std::cout << "g: " << g << std::endl;
           std::cout << "r: " << r << std::endl;
           std::cout << "r_shares_1: " << r_shares_1 << std::endl;
           std::cout << "r_shares_2: " << r_shares_2 << std::endl;

           // test_exp_b_a_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, 2, 3, 4);
           test_exp_b_a_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, g, r_shares_1, r_shares_2);
           uint64_t r_bar = 20;
           std::cout << "r_bar: " << r_bar << std::endl;
           uint64_t r_bar_shares_1  = (rand()) % (r_bar - 1) + 1;
           uint64_t r_bar_shares_2 = r_bar - r_bar_shares_1;
           std::cout << "r_bar_shares_1: " << r_bar_shares_1 << std::endl;
           std::cout << "r_bar_shares_2: " << r_bar_shares_2 << std::endl;

           uint64_t c = Product(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, r_bar_shares_1, r_bar_shares_2, b_shares_1, b_shares_2);
           std::cout << "c: " << c << std::endl;

           // test_exp_b_a_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, 2, 3, 4);
           test_exp_b_a_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, c, a_shares_1, a_shares_2);
           uint64_t c_dot = 30;
           uint64_t c_dot_shares_1  = (rand()) % (c_dot - 1) + 1;
           uint64_t c_dot_shares_2 = c_dot - c_dot_shares_1;
           std::cout << "c_dot: " << c_dot << std::endl;
           std::cout << "c_dot_shares_1: " << c_dot_shares_1 << std::endl;
           std::cout << "c_dot_shares_2: " << c_dot_shares_2 << std::endl;

           uint64_t e = Product(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, r_shares_1, r_shares_2, a_shares_1, a_shares_2);       
           std::cout << "e_: " << e << std::endl;  
           uint64_t e_shares_1  = ((rand()) % (e - 1)) + 1;
           uint64_t e_shares_2 = e - e_shares_1;
           std::cout << "e_shares_1: " << e_shares_1 << std::endl;
           std::cout << "e_shares_2: " << e_shares_2 << std::endl;

           // test_exp_b_a_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, 2, 3, 4);
           test_exp_b_a_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, g, e_shares_1, e_shares_2);
           uint64_t tmp_final = 50;
           std::cout << "tmp_final: " << tmp_final << std::endl;

           uint64_t final_result = Product_inv(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, c_dot_shares_1, c_dot_shares_2, tmp_final);         
           std::cout << "final_result: " << final_result << std::endl;
           return final_result;
}

uint64_t Product_inv(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t b_shares_1, uint64_t b_shares_2, uint64_t n){
    ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
    std::vector<Sharing*>&sharings = party->GetSharings();    
    Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();

    srand(time(NULL));
    uint64_t r  = (rand()) % (n - 1) + 1;
    uint64_t r_shares_1 = (rand()) % (r - 1) + 1;
    uint64_t r_shares_2 = r - r_shares_1;
    std::cout << "inv_r: " << r << std::endl;
    std::cout << "inv_r_shares_1: " << r_shares_1 << std::endl;
    std::cout << "inv_r_shares_2: " << r_shares_2 << std::endl;

    uint64_t a_shares_1 =  (rand()) % (n - 1) + 1;
    uint64_t a_shares_2 = n - a_shares_1;
    std::cout << "a_shares_1: " << a_shares_1 << std::endl;
    std::cout << "a_shares_2: " << a_shares_2 << std::endl;
    std::cout << "b_shares_1: " << b_shares_1 << std::endl;
    std::cout << "b_shares_2: " << b_shares_2 << std::endl;

    share *s_r_shares_1, *s_r_shares_2, *s_a_shares_1, *s_a_shares_2;
    if(role == SERVER) {
        s_r_shares_1 = circ->PutINGate(r_shares_1, bitlen, SERVER);
        s_r_shares_2 = circ->PutDummyINGate(bitlen);
        s_a_shares_1 = circ->PutINGate(a_shares_1, bitlen, SERVER);
        s_a_shares_2 = circ->PutDummyINGate(bitlen);
    } else { //role == CLIENT
        s_r_shares_2 = circ->PutINGate(r_shares_2, bitlen, CLIENT);
        s_r_shares_1 = circ->PutDummyINGate(bitlen);
        s_a_shares_2 = circ->PutINGate(a_shares_2, bitlen, CLIENT);
        s_a_shares_1 = circ->PutDummyINGate(bitlen);
    }
    ArithmeticCircuit *ac = (ArithmeticCircuit*)circ;
    share *tmp = ac->PutADDGate(s_r_shares_1, s_r_shares_2);
    share *tmp_2 = ac->PutADDGate(s_a_shares_1, s_a_shares_2);
    share *out = ac->PutMULGate(tmp, tmp_2);
    out = circ->PutOUTGate(out, ALL);
    party->ExecCircuit();
    uint64_t c = out->get_clear_value<uint32_t>();
    
    party->Reset();
    circ = sharings[sharing]->GetCircuitBuildRoutine();
    share *s_b_shares_1, *s_b_shares_2;
    if(role == SERVER) {
        s_r_shares_1 = circ->PutINGate(r_shares_1, bitlen, SERVER);
        s_r_shares_2 = circ->PutDummyINGate(bitlen);
        s_b_shares_1 = circ->PutINGate(b_shares_1, bitlen, SERVER);
        s_b_shares_2 = circ->PutDummyINGate(bitlen);
    } else { //role == CLIENT
        s_r_shares_2 = circ->PutINGate(r_shares_2, bitlen, CLIENT);
        s_r_shares_1 = circ->PutDummyINGate(bitlen);
        s_b_shares_2 = circ->PutINGate(b_shares_2, bitlen, CLIENT);
        s_b_shares_1 = circ->PutDummyINGate(bitlen);
    }
    ac = (ArithmeticCircuit*)circ;
    tmp = ac->PutADDGate(s_r_shares_1, s_r_shares_2);
    tmp_2 = ac->PutADDGate(s_b_shares_1, s_b_shares_2);
    out = ac->PutMULGate(tmp, tmp_2);
    out = circ->PutOUTGate(out, ALL);
    party->ExecCircuit();
    uint64_t out_2 = out->get_clear_value<uint32_t>();
    std::cout << "out_2: " << out_2 << std::endl; 
    std::cout << "(out_2 > c): " << (out_2 > c) << std::endl;
    delete party;

    std::cout << "c:  " << c << std::endl;
    double part1 = 1.0 / (double)c;
    double part2 = double(out_2) + pow(2, 64);
    std::cout << "part1: " << part1 << std::endl;
    std::cout << "part2: " << part2 << std::endl; 
    double final_result = part1 * part2;
    std::cout << "final_result: " << final_result << std::endl;
    if(final_result < 3){
        return 3;
    }
    uint64_t re;
    memcpy(&re, &final_result, sizeof(re));
    return re;
}

uint64_t Product(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t a_shares_1, uint64_t a_shares_2, uint64_t b_shares_1, uint64_t b_shares_2)
{
    ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
    std::vector<Sharing*>&sharings = party->GetSharings();    
    Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
    share *s_a_shares_1, *s_a_shares_2, *s_b_shares_1, *s_b_shares_2;
    uint64_t output;
    if(role == SERVER) {
        s_a_shares_1 = circ->PutINGate(a_shares_1, bitlen, SERVER);
        s_a_shares_2 = circ->PutDummyINGate(bitlen);
        s_b_shares_1 = circ->PutINGate(b_shares_1, bitlen, SERVER);
        s_b_shares_2 = circ->PutDummyINGate(bitlen);
    } else { //role == CLIENT
        s_a_shares_2 = circ->PutINGate(a_shares_2, bitlen, CLIENT);
        s_a_shares_1 = circ->PutDummyINGate(bitlen);
        s_b_shares_2 = circ->PutINGate(b_shares_2, bitlen, CLIENT);
        s_b_shares_1 = circ->PutDummyINGate(bitlen);
    }
    ArithmeticCircuit *ac = (ArithmeticCircuit*)circ;
    share *tmp = ac->PutADDGate(s_a_shares_1, s_a_shares_2);
    share *tmp_2 = ac->PutADDGate(s_b_shares_1, s_b_shares_2);
    share *out = ac->PutMULGate(tmp, tmp_2);
    out = circ->PutOUTGate(out, ALL);
    party->ExecCircuit();
    output = out->get_clear_value<uint32_t>();
    std::cout << "exp product: " << output << std::endl;
    delete party;
    return output;
}

uint64_t test_exp_b_a_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t b, uint64_t a_shares_1, uint64_t a_shares_2)
    {
        ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
        std::vector<Sharing*>& sharings = party->GetSharings();
        Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
        share *s_a, *s_b, *s_out;
        uint64_t c, output;
        ArithmeticCircuit *ac = (ArithmeticCircuit*) circ;
        if(role == SERVER) {
            c = pow(b, a_shares_1);
            std::cout << "c_product: " << c << std::endl;
            s_a = ac->PutINGate(c, bitlen, SERVER);
            s_b = ac->PutDummyINGate(bitlen);
        } else { //role == CLIENT
            c = pow(b, a_shares_2);
            std::cout << "c_product: " << c << std::endl;
            s_b = ac->PutINGate(c, bitlen, CLIENT);
            s_a = ac->PutDummyINGate(bitlen);
        }
        s_out = ac->PutMULGate(s_a, s_b);
        s_out = ac->PutOUTGate(s_out, ALL);
        party->ExecCircuit();
        output = s_out->get_clear_value<uint32_t>();
        return output;
}

// void test_exp_b_a_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
// 		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t b, uint64_t a_shares_1, uint64_t a_shares_2)
// {
//     ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
//     std::vector<Sharing*>& sharings = party->GetSharings();
//     Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
//     share *s_a, *s_b, *s_out;
//     uint64_t c;

//     std::string c_string;
//     CryptoPP::Integer big_b(b);
//     uint64_t max_number = pow(2, 64);
//     std::ostringstream os;
//     os << max_number;
//     CryptoPP::Integer big_max_number(os.str().c_str());

//     CryptoPP::Integer big_shares_1(a_shares_1);
//     CryptoPP::Integer big_c = a_exp_b_mod_c(big_b, big_shares_1, big_max_number);
//     std::ostringstream ostream;
//     ostream << big_c;
//     c_string = ostream.str();
//     c = std::atoll(c_string.c_str());
//     std::cout << "exp b_a share1 c_product: " << c << std::endl;

//     CryptoPP::Integer big_shares_2(a_shares_2);
//     CryptoPP::Integer big_c_2 = a_exp_b_mod_c(big_b, big_shares_2, big_max_number);
//     std::ostringstream ostream2;
//     ostream2 << big_c_2;
//     c_string = ostream2.str();
//     uint64_t c_2 = std::atoll(c_string.c_str());
//     std::cout << "exp b_a share2 c_product: " << c_2 << std::endl;

//     if (c == c_2) {
//         c_2 = c_2 - 1;
//     }

//     if(role == SERVER) {
//         s_a = circ->PutINGate(c, bitlen, SERVER);
//         s_b = circ->PutDummyINGate(bitlen);
//     } else { //role == CLIENT
//         s_b = circ->PutINGate(c_2, bitlen, CLIENT);
//         s_a = circ->PutDummyINGate(bitlen);
//     }
//     ArithmeticCircuit *ac = (ArithmeticCircuit*) circ;
//     s_out = ac->PutMULGate(s_a, s_b);
//     s_out = ac->PutOUTGate(s_out, ALL);
//     party->ExecCircuit();
//     uint64_t output = s_out->get_clear_value<uint64_t>();
//     std::cout << "exp b_a output: " << output << std::endl;
//     delete party;
//         // return 10;
// }

uint64_t test_xor_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t a_shares_1, uint64_t a_shares_2, uint64_t b_shares_1, uint64_t b_shares_2)
{
    ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
    std::vector<Sharing*>& sharings = party->GetSharings();
    Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
    share *s_a_shares_1, *s_a_shares_2, *s_b_shares_1, *s_b_shares_2, *s_out;
    uint32_t output;
     if(role == SERVER) {
        s_a_shares_1 = circ->PutINGate(a_shares_1, bitlen, SERVER);
        s_a_shares_2 = circ->PutDummyINGate(bitlen);
        s_b_shares_1 = circ->PutINGate(b_shares_1, bitlen, SERVER);
        s_b_shares_2 = circ->PutDummyINGate(bitlen);
    } else { //role == CLIENT
        s_a_shares_2 = circ->PutINGate(a_shares_2, bitlen, CLIENT);
        s_a_shares_1 = circ->PutDummyINGate(bitlen);
        s_b_shares_2 = circ->PutINGate(b_shares_2, bitlen, CLIENT);
        s_b_shares_1 = circ->PutDummyINGate(bitlen);
    }
    BooleanCircuit *bc = (BooleanCircuit*) circ;
    share *tmp = bc->PutADDGate(s_a_shares_1, s_a_shares_2);
    share *tmp2 = bc->PutADDGate(s_b_shares_1, s_b_shares_2);
    share *out = bc->PutXORGate(tmp, tmp2);
    s_out = bc->PutOUTGate(out, ALL);
    party->ExecCircuit();
    output = s_out->get_clear_value<uint64_t>();
    delete party;
    return output;
}

uint64_t test_chameleon_hash_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t m_shares_1, uint64_t m_shares_2, uint64_t h, uint64_t r, uint64_t g)
{
    
    uint64_t hash_m = test_mimc_imple_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, m_shares_1, m_shares_2);
    std::cout << "hash_m: " << hash_m << std::endl;
        
    srand(time(NULL));
    uint64_t hash_m_shares_1 =  (rand()) % (hash_m - 1) + 1;
    uint64_t hash_m_shares_2 = hash_m - hash_m_shares_1;

    std::cout << "hash_m_1: " << hash_m_shares_1 << std::endl;
    std::cout << "hash_m_2: " << hash_m_shares_2 << std::endl;

    // test_exp_b_a_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, 2, 3, 4);
    uint64_t chameleon_part1 = test_exp_b_a_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, g, hash_m_shares_1, hash_m_shares_2);
    // 10;
    std::cout << "ch: " << chameleon_part1 << std::endl;

    CryptoPP::Integer big_chameleon_part1(chameleon_part1 * h);
    CryptoPP::Integer big_r(r);
    uint64_t max_number = pow(2, 64);
    std::ostringstream os;
    os << max_number;
    CryptoPP::Integer big_max_number(os.str().c_str());
    CryptoPP::Integer big_chameleon_part2 = a_exp_b_mod_c(big_chameleon_part1, big_r, big_max_number);
    std::cout << "ch2: " << big_chameleon_part2 << std::endl;

    CryptoPP::Integer big_final_result = a_times_b_mod_c(big_chameleon_part1, big_chameleon_part2, big_max_number);
    std::ostringstream ostream;
    ostream << big_final_result;
    std::string big_final_result_string = ostream.str();
    uint64_t final_result = std::atoll(big_final_result_string.c_str());
    return final_result;
}

uint64_t test_add_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t a_shares_1, uint64_t a_shares_2, uint64_t b_shares_1, uint64_t b_shares_2)
{
    ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
    std::vector<Sharing*>& sharings = party->GetSharings();
    Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
    share *s_a_shares_1, *s_a_shares_2, *s_b_shares_1, *s_b_shares_2, *s_out;
    uint64_t output;
     if(role == SERVER) {
        s_a_shares_1 = circ->PutINGate(a_shares_1, bitlen, SERVER);
        s_a_shares_2 = circ->PutDummyINGate(bitlen);
        s_b_shares_1 = circ->PutINGate(b_shares_1, bitlen, SERVER);
        s_b_shares_2 = circ->PutDummyINGate(bitlen);
    } else { //role == CLIENT
        s_a_shares_2 = circ->PutINGate(a_shares_2, bitlen, CLIENT);
        s_a_shares_1 = circ->PutDummyINGate(bitlen);
        s_b_shares_2 = circ->PutINGate(b_shares_2, bitlen, CLIENT);
        s_b_shares_1 = circ->PutDummyINGate(bitlen);
    }
    ArithmeticCircuit *ac = (ArithmeticCircuit*) circ;
    share *tmp = ac->PutADDGate(s_a_shares_1, s_a_shares_2);
    share *tmp2 = ac->PutADDGate(s_b_shares_1, s_b_shares_2);
    share *out = ac->PutADDGate(tmp, tmp2);
    s_out = ac->PutOUTGate(out, ALL);
    party->ExecCircuit();
    output = s_out->get_clear_value<uint32_t>();
    delete party;
    return output;
}

uint64_t test_sub_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t a_shares_1, uint64_t a_shares_2, uint64_t b_shares_1, uint64_t b_shares_2)
{
    ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
    std::vector<Sharing*>& sharings = party->GetSharings();
    Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
    share *s_a_shares_1, *s_a_shares_2, *s_b_shares_1, *s_b_shares_2, *s_out;
    uint64_t output;
     if(role == SERVER) {
        s_a_shares_1 = circ->PutINGate(a_shares_1, bitlen, SERVER);
        s_a_shares_2 = circ->PutDummyINGate(bitlen);
        s_b_shares_1 = circ->PutINGate(b_shares_1, bitlen, SERVER);
        s_b_shares_2 = circ->PutDummyINGate(bitlen);
    } else { //role == CLIENT
        s_a_shares_2 = circ->PutINGate(a_shares_2, bitlen, CLIENT);
        s_a_shares_1 = circ->PutDummyINGate(bitlen);
        s_b_shares_2 = circ->PutINGate(b_shares_2, bitlen, CLIENT);
        s_b_shares_1 = circ->PutDummyINGate(bitlen);
    }
    ArithmeticCircuit *ac = (ArithmeticCircuit*) circ;
    share *tmp = ac->PutADDGate(s_a_shares_1, s_a_shares_2);
    share *tmp2 = ac->PutADDGate(s_b_shares_1, s_b_shares_2);
    share *out = ac->PutSUBGate(tmp, tmp2);
    s_out = ac->PutOUTGate(out, ALL);
    party->ExecCircuit();
    output = s_out->get_clear_value<uint32_t>();
    delete party;
    return output;
}

uint64_t find_collision_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		    uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint64_t ori_re_shares_1, uint64_t ori_re_shares_2, uint64_t curr_re_shares_1, uint64_t curr_re_shares_2, uint64_t r, uint64_t g, uint64_t x_shares_1, uint64_t x_shares_2)
{
    uint64_t hash_1 = test_mimc_imple_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, ori_re_shares_1, ori_re_shares_2);
    uint64_t hash_2 = test_mimc_imple_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, curr_re_shares_1, curr_re_shares_2);

    uint64_t part1 = pow(g, r);

    uint64_t hash_1_shares_1  = (rand()) % (hash_1 - 1) + 1;
    uint64_t hash_1_shares_2 = hash_1 - hash_1_shares_1;
    uint64_t hash_2_shares_1  = (rand()) % (hash_2 - 1) + 1;
    uint64_t hash_2_shares_2 = hash_2 - hash_2_shares_1;

    uint64_t diff = test_sub_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, hash_1_shares_1, hash_1_shares_2, hash_2_shares_1, hash_2_shares_2);
    
    uint64_t diff_shares_1  = (rand()) % (diff- 1) + 1;
    uint64_t diff_shares_2 = diff - diff_shares_1;

    uint64_t x_e = test_sub_circuit(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, x_shares_1, x_shares_2, ori_re_shares_1, ori_re_shares_2);
    
    uint64_t part2_exp = Product_inv(role, address, port, seclvl, 64, nthreads, mt_alg, S_ARITH, diff_shares_1, diff_shares_2, x_e);
    uint64_t part2 = pow(g, part2_exp);

    return part1 * part2;
}