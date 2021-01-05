#ifndef __LDPC_DECODER_H
#define __LDPC_DECODER_H
#include "LDPC_generator.h"
#include "simple_bitarray.h"
#include "Mtx.h"

//belief-propagation decoder
class LDPC_bp_decoder{
private:
	int code_len;
	int msg_len;

	double* messages;
	int** check_to_data;
	int* check_to_data_mem;
	int* check_degree;
	int** data_to_check;
	int* data_to_check_mem;
	int* data_degree;
	int** check_to_data_id;
	int* check_to_data_id_mem;

	bool* msg_sign;

	double* data_nodes;
	double* error;

public:
	LDPC_bp_decoder(int code_len, int msg_len);
	~LDPC_bp_decoder();

	//init by a given generated parity check matrix
	bool init(LDPC_generator* generator);
	//init by a buffered sparse graph
	bool init(const char* filename);

	bool init(oc::SparseMtx& H);

	//check if a code is valid
	bool check(const bit_array_t& data);
	//soft-decision decoder for BSC
	bool decode_BSC(bit_array_t& data, double error_prob, int iterations=50);

	//hard-decision decoder for BEC
	//bool decode_BEC(bit_array_t& data, bit_array_t& mask);
	////hard-decision decoder for generalized BEC
	//template<typename T>
	//bool decode_BEC(T* arr, bit_array_t& mask){
	//	//first: initialize
	//	bool found = false;
	//	bool no_erasure = false;

	//	do{
	//		found = false;
	//		no_erasure = true;
	//		for (int i = 0; i < code_len - msg_len; i++){
	//			auto check_node = check_to_data_id[i];
	//			int erasure_count = 0;
	//			int erasure_id = 0;
	//			T other_xor;
	//			for (int j = 0; j < check_degree[i]; j++){
	//				if (!mask[check_node[j]]){
	//					erasure_count++;
	//					erasure_id = check_node[j];
	//				}
	//				else other_xor ^= arr[check_node[j]];
	//			}
	//			if (erasure_count > 0)
	//				no_erasure = false;
	//			if (erasure_count == 1){
	//				arr[erasure_id] = other_xor;
	//				mask.set(erasure_id, true);
	//				found = true;
	//			}
	//		}
	//	} while (found&&!no_erasure);
	//	return no_erasure;
	//}
	// 
	//soft-decision decoder for BSC, given all symbol's belief
	bool decode_BSC(bit_array_t& result, const double* data_prob, int iterations=50);
	//hard-decision decoder for BSC
	bool decode_BSC(bit_array_t& data, int iterations = 50);
};
#endif