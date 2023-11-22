#pragma once

#include "cryptoTools/Common/CLP.h"

void MxCircuit_Bit_Ops_Test();
//void MxCircuit_BInt_Bitwise_Test();
void MxCircuit_Adder_const_Test();
void MxCircuit_Subtractor_Test();
void MxCircuit_Subtractor_const_Test();
void MxCircuit_Multiply_Test();
void MxCircuit_Divide_Test();
void MxCircuit_LessThan_Test();
void MxCircuit_GreaterThanEq_Test();
//void MxCircuit_SequentialOp_Test();

void MxCircuit_negate_Test();
void MxCircuit_bitInvert_Test();
void MxCircuit_removeSign_Test();
void MxCircuit_addSign_Test();

void MxCircuit_uint_Adder_Test();
void MxCircuit_uint_Subtractor_Test();
void MxCircuit_uint_Multiply_Test();
void MxCircuit_uint_LessThan_Test();
void MxCircuit_uint_GreaterThanEq_Test();

void MxCircuit_multiplex_Test();

void MxCircuit_xor_and_lvl_test(const oc::CLP& cmd);

void MxCircuit_aes_test();
void MxCircuit_json_Tests();
void MxCircuit_bin_Tests();
