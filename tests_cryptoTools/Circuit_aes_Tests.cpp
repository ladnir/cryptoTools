#include "Circuit_Tests.h"
#include <cryptoTools/Circuit/BetaLibrary.h>

#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Log.h>
#include <random>
#include <fstream>
#include <cryptoTools/Common/TestCollection.h>
using namespace oc;

#ifdef ENABLE_CIRCUITS



void reverse(span<BetaWire> bv)
{
    u64 b = 0, e = bv.size() - 1;
    while (b < e)
    {
        auto  t = bv[e];
        bv[e] = bv[b];
        bv[b] = t;

        ++b;
        --e;
    }

}

void sBox(BetaCircuit& cir, BetaBundle x, BetaBundle s)
{
    reverse(x.mWires);
    reverse(s.mWires);

    BetaBundle y(22), t(68), z(18);

    cir.addTempWireBundle(y);
    cir.addTempWireBundle(t);
    cir.addTempWireBundle(z);

    // Jan 18 +  09
    // Straight-line program for AES sbox 
    // Joan Boyar and Rene Peralta

      // input is X0 + ..,X7  
      //output is S0 + ...,S7
      // arithmetic is over GF2

      // begin top linear transformation 
    cir.addGate(x[3], x[5], GateType::Xor, y[14]);//y14 = x3 + x5;
    cir.addGate(x[0], x[6], GateType::Xor, y[13]);//y13 = x0 + x6;
    cir.addGate(x[0], x[3], GateType::Xor, y[9]); //y9  = x0 + x3;
    cir.addGate(x[0], x[5], GateType::Xor, y[8]); //y8  = x0 + x5;
    cir.addGate(x[01], x[02], GateType::Xor, t[00]); //t00 = x01 + x02;
    cir.addGate(t[00], x[07], GateType::Xor, y[01]); //y01 = t00 + x07;
    cir.addGate(y[01], x[03], GateType::Xor, y[04]); //y04 = y01 + x03;
    cir.addGate(y[13], y[14], GateType::Xor, y[12]); //y12 = y13 + y14;
    cir.addGate(y[01], x[00], GateType::Xor, y[02]); //y02 = y01 + x00;
    cir.addGate(y[01], x[06], GateType::Xor, y[05]); //y05 = y01 + x06;
    cir.addGate(y[05], y[8], GateType::Xor, y[03]); //y03 = y05 + y 8;
    cir.addGate(x[04], y[12], GateType::Xor, t[01]); //t01 = x04 + y12;
    cir.addGate(t[01], x[05], GateType::Xor, y[15]); //y15 = t01 + x05;
    cir.addGate(t[01], x[01], GateType::Xor, y[20]); //y20 = t01 + x01;
    cir.addGate(y[15], x[07], GateType::Xor, y[06]); //y06 = y15 + x07;
    cir.addGate(y[15], t[00], GateType::Xor, y[10]); //y10 = y15 + t00;
    cir.addGate(y[20], y[9], GateType::Xor, y[11]); //y11 = y20 + y 9;
    cir.addGate(x[07], y[11], GateType::Xor, y[07]); //y07 = x07 + y11;
    cir.addGate(y[10], y[11], GateType::Xor, y[17]); //y17 = y10 + y11;
    cir.addGate(y[10], y[8], GateType::Xor, y[19]); //y19 = y10 + y 8;
    cir.addGate(t[00], y[11], GateType::Xor, y[16]); //y16 = t00 + y11;
    cir.addGate(y[13], y[16], GateType::Xor, y[21]); //y21 = y13 + y16;
    cir.addGate(x[00], y[16], GateType::Xor, y[18]); //y18 = x00 + y16;
    // end top linear transformation 
    cir.addGate(y[12], y[15], GateType::And, t[02]); //t02 = y12 X y15;
    cir.addGate(y[03], y[06], GateType::And, t[03]); //t03 = y03 X y06;
    cir.addGate(t[03], t[02], GateType::Xor, t[04]); //t04 = t03 + t02;
    cir.addGate(y[04], x[07], GateType::And, t[05]); //t05 = y04 X x07;
    cir.addGate(t[05], t[02], GateType::Xor, t[06]); //t06 = t05 + t02;
    cir.addGate(y[13], y[16], GateType::And, t[07]); //t07 = y13 X y16;
    cir.addGate(y[05], y[01], GateType::And, t[8]); //t 8 = y05 X y01;
    cir.addGate(t[8], t[07], GateType::Xor, t[9]); //t 9 = t 8 + t07;
    cir.addGate(y[02], y[07], GateType::And, t[10]); //t10 = y02 X y07;
    cir.addGate(t[10], t[07], GateType::Xor, t[11]); //t11 = t10 + t07;
    cir.addGate(y[9], y[11], GateType::And, t[12]); //t12 = y 9 X y11;
    cir.addGate(y[14], y[17], GateType::And, t[13]); //t13 = y14 X y17;
    cir.addGate(t[13], t[12], GateType::Xor, t[14]); //t14 = t13 + t12;
    cir.addGate(y[8], y[10], GateType::And, t[15]); //t15 = y 8 X y10;
    cir.addGate(t[15], t[12], GateType::Xor, t[16]); //t16 = t15 + t12;
    cir.addGate(t[04], t[14], GateType::Xor, t[17]); //t17 = t04 + t14;
    cir.addGate(t[06], t[16], GateType::Xor, t[18]); //t18 = t06 + t16;
    cir.addGate(t[9], t[14], GateType::Xor, t[19]); //t19 = t 9 + t14;
    cir.addGate(t[11], t[16], GateType::Xor, t[20]); //t20 = t11 + t16;
    cir.addGate(t[17], y[20], GateType::Xor, t[21]); //t21 = t17 + y20;
    cir.addGate(t[18], y[19], GateType::Xor, t[22]); //t22 = t18 + y19;
    cir.addGate(t[19], y[21], GateType::Xor, t[23]); //t23 = t19 + y21;
    cir.addGate(t[20], y[18], GateType::Xor, t[24]); //t24 = t20 + y18;
    // this next piece of the circuit is 
    // inversion in GF16, inputs are t21..24
    // and outputs are T37,T33,T40,T29.
    // Refer to paper for representation details
    // (tower field construction, normal basis (W,W^2) for extension   
    // from GF2 to GF4 and (Z^2,Z^8) for extension from GF4 to GF16).
    cir.addGate(t[21], t[22], GateType::Xor, t[25]);// t25 = t21 + t22;
    cir.addGate(t[21], t[23], GateType::And, t[26]);// t26 = t21 X t23;
    cir.addGate(t[24], t[26], GateType::Xor, t[27]);// t27 = t24 + t26;
    cir.addGate(t[25], t[27], GateType::And, t[28]);// t28 = t25 X t27;
    cir.addGate(t[28], t[22], GateType::Xor, t[29]);// t29 = t28 + t22;
    cir.addGate(t[23], t[24], GateType::Xor, t[30]);// t30 = t23 + t24;
    cir.addGate(t[22], t[26], GateType::Xor, t[31]);// t31 = t22 + t26;
    cir.addGate(t[31], t[30], GateType::And, t[32]);// t32 = t31 X t30;
    cir.addGate(t[32], t[24], GateType::Xor, t[33]);// t33 = t32 + t24;
    cir.addGate(t[23], t[33], GateType::Xor, t[34]);// t34 = t23 + t33;
    cir.addGate(t[27], t[33], GateType::Xor, t[35]);// t35 = t27 + t33;
    cir.addGate(t[24], t[35], GateType::And, t[36]);// t36 = t24 X t35;
    cir.addGate(t[36], t[34], GateType::Xor, t[37]);// t37 = t36 + t34;
    cir.addGate(t[27], t[36], GateType::Xor, t[38]);// t38 = t27 + t36;
    cir.addGate(t[29], t[38], GateType::And, t[39]);// t39 = t29 X t38;
    cir.addGate(t[25], t[39], GateType::Xor, t[40]);// t40 = t25 + t39;
    // end GF16 inversion
    cir.addGate(t[40], t[37], GateType::Xor, t[41]);// t41 = t40 + t37;
    cir.addGate(t[29], t[33], GateType::Xor, t[42]);// t42 = t29 + t33;
    cir.addGate(t[29], t[40], GateType::Xor, t[43]);// t43 = t29 + t40;
    cir.addGate(t[33], t[37], GateType::Xor, t[44]);// t44 = t33 + t37;
    cir.addGate(t[42], t[41], GateType::Xor, t[45]);// t45 = t42 + t41;
    cir.addGate(t[44], y[15], GateType::And, z[00]);// z00 = t44 X y15;
    cir.addGate(t[37], y[06], GateType::And, z[01]);// z01 = t37 X y06;
    cir.addGate(t[33], x[07], GateType::And, z[02]);// z02 = t33 X x07;
    cir.addGate(t[43], y[16], GateType::And, z[03]);// z03 = t43 X y16;
    cir.addGate(t[40], y[01], GateType::And, z[04]);// z04 = t40 X y01;
    cir.addGate(t[29], y[07], GateType::And, z[05]);// z05 = t29 X y07;
    cir.addGate(t[42], y[11], GateType::And, z[06]);// z06 = t42 X y11;
    cir.addGate(t[45], y[17], GateType::And, z[07]);// z07 = t45 X y17;
    cir.addGate(t[41], y[10], GateType::And, z[8]);// z 8 = t41 X y10;
    cir.addGate(t[44], y[12], GateType::And, z[9]);// z 9 = t44 X y12;
    cir.addGate(t[37], y[03], GateType::And, z[10]);// z10 = t37 X y03;
    cir.addGate(t[33], y[04], GateType::And, z[11]);// z11 = t33 X y04;
    cir.addGate(t[43], y[13], GateType::And, z[12]);// z12 = t43 X y13;
    cir.addGate(t[40], y[05], GateType::And, z[13]);// z13 = t40 X y05;
    cir.addGate(t[29], y[02], GateType::And, z[14]);// z14 = t29 X y02;
    cir.addGate(t[42], y[9], GateType::And, z[15]);// z15 = t42 X y 9;
    cir.addGate(t[45], y[14], GateType::And, z[16]);// z16 = t45 X y14;
    cir.addGate(t[41], y[8], GateType::And, z[17]);// z17 = t41 X y 8;
    // begin end linear transformation 
    cir.addGate(z[15], z[16], GateType::Xor, t[46]);// t46 = z15 +    z16;
    cir.addGate(z[10], z[11], GateType::Xor, t[47]);// t47 = z10 +    z11;
    cir.addGate(z[05], z[13], GateType::Xor, t[48]);// t48 = z05 +    z13;
    cir.addGate(z[9], z[10], GateType::Xor, t[49]);// t49 = z 9 +    z10;
    cir.addGate(z[02], z[12], GateType::Xor, t[50]);// t50 = z02 +    z12;
    cir.addGate(z[02], z[05], GateType::Xor, t[51]);// t51 = z02 +    z05;
    cir.addGate(z[07], z[8], GateType::Xor, t[52]);// t52 = z07 +    z 8;
    cir.addGate(z[00], z[03], GateType::Xor, t[53]);// t53 = z00 +    z03;
    cir.addGate(z[06], z[07], GateType::Xor, t[54]);// t54 = z06 +    z07;
    cir.addGate(z[16], z[17], GateType::Xor, t[55]);// t55 = z16 +    z17;
    cir.addGate(z[12], t[48], GateType::Xor, t[56]);// t56 = z12 +    t48;
    cir.addGate(t[50], t[53], GateType::Xor, t[57]);// t57 = t50 +    t53;
    cir.addGate(z[04], t[46], GateType::Xor, t[58]);// t58 = z04 +    t46;
    cir.addGate(z[03], t[54], GateType::Xor, t[59]);// t59 = z03 +    t54;
    cir.addGate(t[46], t[57], GateType::Xor, t[60]);// t60 = t46 +    t57;
    cir.addGate(z[14], t[57], GateType::Xor, t[61]);// t61 = z14 +    t57;
    cir.addGate(t[52], t[58], GateType::Xor, t[62]);// t62 = t52 +    t58;
    cir.addGate(t[49], t[58], GateType::Xor, t[63]);// t63 = t49 +    t58;
    cir.addGate(z[04], t[59], GateType::Xor, t[64]);// t64 = z04 +    t59;
    cir.addGate(t[61], t[62], GateType::Xor, t[65]);// t65 = t61 +    t62;
    cir.addGate(z[01], t[63], GateType::Xor, t[66]);// t66 = z01 +    t63;

    cir.addGate(t[59], t[63], GateType::Xor, s[00]);// s00 = t59 +    t63;
    cir.addGate(t[56], t[62], GateType::Nxor, s[06]);// s06 = t56 XNOR t62;
    cir.addGate(t[48], t[60], GateType::Nxor, s[07]);// s07 = t48 XNOR t60;
    cir.addGate(t[64], t[65], GateType::Xor, t[67]);// t67 = t64 +    t65;
    cir.addGate(t[53], t[66], GateType::Xor, s[03]);// s03 = t53 +    t66;
    cir.addGate(t[51], t[66], GateType::Xor, s[04]);// s04 = t51 +    t66;
    cir.addGate(t[47], t[65], GateType::Xor, s[05]);// s05 = t47 +    t65;
    cir.addGate(t[64], s[03], GateType::Nxor, s[01]);// s01 = t64 XNOR s03;
    cir.addGate(t[55], t[67], GateType::Nxor, s[02]);// s02 = t55 XNOR t67;

}

static const uint8_t sbox[256] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };


void reverse(BitVector& bv)
{
    u64 b = 0, e = bv.size() - 1;
    while (b < e)
    {
        u8  t = bv[e];
        bv[e] = bv[b];
        bv[b] = t;

        ++b;
        --e;
    }
}

//struct WireBlock
//{
//    WireBlock() = default;
//    WireBlock(BetaCircuit& cir)
//    {
//        init(cir);
//    }
//    WireBlock(BetaBundle& v)
//    {
//        init(v);
//    }
//
//    void init(BetaBundle& v)
//    {
//        init(v.mWires.begin(), v.mWires.end());
//    }
//    void init(
//        std::vector<BetaWire>::iterator b,
//        std::vector<BetaWire>::iterator e)
//    {
//        if (e - b != 128)
//            throw RTE_LOC;
//
//        for (u64 i = 0; i < 16; ++i)
//        {
//            a[i].mWires.insert(
//                a[i].mWires.end(),
//                b + i * 8,
//                b + i * 8 + 8);
//        }
//    }
//
//    void init(BetaCircuit& cir)
//    {
//        for (u64 i = 0; i < 16; ++i)
//        {
//            a[i].mWires.resize(8);
//            cir.addTempWireBundle(a[i]);
//        }
//    }
//
//    std::array<BetaBundle, 16> a;
//};
//
//

struct ByteBlock
{
    ByteBlock() = default;
    ByteBlock(BitVector& bv)
    {
        if (bv.size() != 128)
            throw RTE_LOC;

        auto s = bv.getSpan<u8>();
        for (u64 i = 0; i < static_cast<u64>(s.size()); ++i)
            a[i] = s[i];

    }
    uint8_t a[16];
};

//
//
//void print(BetaCircuit& cir, WireBlock& b)
//{
//    for (u64 i = 0; i < 16; ++i)
//    {
//        if (i)
//            cir.addPrint(".");
//        cir.addPrint(b.a[i]);
//    }
//    cir.addPrint("\n");
//}
void print(ByteBlock& b)
{
    for (u64 i = 0; i < 16; ++i)
    {
        BitVector bb(&b.a[i], 8);
        reverse(bb);

        if (i)
            std::cout << ".";

        std::cout << bb;

    }
    std::cout << std::endl;
}

//
//void ShiftRows(BetaCircuit& cir, WireBlock& buf, WireBlock& out)
//{
//
//
//    cir.addCopy(buf.a[0], out.a[0]);
//    cir.addCopy(buf.a[4], out.a[4]);
//    cir.addCopy(buf.a[8], out.a[8]);
//    cir.addCopy(buf.a[12], out.a[12]);
//
//    /*shift 2nd row*/
//
//    cir.addCopy(buf.a[1], out.a[13]);// out.a[13] = buf.a[1];
//    cir.addCopy(buf.a[5], out.a[1]); // buf.a[1] = buf.a[5];
//    cir.addCopy(buf.a[9], out.a[5]); // buf.a[5] = buf.a[9];
//    cir.addCopy(buf.a[13], out.a[9]); // buf.a[9] = buf.a[13];
//
//    /*shift 3rd row*/
//    cir.addCopy(buf.a[10], out.a[2]);
//    cir.addCopy(buf.a[2], out.a[10]);
//    //buf.a[2] = buf.a[10];
//    //buf.a[10] = buf.a[2];
//
//    cir.addCopy(buf.a[14], out.a[6]);
//    cir.addCopy(buf.a[6], out.a[14]);
//    //buf.a[6] = buf.a[14];
//    //buf.a[14] = buf.a[6];
//
//    /*shift 4th row*/
//    cir.addCopy(buf.a[15], out.a[3]);
//    cir.addCopy(buf.a[11], out.a[15]);
//    cir.addCopy(buf.a[7], out.a[11]);
//    cir.addCopy(buf.a[3], out.a[7]);
//    //buf.a[3] = buf.a[15];
//    //buf.a[15] = buf.a[11];
//    //buf.a[11] = buf.a[7];
//    //buf.a[7] = buf.a[3];
//}

//
//void Xor(BetaCircuit& cir, BetaBundle& in0, BetaBundle& in1, BetaBundle& out)
//{
//    for (u64 i = 0; i < in0.size(); ++i)
//    {
//        cir.addGate(in0[i], in1[i], GateType::Xor, out[i]);
//    }
//}
//
//void MixColumns(BetaCircuit& cir, WireBlock& buf, WireBlock& out)
//{
//    BetaBundle a(8);
//    std::array<BetaBundle, 4> b{ BetaBundle(8), BetaBundle(8), BetaBundle(8), BetaBundle(8) };
//    //BetaBundle h(8);
//    BetaWire h;
//
//    //print(cir, buf);
//
//    cir.addTempWireBundle(a);
//    cir.addTempWireBundle(b[0]);
//    cir.addTempWireBundle(b[1]);
//    cir.addTempWireBundle(b[2]);
//    cir.addTempWireBundle(b[3]);
//    //cir.addTempWireBundle(h);
//
//    for (uint8_t i = 0; i < 4; i++) {
//
//        for (uint8_t c = 0; c < 4; c++) {
//
//            for (u64 j = 1; j < 8; ++j)
//                cir.addCopy(buf.a[4 * i + c][j - 1], b[c][j]);
//            //b[c] = (buf.a[4 * i + c] << 1);
//
//            //cir.addConst(b[c][0], 0);
//            h = buf.a[4 * i + c][7];
//            cir.addCopy(h, b[c][0]);
//            cir.addGate(b[c][1], h, GateType::Xor, b[c][1]);
//            cir.addGate(b[c][3], h, GateType::Xor, b[c][3]);
//            cir.addGate(b[c][4], h, GateType::Xor, b[c][4]);
//            //h = (buf.a[4 * i + c] >> 7);
//            //b[c]{ 0 } = b[c]{ 0 } ^ (h{ 0 });
//            //b[c]{ 1 } = b[c]{ 1 } ^ (h{ 0 });
//            //b[c]{ 3 } = b[c]{ 3 } ^ (h{ 0 });
//            //b[c]{ 4 } = b[c]{ 4 } ^ (h{ 0 });
//
//        }
//
//        //a = buf.a[4 * i] ^ buf.a[4 * i + 1] ^ buf.a[4 * i + 2] ^ buf.a[4 * i + 3];
//        Xor(cir, buf.a[4 * i], buf.a[4 * i + 1], a);
//        Xor(cir, a, buf.a[4 * i + 2], a);
//        Xor(cir, a, buf.a[4 * i + 3], a);
//
//        //buf.a[4 * i] = b[0] ^ b[1] ^ a ^ buf.a[4 * i]; /* 2 * a0 + a3 + a2 + 3 * a1 */
//        Xor(cir, buf.a[4 * i], b[0], out.a[4 * i]);
//        Xor(cir, out.a[4 * i], b[1], out.a[4 * i]);
//        Xor(cir, out.a[4 * i], a, out.a[4 * i]);
//
//
//        //buf.a[4 * i + 1] = b[1] ^ b[2] ^ a ^ buf.a[4 * i + 1]; /* 2 * a1 + a0 + a3 + 3 * a2 */
//        Xor(cir, buf.a[4 * i + 1], b[1], out.a[4 * i + 1]);
//        Xor(cir, out.a[4 * i + 1], b[2], out.a[4 * i + 1]);
//        Xor(cir, out.a[4 * i + 1], a, out.a[4 * i + 1]);
//
//        //buf.a[4 * i + 2] = b[2] ^ b[3] ^ a ^ buf.a[4 * i + 2]; /* 2 * a2 + a1 + a0 + 3 * a3 */
//        Xor(cir, buf.a[4 * i + 2], b[2], out.a[4 * i + 2]);
//        Xor(cir, out.a[4 * i + 2], b[3], out.a[4 * i + 2]);
//        Xor(cir, out.a[4 * i + 2], a, out.a[4 * i + 2]);
//
//        //buf.a[4 * i + 3] = b[3] ^ b[0] ^ a ^ buf.a[4 * i + 3]; /* 2 * a3 + a2 + a1 + 3 * a0 */
//        Xor(cir, buf.a[4 * i + 3], b[3], out.a[4 * i + 3]);
//        Xor(cir, out.a[4 * i + 3], b[0], out.a[4 * i + 3]);
//        Xor(cir, out.a[4 * i + 3], a, out.a[4 * i + 3]);
//    }
//}
//
//
//void AddRoundKey(BetaCircuit& cir, WireBlock& buf, WireBlock& key, WireBlock& out)
//{
//
//    for (uint8_t i = 0; i < 16; i++) {
//        Xor(cir, buf.a[i], key.a[i], out.a[i]);
//        //buf.a[i] = buf.a[i] ^ key.a[i];
//    }
//    //return buf;
//}
//
//void SubBytes(BetaCircuit&cir, WireBlock& buf, WireBlock& out)
//{
//
//    for (uint8_t i = 0; i < 16; i++)
//    {
//        sBox(cir, buf.a[i], out.a[i]);
//    }
//
//    //cir.addPrint(buf.a[0]);
//    //cir.addPrint(" ");
//    //cir.addPrint(out.a[0]);
//    //cir.addPrint("\n");
//}
//
//void reverseByteOrder(WireBlock& b)
//{
//    for (u64 i = 0; i < 16; ++i)
//    {
//        for (u64 j = 0; j < 4; ++j)
//        {
//            std::swap(b.a[i][j], b.a[i][7 - j]);
//        }
//    }
//}

//void KeyExpansion(BetaCircuit& cir, BetaBundle& key, span<WireBlock> keyEx)
//{
//    for (auto& a : keyEx)
//    {
//        a.init(key);
//    }
//}
//

void KeyExpansion(ByteBlock key, span<ByteBlock> RoundKey)
{
    for (auto& k : RoundKey)
        k = key;
    return;
}



ByteBlock SubBytes(ByteBlock buf)
{
    //u8 v = sbox[buf.a[0]];
    //BitVector v1(&buf.a[0], 8); reverse(v1);
    //BitVector v2(&v, 8); reverse(v2);

    //std::cout << v1 << " " << v2 << std::endl;

    for (u8 i = 0; i < 16; i++)
    {
        buf.a[i] = sbox[buf.a[i]];
    }
    return buf;
}


ByteBlock ShiftRows(ByteBlock buf)
{

    u8 i;
    /*shift 2nd row*/
    i = buf.a[1];
    buf.a[1] = buf.a[5];
    buf.a[5] = buf.a[9];
    buf.a[9] = buf.a[13];
    buf.a[13] = i;

    /*shift 3rd row*/
    i = buf.a[2];
    buf.a[2] = buf.a[10];
    buf.a[10] = i;

    i = buf.a[6];
    buf.a[6] = buf.a[14];
    buf.a[14] = i;

    /*shift 4th row*/
    i = buf.a[3];
    buf.a[3] = buf.a[15];
    buf.a[15] = buf.a[11];
    buf.a[11] = buf.a[7];
    buf.a[7] = i;
    return buf;
}


/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];


// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void ShiftRows(state_t& state)
{
    uint8_t temp;

    // Rotate first row 1 columns to left  
    temp = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = temp;

    // Rotate second row 2 columns to left  
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    // Rotate third row 3 columns to left
    temp = state[0][3];
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = temp;
}


ByteBlock MixColumns(ByteBlock buf)
{
    //print(buf);
    for (u8 i = 0; i < 4; i++) {
        u8 a;
        u8 b[4];
        u8 h;
        for (u8 c = 0; c < 4; c++) {
            b[c] = (buf.a[4 * i + c] << 1);

            h = (buf.a[4 * i + c] >> 7);
            b[c] = b[c] ^ (h) ^ (h << 1) ^ (h << 3) ^ (h << 4);
        }
        a = buf.a[4 * i] ^ buf.a[4 * i + 1] ^ buf.a[4 * i + 2] ^ buf.a[4 * i + 3];

        buf.a[4 * i] = b[0] ^ b[1] ^ a ^ buf.a[4 * i]; /* 2 * a0 + a3 + a2 + 3 * a1 */
        buf.a[4 * i + 1] = b[1] ^ b[2] ^ a ^ buf.a[4 * i + 1]; /* 2 * a1 + a0 + a3 + 3 * a2 */
        buf.a[4 * i + 2] = b[2] ^ b[3] ^ a ^ buf.a[4 * i + 2]; /* 2 * a2 + a1 + a0 + 3 * a3 */
        buf.a[4 * i + 3] = b[3] ^ b[0] ^ a ^ buf.a[4 * i + 3]; /* 2 * a3 + a2 + a1 + 3 * a0 */
    }

    return buf;
}


uint8_t mul(uint8_t x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
void MixColumns(state_t& state)
{
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i)
    {
        t = state[i][0];
        Tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];
        Tm = state[i][0] ^ state[i][1];
        Tm = mul(Tm);
        state[i][0] ^= Tm ^ Tmp;

        Tm = state[i][1] ^ state[i][2];
        Tm = mul(Tm);
        state[i][1] ^= Tm ^ Tmp;

        Tm = state[i][2] ^ state[i][3];
        Tm = mul(Tm);
        state[i][2] ^= Tm ^ Tmp;

        Tm = state[i][3] ^ t;
        Tm = mul(Tm);
        state[i][3] ^= Tm ^ Tmp;

    }
}


ByteBlock AddRoundKey(ByteBlock buf, ByteBlock key)
{

    for (u8 i = 0; i < 16; i++) {
        buf.a[i] = buf.a[i] ^ key.a[i];
    }
    return buf;
}
//
//
//void fAES(BetaCircuit& cir, BetaBundle& textin, span<WireBlock> keyEx, BetaBundle& ctext)
//{
//
//    auto Nr = keyEx.size() - 1;
//    WireBlock text(textin);
//    WireBlock buff(cir), c(ctext);
//
//    AddRoundKey(cir, text, keyEx[0], buff);
//    cir.addPrint("0 ");
//    print(cir, buff);
//    auto pp = 1;
//
//    for (u64 i = 1; i < Nr; i++)
//    {
//        SubBytes(cir, buff, c);
//        //if (i == pp)
//        //{
//        //    cir.addPrint(std::to_string(i) + " ");
//        //    print(cir, c);
//        //}
//
//        ShiftRows(cir, c, buff);
//
//        //if (i == pp)
//        //{
//        //    cir.addPrint(std::to_string(i) + " ");
//        //    print(cir, buff);
//        //}
//        MixColumns(cir, buff, c);
//        //if (i == pp)
//        //{
//        //    cir.addPrint(std::to_string(i) + " ");
//        //    print(cir, c);
//        //}
//
//        AddRoundKey(cir, c, keyEx[i], buff);
//
//        //if (i == pp)
//        //{
//            cir.addPrint(std::to_string(i) + " ");
//            print(cir, buff);
//        //}
//    }
//
//    SubBytes(cir, buff, c);
//    ShiftRows(cir, c, buff);
//
//    AddRoundKey(cir, buff, keyEx[Nr], c);
//}
//
//void fAES(BetaCircuit& cir, BetaBundle& textin, BetaBundle& key, BetaBundle& ctext)
//{
//    std::vector<WireBlock> keyEx;
//    if (key.size() == 128)
//    {
//        keyEx.resize(11);
//        KeyExpansion(cir, key, keyEx);
//    }
//    else
//    {
//        if (key.size() != 128 * 11 &&
//            key.size() != 128 * 13 &&
//            key.size() != 128 * 15)
//            throw RTE_LOC;
//
//        keyEx.resize(key.size() / 128);
//        for (i64 i = 0; i < keyEx.size(); ++i)
//        {
//            keyEx[i].init(key.mWires.begin() + i * 128, key.mWires.begin() + (i * 128 + 128));
//        }
//    }
//
//    fAES(cir, textin, keyEx, ctext);
//
//}

ByteBlock fAES(ByteBlock text, span<ByteBlock> keyEx)
{
    u64  Nr = static_cast<u64>(keyEx.size() - 1);
    ByteBlock buff;
    buff = AddRoundKey(text, keyEx[0]);

    //std::cout << 0 << " ";
    //print(buff);
    //auto pp = 1;
    for (u64 i = 1; i < Nr; i++)
    {
        buff = SubBytes(buff);
        //if (i == pp)
        //{
        //    std::cout << i << " ";
        //    print(buff);
        //}

        buff = ShiftRows(buff);

        //if (i == pp)
        //{
        //    std::cout << i << " ";
        //    print(buff);
        //}

        buff = MixColumns(buff);
        //if (i == pp)
        //{
        //    std::cout << i << " ";
        //    print(buff);
        //}

        buff = AddRoundKey(buff, keyEx[i]);
        //if (i == pp)
        //{
        //    std::cout << i << " ";
        //    print(buff);
        //}

    }


    buff = SubBytes(buff);
    buff = ShiftRows(buff);

    buff = AddRoundKey(buff, keyEx[Nr]);

    return buff;
}
ByteBlock fAES(ByteBlock text, ByteBlock key)
{
    static const u64 Nr(10);
    ByteBlock keyEx[Nr + 1];
    KeyExpansion(key, keyEx);
    //print(text);
    return fAES(text, keyEx);
}


void BetaCircuit_aes_sbox_test()
{
    BetaCircuit cir;


    BetaBundle x(8);
    BetaBundle s(8);

    cir.addInputBundle(x);
    cir.addOutputBundle(s);

    sBox(cir, x, s);

    //u8 val = 1;
    for (u64 val = 0; val < 256; ++val)
    {

        BitVector xx(8), yy(8);
        xx.data()[0] = static_cast<u8>(val);

        cir.evaluate({ &xx,1 }, { &yy,1 }, true);
        auto c = sbox[val];
        BitVector exp(&c, 8);
        //reverse(exp);

        if (yy != exp)
        {
            std::cout << yy << " != " << exp << std::endl;
            throw RTE_LOC;
        }
    }
}
//
//void BetaCircuit_aes_shiftRows_test()
//{
//    BetaCircuit cir;
//
//    BetaBundle in(128), key(128), out(128);
//    cir.addInputBundle(in);
//    //cir.addInputBundle(key);
//    cir.addOutputBundle(out);
//    WireBlock iw(in);
//    //WireBlock k(in);
//    WireBlock ow(out);
//
//    ShiftRows(cir, iw, ow);
//
//    BitVector ii(128), oo(128);
//    PRNG prng(ZeroBlock);
//    ii.randomize(prng);
//
//    //std::cout << "ii " << ii << std::endl;
//
//    cir.evaluate({ &ii,1 }, { &oo,1 }, true);
//    //std::cout << "oo " << oo << std::endl;
//
//    ByteBlock iii(ii), ooo;
//    ooo = ShiftRows(iii);
//
//
//
//    state_t state;
//    memcpy(&state, &iii, 16);
//    ShiftRows(state);
//
//    auto v = oo.getSpan<u8>();
//    for (u64 i = 0; i < 16; ++i)
//    {
//        if (v[i] != ooo.a[i])
//        {
//            std::cout << i << std::endl;
//            std::cout << int(v[i]) << " " << int(ooo.a[i]) << std::endl;
//            throw RTE_LOC;
//        }
//
//        auto s = state[i / 4][i % 4];
//        if (v[i] != s)
//        {
//            std::cout << i << " state " << std::endl;
//            std::cout << int(v[i]) << " " << int(s) << std::endl;
//            throw RTE_LOC;
//        }
//    }
//}
//
//
//
//void BetaCircuit_aes_mixColumns_test()
//{
//
//    BetaCircuit cir;
//
//    BetaBundle in(128), key(128), out(128);
//    cir.addInputBundle(in);
//    //cir.addInputBundle(key);
//    cir.addOutputBundle(out);
//    WireBlock iw(in);
//    //WireBlock k(in);
//    WireBlock ow(out);
//
//    MixColumns(cir, iw, ow);
//
//    BitVector ii(128), oo(128);
//    PRNG prng(ZeroBlock);
//    ii.randomize(prng);
//
//    //std::cout << "ii " << ii << std::endl;
//
//    cir.evaluate({ &ii,1 }, { &oo,1 }, true);
//    //std::cout << "oo " << oo << std::endl;
//
//    ByteBlock iii(ii), ooo;
//    ooo = MixColumns(iii);
//
//
//
//    state_t state;
//    memcpy(&state, &iii, 16);
//    MixColumns(state);
//
//    auto v = oo.getSpan<u8>();
//    for (u64 i = 0; i < 16; ++i)
//    {
//        if (v[i] != ooo.a[i])
//        {
//            std::cout << i << std::endl;
//            std::cout << int(v[i]) << " " << int(ooo.a[i]) << std::endl;
//            throw RTE_LOC;
//        }
//
//        auto s = state[i / 4][i % 4];
//        if (v[i] != s)
//        {
//            std::cout << i << " state " << std::endl;
//            std::cout << int(v[i]) << " " << int(s) << std::endl;
//            throw RTE_LOC;
//        }
//    }
//}



void SubBytes(state_t& state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            state[j][i] = sbox[state[j][i]];
        }
    }
}
void AddRoundKey(state_t& state, const state_t& RoundKey)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            state[i][j] ^= RoundKey[i][j];
        }
    }
}


void print(state_t& state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            if (i || j)
                std::cout << ".";

            BitVector bb(&state[i][j], 8);
            reverse(bb);
            std::cout << bb;
        }
    }

    std::cout << std::endl;
}

void fAES(state_t& state, span<state_t> RoundKey)
{
    u64 round = 0;
    auto Nr = static_cast<u64>(RoundKey.size() - 1);

    print(state);

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(state, RoundKey[0]);

    //std::cout << 0 << " ";
    //print(state);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (round = 1; round < Nr; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, RoundKey[round]);

        //std::cout << round << " ";
        //print(state);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, RoundKey[Nr]);
}



void BetaCircuit_aes_test()
{
    //BetaCircuit_aes_shiftRows_test();
    //BetaCircuit_aes_mixColumns_test();

    //std::cout << "\n";
    //return;

    auto keySize = 11;
    BetaCircuit cir;
    BetaLibrary lib;
    PRNG prng(ZeroBlock);
    BetaBundle x(128), k(128 * keySize);
    BetaBundle c(128);



    cir.addInputBundle(x);
    cir.addInputBundle(k);
    cir.addOutputBundle(c);

    lib.aes_exapnded_build(cir, x, k, c);
    //fAES(cir, x, k, c);

    auto cir2 = lib.aes_exapnded(10);

    for (u64 tr = 0; tr < 10; ++tr)
    {

        std::array<BitVector, 2> in{ BitVector(128), BitVector(128 * keySize) };
        BitVector cc(128), cc2(128);
        block keyBlock = prng.get<block>();
        AES aes(keyBlock);

        in[0].randomize(prng);
        in[1] = BitVector((u8*)aes.mRoundKey.data(), 128 * keySize);

        cir.evaluate(in, { &cc,1 });
        cir2->evaluate(in, { &cc2,1 });

        if (cc2 != cc)
        {
            std::cout << cc2 << "  " << cc << std::endl;
            throw RTE_LOC;
        }

        ByteBlock ptxt = in[0].getSpan<ByteBlock>()[0];

        auto key = in[1].getSpan<ByteBlock>();

        auto ctxt = fAES(ptxt, key);

        auto ctxt2 = aes.ecbEncBlock(in[0].getSpan<block>()[0]);

        //std::vector<state_t> keys(11);
        //for (u64 i = 0; i < keys.size(); ++i)
        //    memcpy(&keys[i], &key, sizeof(block));


        //state_t state;
        //memcpy(&state, &ptxt, sizeof(block));
        //fAES(state, keys);

        auto v = cc.getSpan<u8>();
        for (u64 i = 0; i < 16; ++i)
        {
            if (v[i] != ctxt.a[i])
            {
                std::cout << i << std::endl;
                std::cout << int(v[i]) << " " << int(ctxt.a[i]) << " " << int(((u8*)&ctxt2)[i]) << std::endl;
                throw RTE_LOC;
            }
        }
    }

}
#else

void BetaCircuit_aes_test()
{
    throw UnitTestSkipped("ENABLE_CIRCUITS must be defined.");
}

#endif