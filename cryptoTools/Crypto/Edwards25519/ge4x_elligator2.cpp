#include "ge4x.h"

#include <cstdint>

namespace
{
    constexpr unsigned char c2Bytes[32] = {
        0xb1, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
        0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
        0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
        0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b};
    constexpr unsigned char sqrtMinusOneBytes[32] = {
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
        0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
        0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
        0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b};
    constexpr unsigned char sqrtMinus486664Bytes[32] = {
        0x06, 0x7e, 0x45, 0xff, 0xaa, 0x04, 0x6e, 0xcc,
        0x82, 0x1a, 0x7d, 0x4b, 0xd1, 0xd3, 0xa1, 0xc5,
        0x7e, 0x4f, 0xfc, 0x03, 0xdc, 0x08, 0x7b, 0xd2,
        0xbb, 0x06, 0xa0, 0x60, 0xf4, 0xed, 0x26, 0x0f};
    constexpr unsigned char montgomeryJBytes[32] = {
        0x06, 0x6d, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    void unpackRepeated(gfe4x& out, const unsigned char bytes[32])
    {
        unsigned char packed[128];
        for (unsigned int lane = 0; lane != 4; ++lane)
            for (unsigned int i = 0; i != 32; ++i)
                packed[32 * lane + i] = bytes[i];
        gfe4x_unpack(&out, packed);
    }

    struct Elligator2Constants
    {
        gfe4x c2;
        gfe4x sqrtMinusOne;
        gfe4x sqrtMinus486664;
        gfe4x j;
        gfe4x zero;
        gfe4x one;

        Elligator2Constants()
        {
            unpackRepeated(c2, c2Bytes);
            unpackRepeated(sqrtMinusOne, sqrtMinusOneBytes);
            unpackRepeated(sqrtMinus486664, sqrtMinus486664Bytes);
            unpackRepeated(j, montgomeryJBytes);
            gfe4x_setzero(&zero);
            gfe4x_setone(&one);
        }
    };

    const Elligator2Constants& constants()
    {
        static const Elligator2Constants value;
        return value;
    }

    void equal(unsigned char result[4], const gfe4x& x, const gfe4x& y)
    {
        gfe4x difference;
        unsigned char packed[128];
        gfe4x_sub(&difference, &x, &y);
        gfe4x_pack(packed, &difference);
        for (unsigned int lane = 0; lane != 4; ++lane)
        {
            std::uint32_t different = 0;
            for (unsigned int i = 0; i != 32; ++i)
                different |= static_cast<std::uint32_t>(
                    packed[32 * lane + i]);
            result[lane] = static_cast<unsigned char>(1U ^
                ((different | (0U - different)) >> 31));
        }
    }
}

void ge4x_map_to_curve_elligator2(ge4x *r, const fe25519 u[4])
{
    const auto& c = constants();
    unsigned char packed[128];
    for (unsigned int lane = 0; lane != 4; ++lane)
        fe25519_pack(packed + 32 * lane, &u[lane]);

    gfe4x input;
    gfe4x_unpack(&input, packed);

    gfe4x tv1, tv2, tv3, xd, x1n, gxd, gx1;
    gfe4x y11, y12, x2n, y21, y22, gx2, y1, y2, yneg;
    gfe4x xmn, ymn, xn, xdn, yn, yd;
    unsigned char e1[4], e2[4], e3[4], e4[4], select[4];

    gfe4x_square(&tv1, &input);
    gfe4x_add(&tv1, &tv1, &tv1);
    gfe4x_add(&xd, &tv1, &c.one);
    gfe4x_neg(&x1n, &c.j);
    gfe4x_square(&tv2, &xd);
    gfe4x_mul(&gxd, &tv2, &xd);
    gfe4x_mul(&gx1, &c.j, &tv1);
    gfe4x_mul(&gx1, &gx1, &x1n);
    gfe4x_add(&gx1, &gx1, &tv2);
    gfe4x_mul(&gx1, &gx1, &x1n);

    gfe4x_square(&tv3, &gxd);
    gfe4x_square(&tv2, &tv3);
    gfe4x_mul(&tv3, &tv3, &gxd);
    gfe4x_mul(&tv3, &tv3, &gx1);
    gfe4x_mul(&tv2, &tv2, &tv3);
    gfe4x_pow2523(&y11, &tv2);
    gfe4x_mul(&y11, &y11, &tv3);
    gfe4x_mul(&y12, &y11, &c.sqrtMinusOne);
    gfe4x_square(&tv2, &y11);
    gfe4x_mul(&tv2, &tv2, &gxd);
    equal(e1, tv2, gx1);
    y1 = y12;
    gfe4x_cmov(&y1, &y11, e1);

    gfe4x_mul(&x2n, &x1n, &tv1);
    gfe4x_mul(&y21, &y11, &input);
    gfe4x_mul(&y21, &y21, &c.c2);
    gfe4x_mul(&y22, &y21, &c.sqrtMinusOne);
    gfe4x_mul(&gx2, &gx1, &tv1);
    gfe4x_square(&tv2, &y21);
    gfe4x_mul(&tv2, &tv2, &gxd);
    equal(e2, tv2, gx2);
    y2 = y22;
    gfe4x_cmov(&y2, &y21, e2);

    gfe4x_square(&tv2, &y1);
    gfe4x_mul(&tv2, &tv2, &gxd);
    equal(e3, tv2, gx1);
    xmn = x2n;
    gfe4x_cmov(&xmn, &x1n, e3);
    ymn = y2;
    gfe4x_cmov(&ymn, &y1, e3);
    gfe4x_getparity(e4, &ymn);
    gfe4x_neg(&yneg, &ymn);
    select[0] = static_cast<unsigned char>(e3[0] ^ e4[0]);
    select[1] = static_cast<unsigned char>(e3[1] ^ e4[1]);
    select[2] = static_cast<unsigned char>(e3[2] ^ e4[2]);
    select[3] = static_cast<unsigned char>(e3[3] ^ e4[3]);
    gfe4x_cmov(&ymn, &yneg, select);

    xn = xmn;
    gfe4x_mul(&xn, &xn, &c.sqrtMinus486664);
    gfe4x_mul(&xdn, &xd, &ymn);
    gfe4x_sub(&yn, &xmn, &xd);
    gfe4x_add(&yd, &xmn, &xd);
    gfe4x_mul(&tv1, &xdn, &yd);
    equal(select, tv1, c.zero);
    gfe4x_cmov(&xn, &c.zero, select);
    gfe4x_cmov(&xdn, &c.one, select);
    gfe4x_cmov(&yn, &c.one, select);
    gfe4x_cmov(&yd, &c.one, select);

    gfe4x_mul(&r->x, &xn, &yd);
    gfe4x_mul(&r->y, &yn, &xdn);
    gfe4x_mul(&r->z, &xdn, &yd);
    gfe4x_mul(&r->t, &xn, &yn);
}
