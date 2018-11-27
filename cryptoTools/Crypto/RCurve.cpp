#include "RCurve.h"

#ifdef ENABLE_RELIC

extern "C" {
#include "relic/relic_core.h"
#include "relic/relic_fp.h"
}

namespace osuCrypto
{




    REccNumber::REccNumber(const REccNumber & num)
    {
        init();
        *this = num;
    }

    REccNumber::REccNumber()
    {
        init();
    }


    REccNumber::REccNumber(PRNG & prng)
    {
        init();
        randomize(prng);
    }

    REccNumber::REccNumber(const i32 & val)
    {
        init();
        *this = val;
    }


    REccNumber::REccNumber(REllipticCurve&, const REccNumber & num)
    {
        init();
        *this = num;
    }

    REccNumber::REccNumber(REllipticCurve&)
    {
        init();
    }


    REccNumber::REccNumber(REllipticCurve&,PRNG & prng)
    {
        init();
        randomize(prng);
    }

    REccNumber::REccNumber(REllipticCurve&,const i32 & val)
    {
        init();
        *this = val;
    }

    REccNumber::~REccNumber()
    {
        bn_clean(*this);
    }

    REccNumber & REccNumber::operator=(const REccNumber & c)
    {
        *this = c.mVal;
        return *this;
    }

    REccNumber & REccNumber::operator=(const bn_t c)
    {
        bn_copy(*this, c);
        return *this;
    }

    REccNumber & REccNumber::operator=(int i)
    {
        bn_set_dig(mVal, i);
        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator++()
    {
        return *this += 1;
    }

    REccNumber & REccNumber::operator--()
    {
        return *this -= 1;
    }

    REccNumber & REccNumber::operator+=(int i)
    {
        bn_add_dig(*this, *this, 1);
        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator-=(int i)
    {
        bn_sub_dig(*this, *this, 1);
        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator+=(const REccNumber & b)
    {
        bn_add(*this, *this, b);
        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator-=(const REccNumber & b)
    {
        bn_sub(*this, *this, b);
        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator*=(const REccNumber & b)
    {
        bn_mul(*this, *this, b);
        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator*=(int i)
    {
        bn_mul_dig(*this, *this, i);
        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator/=(const REccNumber & b)
    {
        return (*this *= b.inverse());
    }

    REccNumber & REccNumber::operator/=(int i)
    {
        REccNumber iInv, y, c;


        bn_gcd_ext_dig(c, y, iInv, modulus(), i);


        return (*this *= iInv);
    }

    void REccNumber::init()
    {
        bn_new(mVal);
        bn_init(mVal, sizeDigits());
    }

    void REccNumber::reduce()
    {
        //auto t = *this;
        bn_mod_basic(*this, *this, modulus());
    }

    const bn_st * REccNumber::modulus() const { return &core_get()->ep_r; }

    REccNumber REccNumber::negate() const
    {
        REccNumber r;
        bn_neg(r, *this);
        r.reduce();
        return r;
    }

    REccNumber REccNumber::inverse() const
    {
        REccNumber bInv,y,c;

        bn_gcd_ext_basic(c, bInv, y, *this, modulus());
        bInv.reduce();

        return bInv;
    }

    bool REccNumber::operator==(const REccNumber & cmp) const
    {
        return bn_cmp(*this, cmp) == CMP_EQ;
    }

    bool REccNumber::operator==(const int & cmp) const
    {
        return bn_cmp_dig(*this, cmp) == CMP_EQ;
    }

    bool REccNumber::operator!=(const REccNumber & cmp) const
    {
        return !(*this == cmp);
    }

    bool REccNumber::operator!=(const int & cmp) const
    {
        return !(*this == cmp);
    }

    bool REccNumber::operator>=(const REccNumber & cmp) const
    {
        return  bn_cmp(*this, cmp) != CMP_LT;
    }

    bool REccNumber::operator>=(const int & cmp) const
    {
        return bn_cmp_dig(*this, cmp) != CMP_LT;
    }

    bool REccNumber::operator<=(const REccNumber & cmp) const
    {
        return cmp >= *this;
    }

    bool REccNumber::operator<=(const int & cmp) const
    {
        return bn_cmp_dig(*this, cmp) != CMP_GT;
    }

    bool REccNumber::operator>(const REccNumber & cmp) const
    {
        return bn_cmp(*this, cmp) == CMP_GT;
    }

    bool REccNumber::operator>(const int & cmp) const
    {
        return bn_cmp_dig(*this, cmp) == CMP_GT;
    }

    bool REccNumber::operator<(const REccNumber & cmp) const
    {
        return cmp > *this;
    }

    bool REccNumber::operator<(const int & cmp) const
    {
        return bn_cmp_dig(*this, cmp) == CMP_LT;
    }

    bool REccNumber::iszero() const
    {
        return bn_is_zero(*this);
    }

    bool operator==(const int & cmp1, const REccNumber & cmp2)
    {
        return cmp2 == cmp1;
    }

    bool operator!=(const int & cmp1, const REccNumber & cmp2)
    {
        return cmp2 != cmp1;
    }

    REccNumber operator-(const REccNumber &v)
    {
        return v.negate();
    }

    REccNumber operator+(int i, const REccNumber &v)
    {
        REccNumber r;
        bn_add_dig(r, v, i);
        r.reduce();
        return r;
    }
    REccNumber operator+(const REccNumber &i, const REccNumber &v)
    {
        REccNumber r;
        bn_add(r, v, i);
        r.reduce();
        return r;
    }
    REccNumber operator-(const REccNumber & v, int i)
    {
        REccNumber r;
        bn_sub_dig(r, v, i);
        r.reduce();
        return r;
    }
    REccNumber operator-(int i, const REccNumber &v)
    {
        return i + v.negate();
    }
    REccNumber operator-(const REccNumber &v, const REccNumber &i)
    {
        REccNumber r;
        bn_sub(r, v, i);
        r.reduce();
        return r;
    }
    REccNumber operator*(const REccNumber & v, int i)
    {
        REccNumber r;
        bn_mul_dig(r, v, i);
        r.reduce();
        return r;
    }
    REccNumber operator*(int i, const REccNumber &v)
    {
        return v * i;
    }
    REccNumber operator*(const REccNumber & v, const REccNumber &i)
    {
        REccNumber r;
        bn_mul(r, v, i);
        r.reduce();
        return r;
    }
    REccNumber operator/(const REccNumber & v, int i)
    {
        auto vv = v;
        vv /= i;
        return vv;
    }
    REccNumber operator/(int i, const REccNumber &v)
    {
        return i * v.inverse();
    }
    REccNumber operator/(const REccNumber &i, const REccNumber &v)
    {
        return i * v.inverse();
    }

    REccNumber operator^(const REccNumber & base, const REccNumber & exp)
    {
        REccNumber r;
        bn_mxp_basic(r, base, exp, base.modulus());
        return r;
    }

    std::ostream & operator<<(std::ostream & out, const REccNumber & val)
    {
        auto radix = 16;
        auto size = bn_size_str(val, radix);
        std::string str(size, 0);
        bn_write_str(&str[0], size, val, radix);
        out << str;
        return out;
    }
    std::ostream & operator<<(std::ostream & out, const REccPoint & val)
    {
        auto radix = 16;
        std::string buff(fp_size_str(val.mVal->x, radix), '0');
        fp_write_str(&buff[0], buff.size(), val.mVal->x, radix);
        out << "("<< buff << ", ";
        fp_write_str(&buff[0], buff.size(), val.mVal->y, radix);
        out << buff << ", ";
        fp_write_str(&buff[0], buff.size(), val.mVal->z, radix);
        out << buff << ")";
        return out;
    }

    REccNumber operator+(const REccNumber &v, int i)
    {
        REccNumber r;
        bn_add_dig(r, v, i);
        r.reduce();
        return r;
    }

    REllipticCurve::REllipticCurve()
    {
        if (core_get() == nullptr)
            core_init();

        ep_param_set_any();
    }

    REllipticCurve::Point REllipticCurve::getGenerator() const
    {
        Point g;
        ep_curve_get_gen(g);
        return g;
        // TODO: insert return statement here
    }

    std::vector<REllipticCurve::Point> REllipticCurve::getGenerators() const
    {
        return {getGenerator()};
    }

    REccNumber REllipticCurve::getOrder() const
    {
        REccNumber g;
        ep_curve_get_ord(g);
        return g;
    }




    REccPoint & REccPoint::operator=(const REccPoint & copy)
    {
        ep_copy(*this, copy);
        return *this;
    }

    REccPoint & REccPoint::operator+=(const REccPoint & addIn)
    {
        ep_add(*this, *this, addIn);
        return *this;
    }

    REccPoint & REccPoint::operator-=(const REccPoint & subtractIn)
    {
        ep_sub(*this, *this, subtractIn);
        return *this;
    }

    REccPoint & REccPoint::operator*=(const REccNumber & multIn)
    {
        ep_mul(*this, *this, multIn);
        return *this;
    }

    REccPoint REccPoint::operator+(const REccPoint & addIn) const
    {
        REccPoint r;
        ep_add(r, *this, addIn);
        return r;
    }

    REccPoint REccPoint::operator-(const REccPoint & subtractIn) const
    {
        REccPoint r;
        ep_sub(r, *this, subtractIn);
        return r;
    }

    REccPoint REccPoint::operator*(const REccNumber & multIn) const
    {
        REccPoint r;
        ep_mul(r, *this, multIn);
        return r;
    }

    bool REccPoint::operator==(const REccPoint & cmp) const
    {
        return ep_cmp(*this, cmp) == CMP_EQ;
    }

    bool REccPoint::operator!=(const REccPoint & cmp) const
    {
        return ep_cmp(*this, cmp) != CMP_EQ;
    }

    u64 REccPoint::sizeBytes() const
    {
        return 1 + FP_BYTES;
    }

    void REccPoint::toBytes(u8 * dest) const
    {
        ep_write_bin(dest, sizeBytes(), *this, 1);
    }

    void REccPoint::fromBytes(u8 * src)
    {
        ep_read_bin(*this, src, sizeBytes());
    }

    void REccPoint::randomize(PRNG & prng)
    {
        randomize(prng.get<block>());
    }

    void REccPoint::randomize(const block & seed)
    {
        ep_map(*this, (u8*)&seed, sizeof(block));
    }

    u64 REccNumber::sizeDigits() const
    {
        return bn_size_raw(modulus());
    }

    u64 REccNumber::sizeBytes() const
    {
        return
            bn_size_bin(modulus());
    }

    void REccNumber::toBytes(u8 * dest) const
    {
        bn_write_bin(dest, sizeBytes(), *this);
    }

    void REccNumber::fromBytes(const u8 * src)
    {
        bn_read_bin(*this, src, sizeBytes());
    }

    void REccNumber::fromHex(const char * src)
    {
        auto len = std::strlen(src);
        bn_read_str(*this, src, len, 16);
    }

    void REccNumber::randomize(PRNG & prng)
    { 
        std::array<u8, BN_SIZE * sizeof(dig_t)> buff;
        prng.get(buff.data(), sizeBytes());
        fromBytes(buff.data());
        reduce();

    }

    void REccNumber::randomize(const block & seed)
    {
        PRNG prng(seed);
        randomize(prng);
    }

}

#endif