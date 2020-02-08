#include "RCurve.h"
#include <string>

#ifdef ENABLE_RELIC

extern "C" {
#include "relic/relic_core.h"
#include "relic/relic_fp.h"
}

#if !defined(GSL_UNLIKELY)
#define GSL_UNLIKELY(x) x
#endif

#ifndef RLC_EQ
#define RLC_EQ CMP_EQ
#endif
#ifndef RLC_LT
#define RLC_LT CMP_LT
#endif
#ifndef RLC_GT
#define RLC_GT CMP_GT
#endif
#ifndef RLC_FP_BYTES
#define RLC_FP_BYTES FP_BYTES
#endif
#ifndef RLC_FP_BYTES
#define RLC_FP_BYTES FP_BYTES
#endif
#ifndef RLC_BN_SIZE
#define RLC_BN_SIZE BN_SIZE
#endif

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
        
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic copy error " LOCATION);

        return *this;
    }

    REccNumber & REccNumber::operator=(int i)
    {
        bn_set_dig(mVal, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic set int error " LOCATION);

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

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic add int error " LOCATION);

        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator-=(int i)
    {
        bn_sub_dig(*this, *this, 1);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic sub int error " LOCATION);

        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator+=(const REccNumber & b)
    {
        bn_add(*this, *this, b);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic add error " LOCATION);
        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator-=(const REccNumber & b)
    {
        bn_sub(*this, *this, b);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic sub error " LOCATION);
        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator*=(const REccNumber & b)
    {
        bn_mul(*this, *this, b);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic mul error " LOCATION);

        reduce();
        return *this;
    }

    REccNumber & REccNumber::operator*=(int i)
    {
        bn_mul_dig(*this, *this, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic mul error " LOCATION);

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

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic div error " LOCATION);



        return (*this *= iInv);
    }

    void REccNumber::init()
    {
        bn_new(mVal);
        bn_init(mVal, static_cast<int>(sizeDigits()));
    }

    void REccNumber::reduce()
    {
        //auto t = *this;
        bn_mod_basic(*this, *this, modulus());

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic mod error " LOCATION);

    }

    const bn_st * REccNumber::modulus() const { return &core_get()->ep_r; }

    REccNumber REccNumber::negate() const
    {
        REccNumber r;
        bn_neg(r, *this);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic neg error " LOCATION);

        r.reduce();
        return r;
    }

    REccNumber REccNumber::inverse() const
    {
        REccNumber bInv,y,c;

        bn_gcd_ext_basic(c, bInv, y, *this, modulus());

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic inverse error " LOCATION);

        bInv.reduce();

        return bInv;
    }

    bool REccNumber::operator==(const REccNumber & cmp) const
    {
        return bn_cmp(*this, cmp) == RLC_EQ;
    }

    bool REccNumber::operator==(const int & cmp) const
    {
        return bn_cmp_dig(*this, cmp) == RLC_EQ;
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
        return  bn_cmp(*this, cmp) != RLC_LT;
    }

    bool REccNumber::operator>=(const int & cmp) const
    {
        return bn_cmp_dig(*this, cmp) != RLC_LT;
    }

    bool REccNumber::operator<=(const REccNumber & cmp) const
    {
        return cmp >= *this;
    }


    bool REccNumber::operator<=(const int & cmp) const
    {
        return bn_cmp_dig(*this, cmp) != RLC_GT;
    }

    bool REccNumber::operator>(const REccNumber & cmp) const
    {
        return bn_cmp(*this, cmp) == RLC_GT;
    }

    bool REccNumber::operator>(const int & cmp) const
    {
        return bn_cmp_dig(*this, cmp) == RLC_GT;
    }

    bool REccNumber::operator<(const REccNumber & cmp) const
    {
        return cmp > *this;
    }

    bool REccNumber::operator<(const int & cmp) const
    {
        return bn_cmp_dig(*this, cmp) == RLC_LT;
    }

    bool REccNumber::isPrime() const
    {
        return bn_is_prime(*this);
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


        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic add error " LOCATION);


        r.reduce();
        return r;
    }
    REccNumber operator+(const REccNumber &i, const REccNumber &v)
    {
        REccNumber r;
        bn_add(r, v, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic add error " LOCATION);

        r.reduce();
        return r;
    }
    REccNumber operator-(const REccNumber & v, int i)
    {
        REccNumber r;
        bn_sub_dig(r, v, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic sub error " LOCATION);

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

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic sub error " LOCATION);

        r.reduce();
        return r;
    }
    REccNumber operator*(const REccNumber & v, int i)
    {
        REccNumber r;
        bn_mul_dig(r, v, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic mul error " LOCATION);

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

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic mul error " LOCATION);

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


        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic exp error " LOCATION);

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

        auto print = [radix](std::ostream& out, const fp_t& c) {

            std::string buff(RLC_FP_BYTES * 2 + 1, ' ');

            if (i64(buff.size()) < i64(fp_size_str(c, radix)))
            {
                std::cout << "buff.size() " << buff.size() << std::endl;
                std::cout << "fp_size_str " << fp_size_str(c, radix) << std::endl;
                throw std::runtime_error(LOCATION);
            }
            fp_write_str(&buff[0], static_cast<int>(buff.size()), c, radix);
            if (GSL_UNLIKELY(err_get_code()))
                throw std::runtime_error("Relic write error " LOCATION);

            out << buff;
        };

        REccPoint val2;

        ep_norm(val2, val);

        out << "(";
        print(out, val2.mVal->x);
        out << ", ";
        print(out, val2.mVal->y);
        out << ", ";
        print(out, val2.mVal->z);
        out << ")";

        return out;
    }

    REccNumber operator+(const REccNumber &v, int i)
    {
        REccNumber r;
        bn_add_dig(r, v, i);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic add error " LOCATION);
        r.reduce();
        return r;
    }

    REllipticCurve::REllipticCurve()
    {
        if (core_get() == nullptr)
            core_init();

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic core init error " LOCATION);

        ep_param_set_any();
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic set any error " LOCATION);
    }

    REllipticCurve::Point REllipticCurve::getGenerator() const
    {
        Point g;
        ep_curve_get_gen(g);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic get gen error " LOCATION);

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

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic get order error " LOCATION);
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

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_add error " LOCATION);
        return *this;
    }

    REccPoint & REccPoint::operator-=(const REccPoint & subtractIn)
    {
        ep_sub(*this, *this, subtractIn);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_sub error " LOCATION);
        return *this;
    }

    REccPoint & REccPoint::operator*=(const REccNumber & multIn)
    {
        ep_mul(*this, *this, multIn);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_mul error " LOCATION);
        return *this;
    }

    REccPoint REccPoint::operator+(const REccPoint & addIn) const
    {
        REccPoint r;
        ep_add(r, *this, addIn);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_add error " LOCATION);
        return r;
    }

    REccPoint REccPoint::operator-(const REccPoint & subtractIn) const
    {
        REccPoint r;
        ep_sub(r, *this, subtractIn);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_sub error " LOCATION);
        return r;
    }

    REccPoint REccPoint::operator*(const REccNumber & multIn) const
    {
        REccPoint r;
        ep_mul(r, *this, multIn);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_mul error " LOCATION);
        return r;
    }

    bool REccPoint::operator==(const REccPoint & cmp) const
    {
        return ep_cmp(*this, cmp) == RLC_EQ;
    }

    bool REccPoint::operator!=(const REccPoint & cmp) const
    {
        return ep_cmp(*this, cmp) != RLC_EQ;
    }

    u64 REccPoint::sizeBytes() const
    {
        return 1 + RLC_FP_BYTES;
    }

    void REccPoint::toBytes(u8 * dest) const
    {
        ep_write_bin(dest, static_cast<int>(sizeBytes()), *this, 1);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_write error " LOCATION);
    }

    void REccPoint::fromBytes(u8 * src)
    {
        ep_read_bin(*this, src, static_cast<int>(sizeBytes()));
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_read error " LOCATION);
    }

    void REccPoint::randomize(PRNG & prng)
    {
        randomize(prng.get<block>());
    }

    void REccPoint::randomize(const block & seed)
    {
        ep_map(*this, (u8*)&seed, sizeof(block));
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_map error " LOCATION);
    }

    void REccPoint::randomize()
    {
        ep_rand(*this);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_rand error " LOCATION);
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
        bn_write_bin(dest, static_cast<int>(sizeBytes()), *this);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic write error " LOCATION);
    }

    void REccNumber::fromBytes(const u8 * src)
    {
        bn_read_bin(*this, src, static_cast<int>(sizeBytes()));
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic read error " LOCATION);
    }

    void REccNumber::fromHex(const char * src)
    {
        auto len = std::strlen(src);
        bn_read_str(*this, src, static_cast<int>(len), 16);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic read error " LOCATION);
    }

    void REccNumber::randomize(PRNG & prng)
    { 
        std::array<u8, RLC_BN_SIZE * sizeof(dig_t)> buff;
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