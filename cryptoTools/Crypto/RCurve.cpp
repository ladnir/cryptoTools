#include "RCurve.h"
#include <string>

#ifdef ENABLE_RELIC

extern "C" {
#include "relic/relic_core.h"
#include "relic/relic_fp.h"
#include "relic/relic_util.h"
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

#if !defined(MULTI) || ((MULTI != PTHREAD) && (MULTI != OPENMP) && (MULTI != MSVCTLS))
static_assert(0, "Relic must be built with -DMULTI=PTHREAD or -DMULTI=OPENMP");
#endif


namespace osuCrypto
{




    REccNumber::REccNumber(const REccNumber& num)
    {
        init();
        *this = num;
    }

    REccNumber::REccNumber()
    {
        init();
    }


    REccNumber::REccNumber(PRNG& prng)
    {
        init();
        randomize(prng);
    }

    REccNumber::REccNumber(const i32& val)
    {
        init();
        *this = val;
    }


    REccNumber::REccNumber(REllipticCurve&, const REccNumber& num)
    {
        init();
        *this = num;
    }

    REccNumber::REccNumber(REllipticCurve&)
    {
        init();
    }


    REccNumber::REccNumber(REllipticCurve&, PRNG& prng)
    {
        init();
        randomize(prng);
    }

    REccNumber::REccNumber(REllipticCurve&, const i32& val)
    {
        init();
        *this = val;
    }

    REccNumber::~REccNumber()
    {
        bn_clean(*this);
    }

    REccNumber& REccNumber::operator=(const REccNumber& c)
    {
        *this = c.mVal;
        return *this;
    }

    REccNumber& REccNumber::operator=(const bn_t c)
    {
        if(!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        bn_copy(*this, c);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic copy error " LOCATION);

        return *this;
    }

    REccNumber& REccNumber::operator=(int i)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        if (i < 0)
        {
            i = -i;
            bn_set_dig(mVal, i);
            bn_neg(*this, *this);
        }
        else
        {
            bn_set_dig(mVal, i);
        }
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic set int error " LOCATION);

        reduce();
        return *this;
    }

    REccNumber& REccNumber::operator++()
    {
        return *this += 1;
    }

    REccNumber& REccNumber::operator--()
    {
        return *this -= 1;
    }

    REccNumber& REccNumber::operator+=(int i)
    {
        if (i < 0)
            return *this -= -i;

        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        bn_add_dig(*this, *this, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic add int error " LOCATION);

        reduce();
        return *this;
    }

    REccNumber& REccNumber::operator-=(int i)
    {
        if (i < 0)
            return *this += -i;
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        bn_sub_dig(*this, *this, i);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic sub int error " LOCATION);

        reduce();
        return *this;
    }

    REccNumber& REccNumber::operator+=(const REccNumber& b)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        bn_add(*this, *this, b);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic add error " LOCATION);
        reduce();
        return *this;
    }

    REccNumber& REccNumber::operator-=(const REccNumber& b)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        bn_sub(*this, *this, b);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic sub error " LOCATION);
        reduce();
        return *this;
    }

    REccNumber& REccNumber::operator*=(const REccNumber& b)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        bn_mul(*this, *this, b);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic mul error " LOCATION);

        reduce();
        return *this;
    }

    REccNumber& REccNumber::operator*=(int i)
    {
        if (i < 0)
            return *this *= REccNumber(i);
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        bn_mul_dig(*this, *this, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic mul error " LOCATION);

        reduce();
        return *this;
    }

    REccNumber& REccNumber::operator/=(const REccNumber& b)
    {
        return (*this *= b.inverse());
    }

    REccNumber& REccNumber::operator/=(int i)
    {
        if (i < 0)
            return *this /= REccNumber(i);
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber iInv, y, c;
        bn_gcd_ext_dig(c, y, iInv, modulus(), i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic div error " LOCATION);

        return (*this *= iInv);
    }

    void REccNumber::init()
    {
        bn_new(mVal);
        //bn_init(mVal, static_cast<int>(sizeDigits()));
    }

    void REccNumber::reduce()
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        //auto t = *this;
        bn_mod_basic(*this, *this, modulus());

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic mod error " LOCATION);

    }

    const bn_st* REccNumber::modulus() const { return &core_get()->ep_r; }

    REccNumber REccNumber::negate() const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber r;
        bn_neg(r, *this);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic neg error " LOCATION);

        r.reduce();
        return r;
    }

    REccNumber REccNumber::inverse() const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber bInv, y, c;

        bn_gcd_ext_basic(c, bInv, y, *this, modulus());

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic inverse error " LOCATION);

        bInv.reduce();

        return bInv;
    }

    bool REccNumber::operator==(const REccNumber& cmp) const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return bn_cmp(*this, cmp) == RLC_EQ;
    }

    bool REccNumber::operator==(const int& cmp) const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        if (cmp < 0)
            return *this == REccNumber(cmp);

        return bn_cmp_dig(*this, cmp) == RLC_EQ;
    }

    bool REccNumber::operator!=(const REccNumber& cmp) const
    {
        return !(*this == cmp);
    }

    bool REccNumber::operator!=(const int& cmp) const
    {
        return !(*this == cmp);
    }

    bool REccNumber::operator>=(const REccNumber& cmp) const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return  bn_cmp(*this, cmp) != RLC_LT;
    }

    bool REccNumber::operator>=(const int& cmp) const
    {
        if (cmp < 0)
            return *this >= REccNumber(cmp);
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return bn_cmp_dig(*this, cmp) != RLC_LT;
    }

    bool REccNumber::operator<=(const REccNumber& cmp) const
    {
        return cmp >= *this;
    }


    bool REccNumber::operator<=(const int& cmp) const
    {
        if (cmp < 0)
            return *this <= REccNumber(cmp);
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return bn_cmp_dig(*this, cmp) != RLC_GT;
    }

    bool REccNumber::operator>(const REccNumber& cmp) const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return bn_cmp(*this, cmp) == RLC_GT;
    }

    bool REccNumber::operator>(const int& cmp) const
    {
        if (cmp < 0)
            return *this > REccNumber(cmp);
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return bn_cmp_dig(*this, cmp) == RLC_GT;
    }

    bool REccNumber::operator<(const REccNumber& cmp) const
    {
        return cmp > * this;
    }

    bool REccNumber::operator<(const int& cmp) const
    {
        if (cmp < 0)
            return *this < REccNumber(cmp);
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return bn_cmp_dig(*this, cmp) == RLC_LT;
    }

    bool REccNumber::isPrime() const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return bn_is_prime(*this);
    }

    bool REccNumber::iszero() const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return bn_is_zero(*this);
    }

    bool operator==(const int& cmp1, const REccNumber& cmp2)
    {
        return cmp2 == cmp1;
    }

    bool operator!=(const int& cmp1, const REccNumber& cmp2)
    {
        return cmp2 != cmp1;
    }

    REccNumber operator-(const REccNumber& v)
    {
        return v.negate();
    }

    REccNumber operator+(int i, const REccNumber& v)
    {
        if (i < 0)
            return REccNumber(i) + v;
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber r;
        bn_add_dig(r, v, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic add error " LOCATION);

        r.reduce();
        return r;
    }
    REccNumber operator+(const REccNumber& i, const REccNumber& v)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber r;
        bn_add(r, v, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic add error " LOCATION);

        r.reduce();
        return r;
    }
    REccNumber operator-(const REccNumber& v, int i)
    {
        if (i < 0)
            return v - REccNumber(i);
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber r;
        bn_sub_dig(r, v, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic sub error " LOCATION);

        r.reduce();
        return r;
    }
    REccNumber operator-(int i, const REccNumber& v)
    {
        return i + v.negate();
    }
    REccNumber operator-(const REccNumber& v, const REccNumber& i)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber r;
        bn_sub(r, v, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic sub error " LOCATION);

        r.reduce();
        return r;
    }
    REccNumber operator*(const REccNumber& v, int i)
    {
        if (i < 0)
            return v * REccNumber(i);
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber r;
        bn_mul_dig(r, v, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic mul error " LOCATION);

        r.reduce();
        return r;
    }
    REccNumber operator*(int i, const REccNumber& v)
    {
        return v * i;
    }
    REccNumber operator*(const REccNumber& v, const REccNumber& i)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber r;
        bn_mul(r, v, i);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic mul error " LOCATION);

        r.reduce();
        return r;
    }
    REccNumber operator/(const REccNumber& v, int i)
    {
        auto vv = v;
        vv /= i;
        return vv;
    }
    REccNumber operator/(int i, const REccNumber& v)
    {
        return i * v.inverse();
    }
    REccNumber operator/(const REccNumber& i, const REccNumber& v)
    {
        return i * v.inverse();
    }

    REccNumber operator^(const REccNumber& base, const REccNumber& exp)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber r;
        bn_mxp_basic(r, base, exp, base.modulus());


        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic exp error " LOCATION);

        return r;
    }

    std::ostream& operator<<(std::ostream& out, const REccNumber& val)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        auto radix = 16;
        auto size = bn_size_str(val, radix);
        std::string str(size, 0);
        bn_write_str(&str[0], size, val, radix);

        while (str.size() && str.back() == 0)
            str.resize(str.size() - 1);

        if (str.size() == 0)
            str = "0";

        out << str;
        return out;
    }

    std::ostream& operator<<(std::ostream& out, const REccPoint& val)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

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

    REccNumber operator+(const REccNumber& v, int i)
    {
        if (i < 0)
            return v + REccNumber(i);
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber r;
        bn_add_dig(r, v, i);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic add error " LOCATION);
        r.reduce();
        return r;
    }

    REllipticCurve::REllipticCurve(u64 curveID)
    {
        if (core_get() == nullptr)
        {
            core_init();
            if (GSL_UNLIKELY(err_get_code()))
                throw std::runtime_error("Relic core init error " LOCATION);

            if (!curveID)
            {
                ep_param_set_any();
                if (GSL_UNLIKELY(err_get_code()))
                    throw std::runtime_error("Relic set any error " LOCATION);
            }
        }

        if (curveID)
        {
            if (curveID != ep_param_get())
            {
                ep_param_set(curveID);
                if (GSL_UNLIKELY(err_get_code()))
                    throw std::runtime_error("Relic set any error " LOCATION);
            }
        }
    }

    REllipticCurve::Point REllipticCurve::getGenerator() const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        Point g;
        ep_curve_get_gen(g);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic get gen error " LOCATION);

        return g;
        // TODO: insert return statement here
    }

    std::vector<REllipticCurve::Point> REllipticCurve::getGenerators() const
    {
        return { getGenerator() };
    }

    REccNumber REllipticCurve::getOrder() const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccNumber g;
        ep_curve_get_ord(g);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic get order error " LOCATION);
        return g;
    }


    bool REccPoint::iszero()const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return ep_is_infty(*this);
    }

    REccPoint& REccPoint::operator=(const REccPoint& copy)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        ep_copy(*this, copy);
        return *this;
    }

    REccPoint& REccPoint::operator+=(const REccPoint& addIn)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        ep_add(*this, *this, addIn);

        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_add error " LOCATION);
        return *this;
    }

    REccPoint& REccPoint::operator-=(const REccPoint& subtractIn)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        ep_sub(*this, *this, subtractIn);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_sub error " LOCATION);
        return *this;
    }

    REccPoint& REccPoint::operator*=(const REccNumber& multIn)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        ep_mul(*this, *this, multIn);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_mul error " LOCATION);
        return *this;
    }

    REccPoint REccPoint::operator+(const REccPoint& addIn) const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccPoint r;
        ep_add(r, *this, addIn);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_add error " LOCATION);
        return r;
    }

    REccPoint REccPoint::operator-(const REccPoint& subtractIn) const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccPoint r;
        ep_sub(r, *this, subtractIn);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_sub error " LOCATION);
        return r;
    }

    REccPoint REccPoint::operator*(const REccNumber& multIn) const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccPoint r;
        ep_mul(r, *this, multIn);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_mul error " LOCATION);
        return r;
    }

    REccPoint REccPoint::mulGenerator(const REccNumber& n)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        REccPoint r;
        ep_mul_gen(r, n);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_mul_gen error " LOCATION);
        return r;
    }

    bool REccPoint::operator==(const REccPoint& cmp) const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return ep_cmp(*this, cmp) == RLC_EQ;
    }

    bool REccPoint::operator!=(const REccPoint& cmp) const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        return ep_cmp(*this, cmp) != RLC_EQ;
    }

    void REccPoint::fromHash(const unsigned char* data, size_t len)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        ep_map(*this, data, len);
    }

    void REccPoint::toBytes(u8* dest) const
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        ep_write_bin(dest, static_cast<int>(sizeBytes()), *this, 1);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_write error " LOCATION);
    }

    void REccPoint::fromBytes(u8* src)
    {
        if (!core_get())
            throw std::runtime_error("Relic core not initialized on this thread. Construct a RCurve to initialize it. " LOCATION);

        ep_read_bin(*this, src, static_cast<int>(sizeBytes()));
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_read error " LOCATION);
    }



    namespace
    {
#ifndef RLC_TRY
#define RLC_TRY TRY
#define RLC_CATCH_ANY CATCH_ANY
#define RLC_THROW THROW
#define RLC_FINALLY FINALLY
#endif // !RLC_TRY

        void bn_rand(bn_t a, int sign, int bits, PRNG& prng) {
            int digits;

            RLC_RIP(bits, digits, bits);
            digits += (bits > 0 ? 1 : 0);

            bn_grow(a, digits);

            prng.get((uint8_t*)a->dp, digits * sizeof(dig_t));

            a->used = digits;
            a->sign = sign;
            if (bits > 0) {
                dig_t mask = ((dig_t)1 << (dig_t)bits) - 1;
                a->dp[a->used - 1] &= mask;
            }
            bn_trim(a);
        }

        void bn_rand_mod(bn_t a, bn_t b, PRNG& prng) {
            do {
                bn_rand(a, bn_sign(b), bn_bits(b) + 40, prng);
                bn_mod(a, a, b);
            } while (bn_is_zero(a) || bn_cmp_abs(a, b) != RLC_LT);
        }

        void ep_rand(ep_t p, PRNG& prng) {
            bn_t n, k;

            bn_null(k);
            bn_null(n);

            RLC_TRY{
                bn_new(k);
                bn_new(n);
                ep_curve_get_ord(n);
                bn_rand_mod(k, n, prng);

                ep_mul_gen(p, k);
            } RLC_CATCH_ANY{
                RLC_THROW(ERR_CAUGHT);
            } RLC_FINALLY{
                bn_free(k);
                bn_free(n);
            }
        }
    }


    void REccPoint::randomize(PRNG& prng)
    {
        ep_rand(*this, prng);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic ep_rand error " LOCATION);
    }

    void REccPoint::randomize(const block& seed)
    {
        PRNG prng(seed);
        randomize(prng);
    }
    void REccPoint::randomize()
    {
        ::ep_rand(*this);
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

    void REccNumber::toBytes(u8* dest) const
    {
        bn_write_bin(dest, static_cast<int>(sizeBytes()), *this);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic write error " LOCATION);
    }

    void REccNumber::fromBytes(const u8* src)
    {
        bn_read_bin(*this, src, static_cast<int>(sizeBytes()));
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic read error " LOCATION);
    }

    void REccNumber::fromHex(const char* src)
    {
        auto len = std::strlen(src);
        bn_read_str(*this, src, static_cast<int>(len), 16);
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic read error " LOCATION);
    }

    void REccNumber::randomize(PRNG& prng)
    {
        std::vector<u8> buff(sizeBytes() + 5);
        prng.get(buff.data(), buff.size());
        bn_read_bin(*this, buff.data(), static_cast<int>(buff.size()));
        if (GSL_UNLIKELY(err_get_code()))
            throw std::runtime_error("Relic randomize error " LOCATION);

        reduce();
    }

    void REccNumber::randomize(const block& seed)
    {
        PRNG prng(seed);
        randomize(prng);
    }
}

#endif
