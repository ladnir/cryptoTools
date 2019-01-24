#pragma once

#include <cryptoTools/Common/Defines.h>

#ifdef ENABLE_RELIC


extern "C" {
    #include <relic/relic_bn.h>
    #include <relic/relic_ep.h>
}
#ifdef MONTY
#undef MONTY
#endif
#include <cryptoTools/Crypto/PRNG.h>

namespace osuCrypto
{


    class REllipticCurve;
    class REccPoint;
    class EccBrick;


    class REccNumber
    {
    public:

        REccNumber();
        REccNumber(const REccNumber& num);
        REccNumber(PRNG& prng);
        REccNumber(const i32& val);

        // backwards compatible constructors
        REccNumber(REllipticCurve&);
        REccNumber(REllipticCurve&, const REccNumber& num);
        REccNumber(REllipticCurve&, PRNG& prng);
        REccNumber(REllipticCurve&, const i32& val);

        ~REccNumber();

        REccNumber& operator=(const REccNumber& c);
        REccNumber& operator=(const bn_t c);
        REccNumber& operator=(int i);


        REccNumber& operator++();
        REccNumber& operator--();
        REccNumber& operator+=(int i);
        REccNumber& operator-=(int i);
        REccNumber& operator+=(const REccNumber& b);
        REccNumber& operator-=(const REccNumber& b);
        REccNumber& operator*=(const REccNumber& b);
        REccNumber& operator*=(int i);
        REccNumber& operator/=(const REccNumber& b);
        REccNumber& operator/=(int i);
        //void inplaceNegate();
        REccNumber negate() const;
        REccNumber inverse() const;

        bool operator==(const REccNumber& cmp) const;
        bool operator==(const int& cmp)const;
        friend bool operator==(const int& cmp1, const REccNumber& cmp2);
        bool operator!=(const REccNumber& cmp)const;
        bool operator!=(const int& cmp)const;
        friend bool operator!=(const int& cmp1, const REccNumber& cmp2);

        bool operator>=(const REccNumber& cmp)const;
        bool operator>=(const int& cmp)const;

        bool operator<=(const REccNumber& cmp)const;
        bool operator<=(const int& cmp)const;

        bool operator>(const REccNumber& cmp)const;
        bool operator>(const int& cmp)const;

        bool operator<(const REccNumber& cmp)const;
        bool operator<(const int& cmp)const;

        bool isPrime() const;
        bool iszero() const;

        //const REccNumber& modulus() const;

        friend REccNumber operator-(const REccNumber&);
        friend REccNumber operator+(const REccNumber&, int);
        friend REccNumber operator+(int, const REccNumber&);
        friend REccNumber operator+(const REccNumber&, const REccNumber&);

        friend REccNumber operator-(const REccNumber&, int);
        friend REccNumber operator-(int, const REccNumber&);
        friend REccNumber operator-(const REccNumber&, const REccNumber&);

        friend REccNumber operator*(const REccNumber&, int);
        friend REccNumber operator*(int, const REccNumber&);
        friend REccNumber operator*(const REccNumber&, const REccNumber&);

        friend REccNumber operator/(const REccNumber&, int);
        friend REccNumber operator/(int, const REccNumber&);
        friend REccNumber operator/(const REccNumber&, const REccNumber&);

        friend REccNumber operator^(const REccNumber& base, const REccNumber& exp);

        u64 sizeDigits() const;
        u64 sizeBytes() const;
        void toBytes(u8* dest) const;
        void fromBytes(const u8* src);
        void fromHex(const char* src);
        //void fromDec(const char* src);

        void randomize(PRNG& prng);
        void randomize(const block& seed);

        operator bn_t& () { return mVal; }
        operator const bn_t& () const { return mVal; }

    private:

        void init();
        void reduce();

        const bn_st* modulus()const;

    public:
        bn_t  mVal;

        friend class REllipticCurve;
        friend REccPoint;
        friend std::ostream& operator<<(std::ostream& out, const REccNumber& val);
    };
    std::ostream& operator<<(std::ostream& out, const REccNumber& val);


    class REccPoint
    {
    public:

        REccPoint() { ep_new(mVal); };
        REccPoint(PRNG& prng) { ep_new(mVal); randomize(prng); }
        REccPoint(const REccPoint& copy) { ep_new(mVal); ep_copy(*this, copy); }

        // backwards compatible constructors
        REccPoint(REllipticCurve&) { ep_new(mVal); };
        REccPoint(REllipticCurve&, const REccPoint& copy) { ep_new(mVal); ep_copy(*this, copy);}

        ~REccPoint() { ep_free(mVal); }

        REccPoint& operator=(const REccPoint& copy);
        REccPoint& operator+=(const REccPoint& addIn);
        REccPoint& operator-=(const REccPoint& subtractIn);
        REccPoint& operator*=(const REccNumber& multIn);


        REccPoint operator+(const REccPoint& addIn) const;
        REccPoint operator-(const REccPoint& subtractIn) const;
        REccPoint operator*(const REccNumber& multIn) const;

        bool operator==(const REccPoint& cmp) const;
        bool operator!=(const REccPoint& cmp) const;

        u64 sizeBytes() const;
        void toBytes(u8* dest) const;
        void fromBytes(u8* src);
        //void fromHex(char* x, char* y);
        //void fromDec(char* x, char* y);
        //void fromNum(REccNumber& x, REccNumber& y);

        void randomize(PRNG& prng);
        void randomize(const block& seed);
        void randomize();


        operator ep_t& () { return mVal; }
        operator const ep_t& () const { return mVal; }

        ep_t mVal;
    private:

        friend EccBrick;
        friend REccNumber;
        friend std::ostream& operator<<(std::ostream& out, const REccPoint& val);
    };

    std::ostream& operator<<(std::ostream& out, const REccPoint& val);

    //class EccBrick
    //{
    //public:
    //    EccBrick(const REccPoint& copy);
    //    EccBrick(EccBrick&& copy);

    //    REccPoint operator*(const REccNumber& multIn) const;

    //    void multiply(const REccNumber& multIn, REccPoint& result) const;

    //private:

    //    ebrick2 mBrick2;
    //    ebrick mBrick;
    //    REllipticCurve* mCurve;

    //};

    class REllipticCurve
    {
    public:
        typedef REccPoint Point;



        REllipticCurve();


        Point getGenerator() const;
        std::vector<Point> getGenerators() const;
        REccNumber getOrder() const;

    private:

        friend Point;
        friend REccNumber;
    };
}
#endif