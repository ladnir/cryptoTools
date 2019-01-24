
#include <cryptoTools/Crypto/Curve.h>

#ifdef ENABLE_MIRACL
#include <cryptoTools/Common/Log.h>
#include <miracl/include/miracl.h>
#include <sstream>

namespace osuCrypto
{
    EllipticCurve::EllipticCurve()
    {
        setParameters(p256k1);
        setPrng(sysRandomSeed());
    }

    EllipticCurve::EllipticCurve(const Ecc2mParams & params, const block& seed)
    {
        setParameters(params);
        setPrng(seed);
    }

    EllipticCurve::EllipticCurve(const EccpParams & params, const block & seed)
    {
        setParameters(params);
        setPrng(seed);
    }

    EllipticCurve::~EllipticCurve()
    {
        mG = std::vector<Point>();

        if (mMiracl)
        {
            mirexit(mMiracl);
        }
    }

    void EllipticCurve::setParameters(const Ecc2mParams & params, const block& seed)
    {
        setPrng(seed);
        setParameters(params);
    }

    void EllipticCurve::setParameters(const EccpParams & params)
    {

        mIsPrimeField = true;
        mEcc2mParams = Ecc2mParams();
        mEccpParams = params;

        if (mMiracl) mirexit(mMiracl);

        mMiracl = mirsys(params.bitCount * 2, 2);


        BA.reset(new EccNumber(*this));
        BB.reset(new EccNumber(*this));
        BA->fromHex(params.a);
        BB->fromHex(params.b);
        BA->mModType = EccNumber::FieldPrime;
        BB->mModType = EccNumber::FieldPrime;

        mOrder.reset(new EccNumber(*this));
        mOrder->fromHex((char*)params.n);
		mIsPrimeOrder = ::isprime(mMiracl, mOrder->mVal);

		if (mIsPrimeOrder) {
			prepare_monty(mMiracl, mOrder->mVal);
		}

        mFieldPrime.reset(new EccNumber(*this));
        mFieldPrime->fromHex((char*)params.p);
        mFieldPrime->mModType = EccNumber::FieldPrime;

        ecurve_init(
            mMiracl,
            BA->mVal,
            BB->mVal,
            mFieldPrime->mVal,
            //MR_AFFINE
            MR_PROJECTIVE
        );

        //mG.reset(new EccPoint(*this));
        //mG->fromHex(mEccpParams.X, mEccpParams.Y);
        std::stringstream ssX(mEccpParams.X);
        std::stringstream ssY(mEccpParams.Y);

        while (true)
        {
            std::string X, Y;
            std::getline(ssX, X, ',');
            std::getline(ssY, Y, ',');

            if (X.size())
            {
                mG.emplace_back(*this);
                mG.back().fromHex((char*)X.c_str(), (char*)Y.c_str());
            }
            else
            {
                break;
            }
        }

    }

    void EllipticCurve::setPrng(const block & seed)
    {
        mPrng.SetSeed(seed);
        irand(mMiracl, (int)mPrng.get<u32>());
    }

    void EllipticCurve::setParameters(const Ecc2mParams & params)
    {


        mIsPrimeField = false;
        mEcc2mParams = params;
        mEccpParams = EccpParams();

        if (mMiracl) mirexit(mMiracl);

        mMiracl = mirsys(params.bitCount * 2, 2);

        mMiracl->IOBASE = 16;

        BA.reset(new EccNumber(*this));
        BB.reset(new EccNumber(*this));

        convert(mMiracl, params.BA, BA->mVal);
        convert(mMiracl, params.BB, BB->mVal);

        mOrder.reset(new EccNumber(*this));
        mOrder->fromHex((char*)(params.order));
		mIsPrimeOrder = ::isprime(mMiracl, mOrder->mVal);

		if (mIsPrimeOrder) {
			prepare_monty(mMiracl, mOrder->mVal);
		}

        ecurve2_init(
            mMiracl,
            params.m,
            params.a,
            params.b,
            params.c,
            BA->mVal,
            BB->mVal,
            false,
            MR_PROJECTIVE);

        //mG.reset(new EccPoint(*this));
        //mG->fromHex(params.X, params.Y);
        std::stringstream ssX(params.X);
        std::stringstream ssY(params.Y);

        while (true)
        {
            std::string X, Y;
            std::getline(ssX, X, ',');
            std::getline(ssY, Y, ',');

            if (X.size())
            {
                mG.emplace_back(*this);
                mG.back().fromHex((char*)X.c_str(), (char*)Y.c_str());
            }
            else
            {
                break;
            }
        }

    }

    miracl & EllipticCurve::getMiracl() const
    {
        return *mMiracl;
    }

    const EllipticCurve::Point & EllipticCurve::getGenerator() const
    {
        return mG[0];
    }

    const std::vector<EccPoint>& EllipticCurve::getGenerators() const
    {
        return mG;
    }

    const EccNumber & EllipticCurve::getOrder() const
    {
        return *mOrder;
    }

    const EccNumber & EllipticCurve::getFieldPrime() const
    {
        return *mFieldPrime;
    }

	u64 EllipticCurve::bitCount() const
	{
		if (mIsPrimeField)
			return mEccpParams.bitCount;
		else
			return mEcc2mParams.bitCount;
	}

    EccPoint::EccPoint(
        EllipticCurve & curve)
        :
        mVal(nullptr),
        mMem(nullptr),
        mCurve(&curve)

    {
        init();
    }

    EccPoint::EccPoint(
        EllipticCurve & curve,
        const EccPoint & copy)
        :
        mVal(nullptr),
        mMem(nullptr),
        mCurve(&curve)
    {
        init();

        *this = copy;
    }

#ifdef DEPRECATED_ECC_POINT_RANDOMIZE
	EccPoint::EccPoint(EllipticCurve & curve, PRNG & prng)
		:
		mVal(nullptr),
		mMem(nullptr),
		mCurve(&curve)
	{
		init();
		randomize(prng);
	}
#endif

    EccPoint::EccPoint(
        const EccPoint & copy)
        :
        mVal(nullptr),
        mMem(nullptr),
        mCurve(copy.mCurve)
    {

        init();

        *this = copy;
    }

    EccPoint::EccPoint(EccPoint && move)
        :
        mVal(move.mVal),
        mMem(move.mMem),
        mCurve(move.mCurve)
    {
        move.mVal = nullptr;
        move.mMem = nullptr;
    }

    EccPoint::~EccPoint()
    {
        if (mMem)
            ecp_memkill(mCurve->mMiracl, mMem, 0);
    }

    EccPoint & EccPoint::operator=(
        const EccPoint & copy)
    {

        if (mCurve->mIsPrimeField)
        {
            epoint_copy((epoint*)copy.mVal, mVal);
        }
        else
        {
            epoint2_copy((epoint*)copy.mVal, mVal);
        }

        return *this;
    }

    EccPoint & EccPoint::operator+=(
        const EccPoint & addIn)
    {
#ifndef NDEBUG
        if (mCurve != addIn.mCurve) throw std::runtime_error("curves instances must match.");
#endif

        if (mCurve->mIsPrimeField)
        {
            ecurve_add(mCurve->mMiracl, (epoint*)addIn.mVal, mVal);
        }
        else
        {
            ecurve2_add(mCurve->mMiracl, (epoint*)addIn.mVal, mVal);
        }
        return *this;
    }

    EccPoint & EccPoint::operator-=(
        const EccPoint & subtractIn)
    {
#ifndef NDEBUG
        if (mCurve != subtractIn.mCurve) throw std::runtime_error("curves instances must match.");
#endif
        if (mCurve->mIsPrimeField)
        {
            ecurve_sub(mCurve->mMiracl, (epoint*)subtractIn.mVal, mVal);
        }
        else
        {
            ecurve2_sub(mCurve->mMiracl, (epoint*)subtractIn.mVal, mVal);
        }
        return *this;
    }

    EccPoint & EccPoint::operator*=(
        const EccNumber & multIn)
    {
#ifndef NDEBUG
        if (mCurve != multIn.mCurve) throw std::runtime_error("curves instances must match.");
#endif
        //multIn.fromNres();


        if (mCurve->mIsPrimeField)
        {
            ecurve_mult(mCurve->mMiracl, multIn.mVal, mVal, mVal);
        }
        else
        {
            ecurve2_mult(mCurve->mMiracl, multIn.mVal, mVal, mVal);
        }

        return *this;
    }

    EccPoint EccPoint::operator+(
        const EccPoint & addIn) const
    {
#ifndef NDEBUG
        if (mCurve != addIn.mCurve) throw std::runtime_error("curves instances must match.");
#endif

        EccPoint temp(*this);

        temp += addIn;

        return temp;
    }

    EccPoint EccPoint::operator-(
        const EccPoint & subtractIn) const
    {
        EccPoint temp(*this);

        temp -= subtractIn;

        return temp;
    }

    EccPoint EccPoint::operator*(
        const EccNumber & multIn) const
    {

        EccPoint temp(*this);

        temp *= multIn;

        return temp;
    }

    bool EccPoint::operator==(
        const EccPoint & cmp) const
    {
#ifndef NDEBUG
        if (mCurve != cmp.mCurve) throw std::runtime_error("curves instances must match.");
#endif
        if (mCurve->mIsPrimeField)
        {
            return epoint_comp(mCurve->mMiracl, mVal, cmp.mVal) != 0;
        }
        else
        {
            return epoint2_comp(mCurve->mMiracl, mVal, cmp.mVal) != 0;
        }
    }
    bool EccPoint::operator!=(
        const EccPoint & cmp) const
    {
        return !(*this == cmp);
    }

    u64 EccPoint::sizeBytes() const
    {
        return (mCurve->bitCount()
            + 7) / 8 + 1;
    }

    void EccPoint::toBytes(u8 * dest) const
    {
        big varX = mirvar(mCurve->mMiracl, 0);

        // convert the point into compressed format where dest[0] holds
        // the y bit and varX holds the x data.
        if (mCurve->mIsPrimeField)
        {
            dest[0] = epoint_get(mCurve->mMiracl, mVal, varX, varX) & 1;
        }
        else
        {
            dest[0] = epoint2_get(mCurve->mMiracl, mVal, varX, varX) & 1;
        }
        // copy the bits of varX into the buffer
        big_to_bytes(mCurve->mMiracl, (int)sizeBytes() - 1, varX, (char*)dest + 1, true);

        mirkill(varX);
    }

    void EccPoint::fromBytes(u8 * src)
    {
        big varX = mirvar(mCurve->mMiracl, 0);

		bool success;
        bytes_to_big(mCurve->mMiracl, (int)sizeBytes() - 1, (char*)src + 1, varX);
        if (mCurve->mIsPrimeField)
        {
			success = epoint_set(mCurve->mMiracl, varX, varX, src[0], mVal);
        }
        else
        {
			success = epoint2_set(mCurve->mMiracl, varX, varX, src[0], mVal);
        }


		if (success == false)
		{
			throw std::runtime_error(LOCATION);
		}
        mirkill(varX);
    }

    void EccPoint::fromHex(char * x, char * y)
    {
        EccNumber XX(*mCurve), YY(*mCurve);
        XX.fromHex(x);
        YY.fromHex(y);

        fromNum(XX, YY);
    }

    void EccPoint::fromDec(char * x, char * y)
    {

        EccNumber XX(*mCurve), YY(*mCurve);
        XX.fromDec(x);
        YY.fromDec(y);
        fromNum(XX, YY);

    }

    void EccPoint::fromNum(EccNumber & XX, EccNumber & YY)
    {

        if (mCurve->mIsPrimeField)
        {
            auto result = epoint_set(mCurve->mMiracl, XX.mVal, YY.mVal, 0, mVal);

            //std::cout << "plain " << XX << " " << YY << std::endl;
            //std::cout << "point " << *this << std::endl;
            if (result == false)
            {
                std::cout << "bad point" << std::endl;
                throw std::runtime_error(LOCATION);
            }
        }
        else
        {
            auto result = epoint2_set(mCurve->mMiracl, XX.mVal, YY.mVal, 0, mVal);

            if (result == false)
            {
                std::cout << "bad point" << std::endl;
                throw std::runtime_error(LOCATION);
            }
        }
    }


#ifdef    DEPRECATED_ECC_POINT_RANDOMIZE
    // chi calculates out = z^((p-1)/2). The result is either 1, 0, or -1 depending
    // on whether z is a non-zero square, zero, or a non-square.
    // See https://github.com/agl/ed25519/blob/master/extra25519/extra25519.go#L254
    EccNumber EccNumber::chi() const
    {
        if (mCurve->mEccpParams.a != Curve25519.a)
            throw std::runtime_error("chi only implememented for curve 25519");

        auto& z = *this;

        auto t0 = z * z;
        auto t1 = t0 * z;
        t0 = t1 * t1;
        auto t2 = t0 * t0;
        t2 *= t2;
        t2 *= t0;
        t1 = t2 * z;
        t2 = t1 * t1;
        for (auto i = 1; i < 5; ++i)
            t2 *= t2;
        t1 *= t2;
        t2 = t1 * t1;
        for (auto i = 1; i < 10; ++i)
            t2 *= t2;
        t2 *= t1;
        auto t3 = t2 * t2;
        for (auto i = 1; i < 20; ++i)
            t3 *= t3;

        t2 *= t3;
        t2 *= t2;
        for (auto i = 1; i < 10; ++i)
            t2 *= t2;

        t1 *= t2;
        t2 = t1 * t1;
        for (auto i = 1; i < 50; ++i)
            t2 *= t2;

        t2 *= t1;
        t3 = t2 * t2;
        for (auto i = 1; i < 100; ++i)
            t3 *= t3;

        t2 *= t3;
        t2 *= t2;
        for (auto i = 1; i < 50; ++i)
            t2 *= t2;

        t1 *= t2;
        t1 *= t1;
        for (auto i = 1; i < 4; ++i)
            t1 *= t1;

        auto ret = t1 * t0;


        auto check = ret == -1 || ret == 0 || ret == 1;

        if (!check)
        {
            std::cout << "bad chi " << ret << std::endl;
            //throw std::runtime_error(LOCATION);
        }

        return ret;

    }


    // implements elligator 2
    // See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-01#section-5.2.4
    // See http://elligator.cr.yp.to/elligator-20130828.pdf
    // See https://www.imperialviolet.org/2013/12/25/elligator.html
    void EccPoint::randomize(PRNG& prng)
    {
        if (mCurve->mEccpParams.a != Curve25519.a)
            throw std::runtime_error("Elligator only implememented for curve 25519");


        // 1.   r = HashToBase(alpha)
        EccNumber r(*mCurve, prng, EccNumber::FieldPrime); 

        auto u = 2;
        auto& A = *mCurve->BA;
        auto& B = *mCurve->BB;

        // 2.   r = r^2 (mod p)
        // r^2
        r *= r;
        // 3.  r = r * u (mod p)
        // ur^2
        r *= u;
        // 5.   r = r + 1 (mod p)
        // 1 + ur^2
        r = 1 + r;
        // 6.   r = r ^ (-1) (mod p)
        // 1 / (1 + ur^2)
        r = r.inverse();

        // 7.   v = A * r (mod p)
        // 8.   v = v * -1 (mod p)   // -A / (1 + ur^2)
        // v = -A * / (1 + ur^2)
        auto v = (A * r).negate();


        // 9.  v2 = v^2 (mod p)
        auto v2 = v * v;

        // 10. v3 = v * v2 (mod p)
        auto v3 = v2 * v;

        // 11.  e = v3 * v (mod p)
        auto e = v3 * v;

        // 12. v2 = v2 * A(mod p)
        // v2 = v^2 * A
        v2 = v2 * A;

        // 13.  e = v2 * e (mod p)
        e = v2 * e;
        auto ee = e;

        // e = e^((p - 1) / 2)
        // 14.  e = e^((p - 1) / 2)  // Legendre symbol
        auto power = ((*mCurve->mFieldPrime - 1) / 2);
        powmod(mCurve->mMiracl, ee.mVal, power.mVal, mCurve->mFieldPrime->mVal, e.mVal);

        // 15. nv = v * -1 (mod p)
        auto nv = v.negate();

        //std::cout << "neg " << std::endl;
        auto neg = e == -1;
        //std::cout << "pos " << std::endl;
        auto pos = e == 1;

        if ( !neg && !pos)
        {

            std::cout << e << "\n = "<<ee<<"  \n / " << mCurve->getFieldPrime() << std::endl;

            std::cout <<"      "<< mCurve->getFieldPrime() - 1 << std::endl;
            std::cout << "bad e " << e<< std::endl;
            std::cout << "c " << !neg << " " << !pos << std::endl;
            std::cout << "-1 " << EccNumber(*mCurve, -1, EccNumber::FieldPrime) << std::endl;
            ee.chi();


            if (ee + ee.negate() != 0)
            {
                std::cout << "bad negate" << std::endl;
            }
        }


        // 16.  v = CMOV(v, nv, e)   // If e = 1, choose v, else choose nv
        // 17. v2 = CMOV(0, A, e)    // If e = 1, choose 0, else choose A
        if (pos)
        {
            v = v;
            v2 = 0;
        }
        else
        {
            v = nv;
            v2 = A;
        }

        // 18.  u = v - v2(mod p)
        v -= v2;

        //e = v2 + e;
        //e = e.chi();

        //auto eIsMinus1 = e == -1;
        //auto negV = -v;

        //v = eIsMinus1 ? v : negV;
        //v2 = 0;
        //v2 = eIsMinus1 ? v2 : A;
        //v -= v2;

        if (v.mModType != EccNumber::FieldPrime)
            throw std::runtime_error(LOCATION);

        //auto f = [&](auto x) {return };
        auto y = v * (v * v + A * v + B);

        // v2 = sqrt(y)
        sqroot(mCurve->mMiracl,
            y.mVal, 
            mCurve->getFieldPrime().mVal,
            v2.mVal);

        fromNum(v, v2);
        
        //// given the x coordinate (v), use point decompression
        //// to solve for y. First we serialize v and then read it
        //// into the point. Note that dest[0] = 0 denotes that y 
        //// should be positive.
        //std::vector<u8> dest(sizeBytes());
        //dest[0] = 0;
        //v.toBytes(dest.data() + 1);
        //fromBytes(dest.data());



        if(false)
		{
			// if that failed, just get a random point
			// by computing g^r    where r <- Z_p
			EccNumber num(*mCurve, prng);

			*this = mCurve->getGenerator() * num;
		}
    }

    void EccPoint::randomize(const block & seed)
    {
        PRNG prng(seed);
        randomize(prng);
    }
#endif


    void EccPoint::randomize()
    {
        PRNG prng(sysRandomSeed());
        EccNumber num(*mCurve, prng);
        *this = mCurve->getGenerator() * num;
    }

    void EccPoint::setCurve(EllipticCurve & curve)
    {
        mCurve = &curve;
    }

    void EccPoint::init()
    {
        mMem = (char *)ecp_memalloc(mCurve->mMiracl, 1);
        mVal = (epoint *)epoint_init_mem(mCurve->mMiracl, mMem, 0);
    }

    EccNumber::EccNumber(const EccNumber & num)
        :mVal(nullptr)
        , mCurve(num.mCurve)
        , mModType(num.mModType)
    {
        init();

        *this = num;
    }

    EccNumber::EccNumber(EccNumber && num)
        : mVal(num.mVal)
        , mCurve(num.mCurve)
        , mModType(num.mModType)
    {
        num.mVal = nullptr;
    }

    EccNumber::EccNumber(
        EllipticCurve & curve)
        :
        mVal(nullptr),
        mCurve(&curve)
    {
        init();
    }

    EccNumber::EccNumber(
        EllipticCurve & curve,
        const EccNumber& copy)
        :
        mVal(nullptr),
        mCurve(&curve),
        mModType(copy.mModType)
    {
        init();
        *this = copy;
    }

    EccNumber::EccNumber(EllipticCurve & curve, PRNG & prng, Modulus type)
        :
        mVal(nullptr),
        mCurve(&curve),
        mModType(type)
    {
        init();
        randomize(prng);
    }

    EccNumber::EccNumber(
        EllipticCurve & curve,
        const i32 & val,
        Modulus type)
        :
        mVal(nullptr),
        mCurve(&curve),
        mModType(type)
    {
        init();
        *this = val;
    }

    EccNumber::~EccNumber()
    {
        if (mVal)
            mirkill(mVal);
    }

    EccNumber& EccNumber::operator=(const EccNumber& c)
    {
        copy(c.mVal, mVal);
        mModType = c.mModType;
        return *this;
    }

    EccNumber& EccNumber::operator=(big c)
    {
        copy(c, mVal);
        return *this;
    }

    EccNumber& EccNumber::operator=(int i)
    {
        if (i == 0)
            zero(mVal);
        else
        {
            convert(mCurve->mMiracl, i, mVal);
            reduce();
            //nres(mCurve->mMiracl, mVal, mVal);
        }
        return *this;
    }
    EccNumber& EccNumber::operator++()
    {
        incr(mCurve->mMiracl, mVal, 1, mVal);
        reduce();

        //toNres();
        //nres_modadd(mCurve->mMiracl, mVal, mCurve->mMiracl->one, mVal);
        return *this;
    }
    EccNumber& EccNumber::operator--()
    {
        decr(mCurve->mMiracl, mVal, 1, mVal);
        reduce();

        //toNres();
        //nres_modsub(mCurve->mMiracl, mVal, mCurve->mMiracl->one, mVal);
        return *this;
    }

    EccNumber& EccNumber::operator+=(int i)
    {
        EccNumber inc(*mCurve, i, mModType);

        add(mCurve->mMiracl, mVal, inc.mVal, mVal);
        reduce();

        //toNres();
        //inc.toNres();
        //nres_modadd(mCurve->mMiracl, mVal, inc.mVal, mVal);

        return *this;
    }
    EccNumber& EccNumber::operator-=(int i)
    {
        EccNumber dec(*mCurve, i, mModType);
        subtract(mCurve->mMiracl, mVal, dec.mVal, mVal);
        reduce();

        //toNres();
        //dec.toNres();
        //nres_modsub(mCurve->mMiracl, mVal, dec.mVal, mVal);

        return *this;
    }
    EccNumber& EccNumber::operator+=(const EccNumber& b)
    {
        add(mCurve->mMiracl, mVal, b.mVal, mVal);

        reduce();

        //toNres();
        //b.toNres();
        //nres_modadd(mCurve->mMiracl, mVal, b.mVal, mVal);

        return *this;
    }
    EccNumber& EccNumber::operator-=(const EccNumber& b)
    {
        subtract(mCurve->mMiracl, mVal, b.mVal, mVal);
        reduce();
        //toNres();
        //b.toNres();
        //nres_modsub(mCurve->mMiracl, mVal, b.mVal, mVal);
        return *this;
    }
    EccNumber& EccNumber::operator*=(const EccNumber& b)
    {
        multiply(mCurve->mMiracl, mVal, b.mVal, mVal);
        reduce();

        //toNres();
        //b.toNres();
        //nres_modmult(mCurve->mMiracl, mVal, b.mVal, mVal);
        return *this;
    }
    EccNumber& EccNumber::operator*=(int i)
    {
        premult(mCurve->mMiracl, mVal, i, mVal);
        reduce();

        //toNres();
        //nres_premult(mCurve->mMiracl, mVal, i, mVal);
        return *this;
    }
    EccNumber& EccNumber::operator/=(const EccNumber& b)
    {
		*this *= b.inverse();
        return *this;
    }
    EccNumber& EccNumber::operator/=(int i)
    {
        EccNumber div(*mCurve, i, mModType);

        *this /= div;

        //toNres();
        //div.toNres();
        //nres_moddiv(mCurve->mMiracl, mVal, div.mVal, mVal);

        return *this;
    }
    const EccNumber& EccNumber::modulus() const
    {
        if (mModType == CurveOrder)
            return *mCurve->mOrder;
        else
            return *mCurve->mFieldPrime;
    }


    void EccNumber::inplaceNegate()
    {
        auto& mod = modulus();
        if (iszero() == false)
            *this = mod - *this;
    }



    EccNumber EccNumber::negate() const
    {
        auto r = *this;
        r.inplaceNegate();
        return r;
        //auto t = *this;

        //auto& mod = modulus();
        //if (iszero() == false)
        //    t = mod - *this;

        //std::cout << "neg mid: " << mod << " - " << t << " = " << *this << std::endl;
        //
        //return t;
    }


	EccNumber EccNumber::inverse() const
	{
		EccNumber ret(*this);

        big mod;

        if (mModType == CurveOrder)
        {
		    if (mCurve->mIsPrimeOrder == false)
			    throw std::runtime_error("Only implemented when the group order is prime. " LOCATION);
        
            mod = mCurve->mOrder->mVal;
        }
        else
        {
            if (mCurve->mFieldPrime == nullptr)
                throw std::runtime_error("Only implentmented for prime fields. " LOCATION);
            mod = mCurve->mFieldPrime->mVal;
        }

        // ret = ret ^ -1 % mod 
		xgcd(mCurve->mMiracl, ret.mVal, mod, ret.mVal, ret.mVal, ret.mVal);

		return ret;
	}


    bool EccNumber::operator==(const EccNumber & cmp) const
    {
        //fromNres();
        //cmp.fromNres();
        auto x = mr_compare(mVal, cmp.mVal);
        //std::cout << " op== " << *this << " " << cmp << " -> " << x << std::endl;

        return (x == 0);
    }

    bool EccNumber::operator==(const int & cmp)const
    {
        return cmp == *this;
    }

    bool EccNumber::operator!=(const EccNumber & cmp)const
    {
        return !(*this == cmp);
    }

    bool EccNumber::operator!=(const int & cmp)const
    {
        return !(*this == cmp);
    }

    bool EccNumber::operator>=(const EccNumber & cmp)const
    {
        //fromNres();
        //cmp.fromNres();
        return (mr_compare(mVal, cmp.mVal) >= 0);
    }

    bool EccNumber::operator>=(const int & cmp)const
    {
        EccNumber c(*mCurve, cmp, mModType);
        return (*this >= c);
    }

    bool EccNumber::operator<=(const EccNumber & cmp)const
    {
        //fromNres();
        //cmp.fromNres();
        return (mr_compare(mVal, cmp.mVal) <= 0);
    }

    bool EccNumber::operator<=(const int & cmp)const
    {
        EccNumber c(*mCurve, cmp, mModType);
        return (*this <= c);
    }

    bool EccNumber::operator>(const EccNumber & cmp)const
    {
        return !(cmp >= *this);
    }

    bool EccNumber::operator>(const int & cmp)const
    {
        EccNumber c(*mCurve, cmp, mModType);
        return !(c >= *this);
    }

    bool EccNumber::operator<(const EccNumber & cmp)const
    {
        return !(cmp <= *this);
    }

    bool EccNumber::operator<(const int & cmp)const
    {
        EccNumber c(*mCurve, cmp, mModType);
        return !(c <= *this);
    }

    BOOL EccNumber::iszero() const
    {
        if (size(mVal) == 0) return TRUE;
        return FALSE;
    }

    bool operator==(const int & cmp1, const EccNumber & cmp2)
    {
        EccNumber cmp(*cmp2.mCurve, cmp1, cmp2.mModType);

        return (cmp == cmp2);
    }

    EccNumber operator-(const EccNumber& b)
    {
        EccNumber x = b;
        x.inplaceNegate();
        return x;
    }

    EccNumber operator+(const EccNumber& b, int i)
    {
        EccNumber abi = b;
        abi += i;
        return abi;
    }
    EccNumber operator+(int i, const EccNumber& b)
    {
        EccNumber aib = b;
        aib += i;
        return aib;
    }
    EccNumber operator+(const EccNumber& b1, const EccNumber& b2)
    {
        EccNumber abb = b1;
        abb += b2;
        return abb;
    }

    EccNumber operator-(const EccNumber& b, int i)
    {
        EccNumber mbi = b;
        mbi -= i;
        return mbi;
    }
    EccNumber operator-(int i, const EccNumber& b)
    {
        EccNumber mib(*b.mCurve, i, b.mModType);
        mib -= b;
        return mib;
    }
    EccNumber operator-(const EccNumber& b1, const EccNumber& b2)
    {
        EccNumber mbb = b1;
        mbb -= b2;
        return mbb;
    }

    EccNumber operator*(const EccNumber& b, int i)
    {
        EccNumber xbb = b;
        xbb *= i;
        return xbb;
    }
    EccNumber operator*(int i, const EccNumber& b)
    {
        EccNumber xbb = b;
        xbb *= i;
        return xbb;
    }
    EccNumber operator*(const EccNumber& b1, const EccNumber& b2)
    {
        EccNumber xbb = b1;
        xbb *= b2;
        return xbb;
    }

    EccNumber operator/(const EccNumber& b1, int i)
    {
        EccNumber z = b1;
        z /= i;
        return z;
    }

    EccNumber operator/(int i, const EccNumber& b2)
    {
        EccNumber z(*b2.mCurve, i, b2.mModType);
        z /= b2;
        return z;
    }
    EccNumber operator/(const EccNumber& b1, const EccNumber& b2)
    {
        EccNumber z = b1;
        z /= b2;
        return z;
    }

    u64 EccNumber::sizeBytes() const
    {
        return (mCurve->bitCount() + 7) / 8;
    }

    void EccNumber::toBytes(u8 * dest) const
    {
        //fromNres();
        big_to_bytes(mCurve->mMiracl, (int)sizeBytes(), mVal, (char*)dest, true);

        //dest[0] = exsign(mVal);
        //if (b)
        //{
        //    std::cout << *this << std::endl;
        //    std::cout << u32(dest[0]) << std::endl;
        //}
    }

    void EccNumber::fromBytes(const u8 * src)
    {
        bytes_to_big(mCurve->mMiracl, (int)sizeBytes(), (char*)src, mVal);
        //mIsNres = NresState::nonNres;
        //if (b)
        //std::cout << *this << std::endl;

        //insign(char(src[0]), mVal);

        //if (b)
        //{
        //    std::cout << *this << std::endl;
        //    std::cout << u32(src[0]) << std::endl;
        //}
    }

    void EccNumber::fromHex(const char * src)
    {
        auto oldBase = mCurve->mMiracl->IOBASE;
        mCurve->mMiracl->IOBASE = 16;

        cinstr(mCurve->mMiracl, mVal, (char*)src);
        //mIsNres = NresState::nonNres;

        mCurve->mMiracl->IOBASE = oldBase;
    }

    void EccNumber::fromDec(const char * src)
    {
        auto oldBase = mCurve->mMiracl->IOBASE;
        mCurve->mMiracl->IOBASE = 10;

        cinstr(mCurve->mMiracl, mVal,(char*) src);
        //mIsNres = NresState::nonNres;

        mCurve->mMiracl->IOBASE = oldBase;
    }

    void EccNumber::randomize(PRNG & prng)
    {

        int m;
        mr_small r;

        auto w = mCurve->getOrder().mVal;
        auto mr_mip = mCurve->mMiracl;

        m = 0;
        zero(mVal);

        do
        { /* create big rand piece by piece */
            m++;
            mVal->len = m;
            r = prng.get<u64>();

            if (mCurve->mMiracl->base == 0)
            {
                mVal->w[m - 1] = r;
            }
            else
            {
                mVal->w[m - 1] = MR_REMAIN(r, mCurve->mMiracl->base);
            }

        } while (mr_compare(mVal, w) < 0);

        mr_lzero(mVal);
        divide(_MIPP_ mVal, w, w);

        while (mr_compare(mVal, mCurve->getOrder().mVal) > 0)
        {
            std::cout << "bad rand" << std::endl;
            throw std::runtime_error("");
        }

    }

    void EccNumber::randomize(const block & seed)
    {
        PRNG prng(seed);
        randomize(prng);
    }

    void EccNumber::init()
    {
        mVal = mirvar(mCurve->mMiracl, 0);

    }

    void EccNumber::reduce()
    {

        auto& mod = modulus();

        if (exsign(mVal) == -1)
        {
            //std::cout << "neg                  " << *this << std::endl;


            add(mCurve->mMiracl, mVal, mod.mVal, mVal);
            //*this += mCurve->getOrder();

            if (exsign(mVal) == -1)
            {
                std::cout << "neg reduce error " << *this << std::endl;
                std::cout << "                  " << mod << std::endl;
                throw std::runtime_error(LOCATION);
            }
        }

        if (*this >= mod)
        {
            // only computes the remainder. since the params are
            //
            //    divide(mVal, mod, mod)
            //
            // mVal holds  the remainder

            divide(mCurve->mMiracl,
                mVal,
                mod.mVal,
                mod.mVal);
        }

        //if (exsign(mVal) == -1)
        //{
        //    *this += mCurve->getModulus();
        //}
        //else if (*this >= mCurve->getModulus())
        //{
        //    *this -= mCurve->getModulus();
        //}


        //if (exsign(mVal) == -1 || *this >= mCurve->getModulus())
        //{
        //    std::cout << "EccNumber mod error" << std::endl;
        //    throw std::runtime_error("");
        //}
    }

    EccBrick::EccBrick(const EccPoint & copy)
        :mCurve(copy.mCurve)
    {
        bool result = 0;
        //big x, y;
        if (mCurve->mIsPrimeField)
        {

            big x = mirvar(copy.mCurve->mMiracl, 0);
            big y = mirvar(copy.mCurve->mMiracl, 0);

            redc(copy.mCurve->mMiracl, copy.mVal->X, x);
            redc(copy.mCurve->mMiracl, copy.mVal->Y, y);



            result = 0 < ebrick_init(
                mCurve->mMiracl,
                &mBrick,
                x, y,
                mCurve->BA->mVal, mCurve->BB->mVal,
                mCurve->getFieldPrime().mVal,
                8, mCurve->mEccpParams.bitCount);

            mirkill(x);
            mirkill(y);
        }
        else
        {

            result = 0 < ebrick2_init(
                mCurve->mMiracl,
                &mBrick2,
                copy.mVal->X,
                copy.mVal->Y,
                mCurve->BA->mVal,
                mCurve->BB->mVal,
                mCurve->mEcc2mParams.m,
                mCurve->mEcc2mParams.a,
                mCurve->mEcc2mParams.b,
                mCurve->mEcc2mParams.c,
                8,
                mCurve->mEcc2mParams.bitCount);
        }

        if (result == 0)
        {
            throw std::runtime_error(LOCATION);
        }
    }

    EccBrick::EccBrick(EccBrick && copy)
        :
        mBrick2(copy.mBrick2),
        mCurve(copy.mCurve)
    {

    }

    EccPoint EccBrick::operator*(const EccNumber & multIn) const
    {

        EccPoint ret(*mCurve);

        multiply(multIn, ret);

        return ret;
    }

    void EccBrick::multiply(const EccNumber & multIn, EccPoint & result) const
    {
#ifndef NDEBUG
        if (mCurve != multIn.mCurve) throw std::runtime_error("curves instances must match.");
        if (mCurve != result.mCurve) throw std::runtime_error("curves instances must match.");
#endif

        //multIn.fromNres();
        big x, y;

        x = mirvar(mCurve->mMiracl, 0);
        y = mirvar(mCurve->mMiracl, 0);


        if (mCurve->mIsPrimeField)
        {
            mul_brick(mCurve->mMiracl, (ebrick*)&mBrick, multIn.mVal, x, y);
            epoint_set(mCurve->mMiracl, x, y, 0, result.mVal);
            //throw std::runtime_error(LOCATION);
        }
        else
        {
            //throw std::runtime_error(LOCATION);
            mul2_brick(mCurve->mMiracl, (ebrick2*)&mBrick2, multIn.mVal, x, y);
            epoint2_set(mCurve->mMiracl, x, y, 0, result.mVal);
        }

        mirkill(x);
        mirkill(y);
    }

    std::ostream & operator<<(std::ostream & out, const EccNumber & val)
    {
        //val.fromNres();

        cotstr(val.mCurve->mMiracl, val.mVal, val.mCurve->mMiracl->IOBUFF);
        out << val.mCurve->mMiracl->IOBUFF;

        return out;
    }

    std::ostream & operator<<(std::ostream & out, const EccPoint & val)
    {

        if (val.mVal->marker == MR_EPOINT_INFINITY)
        {
            out << "(Infinity)";
        }
        else
        {

            if (val.mCurve->mIsPrimeField)
            {
                epoint_norm(val.mCurve->mMiracl, val.mVal);
                big x = mirvar(val.mCurve->mMiracl, 0);
                big y = mirvar(val.mCurve->mMiracl, 0);

                redc(val.mCurve->mMiracl, val.mVal->X, x);
                redc(val.mCurve->mMiracl, val.mVal->Y, y);

                cotstr(val.mCurve->mMiracl, x, val.mCurve->mMiracl->IOBUFF);
                out << val.mCurve->mMiracl->IOBUFF << " ";
                cotstr(val.mCurve->mMiracl, y, val.mCurve->mMiracl->IOBUFF);
                out << val.mCurve->mMiracl->IOBUFF;

                mirkill(x);
                mirkill(y);

            }
            else
            {
                epoint2_norm(val.mCurve->mMiracl, val.mVal);

                cotstr(val.mCurve->mMiracl, val.mVal->X, val.mCurve->mMiracl->IOBUFF);
                out << val.mCurve->mMiracl->IOBUFF << " ";
                cotstr(val.mCurve->mMiracl, val.mVal->Y, val.mCurve->mMiracl->IOBUFF);
                out << val.mCurve->mMiracl->IOBUFF;

            }

        }

        return out;
    }

}
#endif