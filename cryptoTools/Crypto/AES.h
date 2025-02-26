#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Aligned.h>
#include <type_traits>
#include <cassert>
#include <utility>

#ifdef ARM
#undef ARM
#endif

namespace osuCrypto {

	namespace details
	{
		enum AESTypes
		{
			NI,
			Portable,
			ARM
		};

		// templated implementation of AES 128. Each type has a different
		// implmentation of the round function which maps to native hardware 
		// for x86 AES NI and ARM64 platforms.
		template<AESTypes type>
		class AES
		{
		public:
			static const u64 rounds = 10;

			// Default constructor leave the class in an invalid state
			// until setKey(...) is called.
			AES() = default;
			AES(const AES&) = default;

			// Constructor to initialize the class with the given key
			AES(const block& userKey) { setKey(userKey); }

			// Set the key to be used for encryption.
			void setKey(const block& userKey);

			block getKey() const { return mRoundKey[0]; }


			///////////////////////////////////////////////
			// ECB ENCRYPTION

			// for i = 0,...,blocks-1, set ciphertext[i] = AES.Enc(plaintext[i]).
			// Encryption is performed in ECB mode.
			template<u64 blocks>
			OC_FORCEINLINE void ecbEncBlocks(const block* plaintext, block* ciphertext) const;

			// set ciphertext = AES.Enc(plaintext). Encryption is performed in ECB mode.
			inline void ecbEncBlock(const block& plaintext, block& ciphertext) const;

			// return AES.Enc(plaintext). Encryption is performed in ECB mode.
			inline block ecbEncBlock(const block& plaintext) const;

			// for i = 0,...,blocks-1, set ciphertext[i] = AES.Enc(plaintext[i]).
			// Encryption is performed in ECB mode.
			inline void ecbEncBlocks(const block* plaintext, u64 blocks, block* ciphertext) const;

			// for i = 0,...,plaintext.size()-1, set ciphertext[i] = AES.Enc(plaintext[i]).
			// Encryption is performed in ECB mode.
			inline void ecbEncBlocks(span<const block> plaintext, span<block> ciphertext) const;


			///////////////////////////////////////////////
			// Counter mode stream

			// for i = 0,...,blocks-1, set ciphertext[i] = AES.Enc(baseIdx + i).
			// Encryption is performed in ECB mode.
			void ecbEncCounterMode(u64 baseIdx, u64 blocks, block* ciphertext) const;

			// for i = 0,...,blocks-1, set ciphertext[i] = AES.Enc(baseIdx + i).
			// Encryption is performed in ECB mode.
			void ecbEncCounterMode(block baseIdx, u64 blocks, block* ciphertext) const;

			// for i = 0,...,ciphertext.size()-1, set ciphertext[i] = AES.Enc(baseIdx + i).
			// Encryption is performed in ECB mode.
			void ecbEncCounterMode(u64 baseIdx, span<block> ciphertext) const;

			// for i = 0,...,ciphertext.size()-1, set ciphertext[i] = AES.Enc(baseIdx + i).
			// Encryption is performed in ECB mode.
			void ecbEncCounterMode(block baseIdx, span<block> ciphertext) const;


			///////////////////////////////////////////////
			// Tweakable correlation robust hash function.
			// https://eprint.iacr.org/2019/074.pdf section 7.4

			// Tweakable correlation robust hash function.
			// y_i = AES(AES(x_i) ^ tweak_i) + AES(x_i).
			template<u64 blocks, typename TweakFn>
			OC_FORCEINLINE void TmmoHashBlocks(const block* plaintext, block* ciphertext, TweakFn&& tweakFn) const;

			// Tweakable correlation robust hash function.
			// TMMO(x, i) = AES(AES(x) + i) + AES(x).
			block TmmoHashBlock(block plaintext, block baseTweak) const;

			// Tweakable correlation robust hash function.
			// y_i = AES(AES(x_i) ^ tweak_i) + AES(x_i).
			template<typename TweakFn>
			inline void TmmoHashBlocks(span<const block> plaintext, span<block> ciphertext, TweakFn&& tweak) const;

			// Tweakable correlation robust hash function.
			// y_i = AES(AES(x_i) ^ tweak_i) + AES(x_i).
			template<typename TweakFn>
			inline void TmmoHashBlocks(const block* plaintext, u64 blockLength, block* ciphertext, TweakFn&& tweak) const;


			///////////////////////////////////////////////
			// Correlation robust hash function.


			// Correlation robust hash function.
			// H(x) = AES(x) + x.
			template<u64 blocks>
			OC_FORCEINLINE void hashBlocks(const block* plaintext, block* ciphertext) const;

			// Correlation robust hash function.
			// H(x) = AES(x) + x.
			inline void hashBlocks(span<const block> plaintext, span<block> ciphertext) const;

			// Correlation robust hash function.
			// H(x) = AES(x) + x.
			inline block hashBlock(const block& plaintext) const;

			// Correlation robust hash function.
			// H(x) = AES(x) + x.
			inline void hashBlocks(const block* plaintext, u64 blockLength, block* ciphertext) const;

			// The expanded key.
			std::array<block, rounds + 1> mRoundKey;

			////////////////////////////////////////
			// Low level

            // AES is implemented as:
            // state = key[0] ^ input
            // state = (^key[1]  o mixCol o shiftRow o sbox)(state) 
            // state = (^key[2]  o mixCol o shiftRow o sbox)(state) 
            // ...
            // state = (^key[9]  o mixCol o shiftRow o sbox)(state) 
            // state = (^key[10] o          shiftRow o sbox)(state) 


			// applies the round function and then XORs with the round key.
            // output = (mixCol o shiftRow o sbox)(input) ^ roundKey.
			static block roundEnc(block state, const block& roundKey);

			// combine the state with the first round key. 
			// For portable and NI: ^roundKey(state).
			// For ARM: (mixCol o shiftRow o sbox o ^roundKey)(state) 
			static block firstFn(block state, const block& roundKey);

			// combine the state with a middle round key. 
			// For portable and NI: (^roundKey o mixCol o shiftRow o sbox)(state) 
			// For ARM: (mixCol o shiftRow o sbox o ^roundKey)(state) 
			static block roundFn(block state, const block& roundKey);

			// combine the state with the last round key. 
			// For portable and NI: (^roundKey o mixCol o shiftRow o sbox)(state) 
			// For ARM: (shiftRow o sbox o ^roundKey)(state) 
			static block penultimateFn(block state, const block& roundKey);

			// combine the state with the last round key. 
			// For portable and NI: (^roundKey o sbox o shiftRows)(state) 
			// For ARM: ^roundKey(state).
			static block finalFn(block state, const block& roundKey);

		private:

			static bool isOverlapping(const block* ptr1, std::size_t size1, const block* ptr2, std::size_t size2) {
				auto end1 = ptr1 + size1;
				auto end2 = ptr2 + size2;
				return (ptr1 < end2) && (ptr2 < end1);
			}

			template<u64 blocks, typename TweakFn>
			static OC_FORCEINLINE void generateTweaks(TweakFn&& tweakFn, block* tweaks)
			{
				tweaks[0] = tweakFn();
				if constexpr (blocks > 1)
					generateTweaks<blocks - 1>(std::forward<TweakFn>(tweakFn), tweaks + 1);
			}

			template<u64 blocks>
			static OC_FORCEINLINE void xorBlocks(const block* __restrict x, block* __restrict y)
			{
				assert(isOverlapping(x, blocks, y, blocks) == false);

				y[0] = x[0] ^ y[0];
				if constexpr (blocks > 1)
					xorBlocks<blocks - 1>(x + 1, y + 1);
			}

		};


		template<AESTypes type>
		template<u64 blocks>
		OC_FORCEINLINE void AES<type>::ecbEncBlocks(const block* plaintext, block* ciphertext) const
		{
			assert((u64)plaintext % 16 == 0 && "plaintext must be aligned.");
			assert((u64)ciphertext % 16 == 0 && "ciphertext must be aligned.");

			if constexpr (blocks <= 16)
			{
				oc::AlignedArray<block, blocks> buffer;
				for (u64 j = 0; j < blocks; ++j)
					buffer[j] = firstFn(plaintext[j], mRoundKey[0]);

				for (u64 i = 1; i < rounds - 1; ++i)
				{
					for (u64 j = 0; j < blocks; ++j)
						buffer[j] = roundFn(buffer[j], mRoundKey[i]);
				}

				for (u64 j = 0; j < blocks; ++j)
					buffer[j] = penultimateFn(buffer[j], mRoundKey[rounds - 1]);

				for (u64 j = 0; j < blocks; ++j)
					ciphertext[j] = finalFn(buffer[j], mRoundKey[rounds]);
			}
			else
			{
				ecbEncBlocks(plaintext, blocks, ciphertext);
			}
		}


		// Encrypts the plaintext block and stores the result in ciphertext
		template<AESTypes type>
		inline void AES<type>::ecbEncBlock(const block& plaintext, block& ciphertext) const
		{
			ecbEncBlocks<1>(&plaintext, &ciphertext);
		}

		// Encrypts the plaintext block and returns the result
		template<AESTypes type>
		inline block AES<type>::ecbEncBlock(const block& plaintext) const
		{
			block ciphertext;
			ecbEncBlock(plaintext, ciphertext);
			return ciphertext;
		}

		// Encrypts blockLength starting at the plaintext pointer and writes the result
		// to the ciphertext pointer
		template<AESTypes type>
		inline void AES<type>::ecbEncBlocks(const block* plaintext, u64 blockLength, block* ciphertext) const
		{
			assert(
				plaintext == ciphertext || 
				isOverlapping(plaintext, blockLength, ciphertext, blockLength) == false);

			const u64 step = 8;
			u64 idx = 0;

			for (; idx + step <= blockLength; idx += step)
			{
				ecbEncBlocks<step>(plaintext + idx, ciphertext + idx);
			}

			i32 misalignment = blockLength % step;
			switch (misalignment) {
#define SWITCH_CASE(n) \
		    case n: \
		        ecbEncBlocks<n>(plaintext + idx, ciphertext + idx); \
		        break
				SWITCH_CASE(1);
				SWITCH_CASE(2);
				SWITCH_CASE(3);
				SWITCH_CASE(4);
				SWITCH_CASE(5);
				SWITCH_CASE(6);
				SWITCH_CASE(7);
#undef SWITCH_CASE
			}
		}

		template<AESTypes type>
		inline void AES<type>::ecbEncBlocks(span<const block> plaintext, span<block> ciphertext) const
		{
			if (plaintext.size() != ciphertext.size())
				throw RTE_LOC;
			ecbEncBlocks(plaintext.data(), plaintext.size(), ciphertext.data());
		}


		///////////////////////////////////////////////
		// Counter mode stream

		// Encrypts the vector of blocks {baseIdx, baseIdx + 1, ..., baseIdx + blockLength - 1}
		// and writes the result to ciphertext.
		template<AESTypes type>
		void AES<type>::ecbEncCounterMode(u64 baseIdx, u64 blockLength, block* ciphertext) const
		{
			ecbEncCounterMode(toBlock(baseIdx), blockLength, ciphertext);
		}
		template<AESTypes type>
		void AES<type>::ecbEncCounterMode(u64 baseIdx, span<block> ciphertext) const
		{
			ecbEncCounterMode(toBlock(baseIdx), ciphertext.size(), ciphertext.data());
		}
		template<AESTypes type>
		void AES<type>::ecbEncCounterMode(block baseIdx, span<block> ciphertext) const
		{
			ecbEncCounterMode(baseIdx, ciphertext.size(), ciphertext.data());
		}

		template<AESTypes type>
		inline void AES<type>::ecbEncCounterMode(block baseIdx, u64 blockLength, block* ciphertext) const
		{

			constexpr u64 step = 8;
			u64 idx = 0;
			oc::AlignedArray<block, step> plaintext;

			for (; idx + step <= blockLength; idx += step)
			{
				plaintext[0] = baseIdx.add_epi64(block(idx + 0));
				plaintext[1] = baseIdx.add_epi64(block(idx + 1));
				plaintext[2] = baseIdx.add_epi64(block(idx + 2));
				plaintext[3] = baseIdx.add_epi64(block(idx + 3));
				plaintext[4] = baseIdx.add_epi64(block(idx + 4));
				plaintext[5] = baseIdx.add_epi64(block(idx + 5));
				plaintext[6] = baseIdx.add_epi64(block(idx + 6));
				plaintext[7] = baseIdx.add_epi64(block(idx + 7));
				ecbEncBlocks<step>(plaintext.data(), ciphertext + idx);
			}

			i32 misalignment = blockLength % step;
			switch (misalignment) {
#define SWITCH_CASE(n) \
		    case n: \
				for(u64 j = 0; j < n; ++j) plaintext[j] = baseIdx.add_epi64(block(idx + j));\
		        ecbEncBlocks<n>(plaintext.data(), ciphertext + idx); \
		        break
				SWITCH_CASE(1);
				SWITCH_CASE(2);
				SWITCH_CASE(3);
				SWITCH_CASE(4);
				SWITCH_CASE(5);
				SWITCH_CASE(6);
				SWITCH_CASE(7);
#undef SWITCH_CASE
			}
		}

		///////////////////////////////////////////////
		// Tweakable correlation robust hash function.
		// https://eprint.iacr.org/2019/074.pdf section 7.4


		// Tweakable correlation robust hash function.
		// y_i = AES(AES(x_i) ^ tweak_i) + AES(x_i).
		template<AESTypes type>
		template<u64 blocks, typename TweakFn>
		OC_FORCEINLINE void AES<type>::TmmoHashBlocks(const block* plaintext, block* ciphertext, TweakFn&& tweakFn) const
		{
			oc::AlignedArray<block, blocks> buff;
			oc::AlignedArray<block, blocks> pix;

			// pix = AES(x)
			ecbEncBlocks<blocks>(plaintext, pix.data());

			// buff = { tweaks_0, ..., baseTweak_{blocks - 1} } 
			generateTweaks<blocks>(std::forward<TweakFn>(tweakFn), buff.data());

			// buff = AES(x) ^ tweaks
			xorBlocks<blocks>(pix.data(), buff.data());

			// ciphertext = AES( AES(x) ^ tweaks)
			ecbEncBlocks<blocks>(buff.data(), ciphertext);

			// ciphertext = AES(AES(x) ^ tweaks) ^ AES(x)
			xorBlocks<blocks>(pix.data(), ciphertext);
		}


		// Tweakable correlation robust hash function.
		// TMMO(x, i) = AES(AES(x) + i) + AES(x).
		template<AESTypes type>
		block AES<type>::TmmoHashBlock(block plaintext, block baseTweak) const
		{
			block r;
			TmmoHashBlocks<1>(&plaintext, &r, [baseTweak]() { return baseTweak; });
			return r;
		}


		// Tweakable correlation robust hash function.
		// y_i = AES(AES(x_i) ^ tweak_i) + AES(x_i).
		template<AESTypes type>
		template<typename TweakFn>
		inline void AES<type>::TmmoHashBlocks(span<const block> plaintext, span<block> ciphertext, TweakFn&& tweak) const
		{
			if (plaintext.size() != ciphertext.size())
				throw RTE_LOC;

			TmmoHashBlocks(plaintext.data(), plaintext.size(), ciphertext.data(), tweak);
		}


		// Tweakable correlation robust hash function.
		// y_i = AES(AES(x_i) ^ tweak_i) + AES(x_i).
		template<AESTypes type>
		template<typename TweakFn>
		inline void AES<type>::TmmoHashBlocks(const block* plaintext, u64 blockLength, block* ciphertext, TweakFn&& tweak) const
		{
			const u64 step = 8;
			u64 idx = 0;

			for (; idx + step <= blockLength; idx += step)
			{
				TmmoHashBlocks<step>(plaintext + idx, ciphertext + idx, tweak);
			}

			i32 misalignment = blockLength % step;
			switch (misalignment) {
#define SWITCH_CASE(n) \
		                    case n: \
		                        TmmoHashBlocks<n>(plaintext + idx, ciphertext + idx, tweak); \
		                        break;
				SWITCH_CASE(1)
					SWITCH_CASE(2)
					SWITCH_CASE(3)
					SWITCH_CASE(4)
					SWITCH_CASE(5)
					SWITCH_CASE(6)
					SWITCH_CASE(7)
#undef SWITCH_CASE
			}
		}




		///////////////////////////////////////////////
		// Correlation robust hash function.


		// Correlation robust hash function.
		// H(x) = AES(x) + x.
		template<AESTypes type>
		template<u64 blocks>
		OC_FORCEINLINE void AES<type>::hashBlocks(const block* plaintext, block* ciphertext) const
		{
			if constexpr (blocks <= 16)
			{

				oc::AlignedArray<block, blocks> buff;
				ecbEncBlocks<blocks>(plaintext, buff.data());
				for (u64 j = 0; j < blocks; ++j)
					ciphertext[j] = buff[j] ^ plaintext[j];
			}
			else
			{
				hashBlocks(plaintext, blocks, ciphertext);
			}
		}

		// Correlation robust hash function.
		// H(x) = AES(x) + x.
		template<AESTypes type>
		inline void AES<type>::hashBlocks(span<const block> plaintext, span<block> ciphertext) const
		{
			if (plaintext.size() != ciphertext.size())
				throw RTE_LOC;
			hashBlocks(plaintext.data(), plaintext.size(), ciphertext.data());
		}


		// Correlation robust hash function.
		// H(x) = AES(x) + x.
		template<AESTypes type>
		inline block AES<type>::hashBlock(const block& plaintext) const
		{
			block ciphertext;
			hashBlocks<1>(&plaintext, &ciphertext);
			return ciphertext;
		}


		// Correlation robust hash function.
		// H(x) = AES(x) + x.
		template<AESTypes type>
		inline void AES<type>::hashBlocks(const block* plaintext, u64 blockLength, block* ciphertext) const
		{
			const u64 step = 8;
			u64 idx = 0;

			for (; idx + step <= blockLength; idx += step)
			{
				hashBlocks<step>(plaintext + idx, ciphertext + idx);
			}

			i32 misalignment = blockLength % step;
			switch (misalignment) {
#define SWITCH_CASE(n) \
		        case n: \
		            hashBlocks<n>(plaintext + idx, ciphertext + idx); \
		            break
				SWITCH_CASE(1);
				SWITCH_CASE(2);
				SWITCH_CASE(3);
				SWITCH_CASE(4);
				SWITCH_CASE(5);
				SWITCH_CASE(6);
				SWITCH_CASE(7);
#undef SWITCH_CASE
			}
		}


		////////////////////////////////////////
		// Low level


		template<AESTypes type>
		block AES<type>::roundEnc(block state, const block& roundKey)
		{
			if constexpr (type == AESTypes::ARM)
			{
				// ARM is different in that it XORs in the key first.
				return roundFn(state, oc::ZeroBlock) ^ roundKey;
			}
			else
			{
				return roundFn(state, roundKey);
			}
		}

#ifdef OC_ENABLE_PORTABLE_AES
		template<>
		inline block AES<Portable>::firstFn(block state, const block& roundKey)
		{
			return state ^ roundKey;
		}

#endif // OC_ENABLE_AES_PORTABLE


#ifdef OC_ENABLE_AESNI

		template<>
		inline block AES<NI>::firstFn(block state, const block& roundKey)
		{
			return state ^ roundKey;
		}

		template<>
		inline block AES<NI>::roundFn(block state, const block& roundKey)
		{
			return _mm_aesenc_si128(state, roundKey);
		}

		template<>
		inline block AES<NI>::penultimateFn(block state, const block& roundKey)
		{
			return roundFn(state, roundKey);
		}


		template<>
		inline block AES<NI>::finalFn(block state, const block& roundKey)
		{
			return _mm_aesenclast_si128(state, roundKey);
		}

#elif defined(ENABLE_ARM_AES)

		template<>
		inline block AES<ARM>::firstFn(block state, const block& roundKey)
		{
			block r;
			r.mData = vaeseq_u8(state.mData, roundKey.mData);
			r.mData = vaesmcq_u8(r.mData);
			return r;
		}

		template<>
		inline block AES<ARM>::roundFn(block state, const block& roundKey)
		{
			return firstFn(state, roundKey);
		}

		template<>
		inline block AES<ARM>::penultimateFn(block state, const block& roundKey)
		{
			block r;
			r.mData = vaeseq_u8(state.mData, roundKey.mData);
			return r;
		}

		template<>
		inline block AES<ARM>::finalFn(block state, const block& roundKey)
		{
			return state ^ roundKey;
		}
#endif



		// A class to perform AES decryption.
		template<AESTypes type>
		class AESDec
		{
		public:
			static const u64 rounds = AES<type>::rounds;

			AESDec() = default;
			AESDec(const AESDec&) = default;

			AESDec(const block& key)
			{
				setKey(key);
			}

			void setKey(const block& userKey);
			void ecbDecBlock(const block& ciphertext, block& plaintext);

			block ecbDecBlock(const block& ciphertext)
			{
				block ret;
				ecbDecBlock(ciphertext, ret);
				return ret;
			}

			std::array<block, rounds + 1> mRoundKey;


			////////////////////////////////////////
			// Low level

            // AESDec is implemented as:
            // state = key[0] ^ input
            // state = (^key[1]  o -sbox o -shiftRow)(state) 
            // state = (^key[2]  o -sbox o -shiftRow o -mixCols)(state) 
            // ...
            // state = (^key[9]  o -sbox o -shiftRow o -mixCols)(state) 
            // state = (^key[10] o -sbox o -shiftRow o -mixCols)(state) 



            // NI,Portable: (^roundKey)(state)
            // ARM: (-sbox o -shiftRow o ^roundKey)(state)
			static block firstFn(block state, const block& roundKey);

            // Portable: (-mixCols o ^roundKey o -sbox o -shiftRow)(state)
            // NI: (^-mixCols(roundKey) o -mixCols o -sbox o -shiftRow)(state)
            //   = (-mixCols o ^-roundKey o -sbox o -shiftRow)(state)
			// ARM: (-sbox o -shiftRow o ^-mixCols(roundKey) o -mixCols )(state)
            //    = (-sbox o -shiftRow o -mixCols o ^roundKey)(state)
			static block roundFn(block state, const block& roundKey);

            // NI,Portable: (^roundKey o -sbox o -shiftRow)(state)
			// ARM: (^roundKey)(state)
			static block finalFn(block state, const block& roundKey);

		};

        
#ifdef ENABLE_ARM_AES

		template<>
		inline block AESDec<ARM>::firstFn(block state, const block& roundKey)
		{
			block r;
			r.mData = vaesdq_u8(state.mData, roundKey.mData);
			return r;
		}
		template<>
		inline block AESDec<ARM>::roundFn(block state, const block& roundKey)
		{
			block r;
			r.mData = vaesimcq_u8(state.mData);
			r.mData = vaesdq_u8(r.mData, roundKey.mData); // roundKey is already mixed.
			return r;
		}

		template<>
		inline block AESDec<ARM>::finalFn(block state, const block& roundKey)
		{
			return state ^ roundKey;
		}

#endif

#ifdef OC_ENABLE_AESNI

		template<>
		inline block AESDec<NI>::firstFn(block state, const block& roundKey)
		{
			return state ^ roundKey;
		}

		template<>
		inline block AESDec<NI>::roundFn(block state, const block& roundKey)
		{
			return _mm_aesdec_si128(state, roundKey);
		}

		template<>
		inline block AESDec<NI>::finalFn(block state, const block& roundKey)
		{
			return _mm_aesdeclast_si128(state, roundKey);
		}
#endif

	}

#ifdef OC_ENABLE_AESNI
	using AES = details::AES<details::NI>;
	using AESDec = details::AESDec<details::NI>;
#elif defined(ENABLE_ARM_AES)
	using AES = details::AES<details::ARM>;
	using AESDec = details::AESDec<details::ARM>;
#else
	using AES = details::AES<details::Portable>;
	using AESDec = details::AESDec<details::Portable>;
#endif

	// An AES instance with a fixed and public key.
	extern const AES mAesFixedKey;


}
