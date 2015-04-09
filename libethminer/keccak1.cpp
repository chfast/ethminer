
#include <array>
#include <cstdint>
#include <cstring>
#include <cassert>

#include <iostream>
#include <iomanip>

#include "ethminer.h"

namespace
{

	uint8_t  const rho[] = {  1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
	    					 27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44 };
	uint8_t  const pi[]  = { 10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
   							 15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1 };
	uint64_t const RC[]  = { 1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
							 0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
							 0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
							 0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
							 0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
							 0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

	constexpr uint64_t rot(uint64_t x, uint64_t s) { return x << s | x >> (64 - s); }

	#define REPEAT6(e)  e e e e e e
	#define REPEAT24(e) REPEAT6(e e e e)
	#define REPEAT5(e)  e e e e e
	#define FOR5(v, s, e) v = 0; REPEAT5(e; v += s;)

	/// Keccak-f[1600]
	inline void keccakf1600(uint64_t* a) noexcept
	{
		uint64_t b[5] = {0};
		uint64_t t = 0;
		uint8_t x, y;

		for (size_t i = 0; i < 24; ++i)
		{
			// Round[1600](a,RC):
			//  theta step:
			FOR5(x, 1,
			     b[x] = 0;
			     FOR5(y, 5,
			          b[x] ^= a[x + y]; ))
			FOR5(x, 1,
			     FOR5(y, 5,
			          a[y + x] ^= b[(x + 4) % 5] ^ rot(b[(x + 1) % 5], 1); ))

			//  rho and pi steps
			t = a[1];
			x = 0;
			REPEAT24(b[0] = a[pi[x]];
			         a[pi[x]] = rot(t, rho[x]);
			         t = b[0];
			         x++; )
			// chi step
			FOR5(y,
			   5,
			   FOR5(x, 1,
			        b[x] = a[y + x];)
			   FOR5(x, 1,
			        a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
			// iota step
			a[0] ^= RC[i];
		}
	}

	inline void xorin(uint64_t* dst, const uint64_t* src, size_t size)
	{
		for (size_t i = 0; i < size; ++i)
			dst[i] ^= src[i];
	}

	inline void hash(uint64_t* out, size_t outSize, const uint64_t* data, size_t size)
	{
		constexpr auto stateSize = 200;
		const auto r = stateSize - (2 * outSize); // 256: 136, 512: 72
		uint64_t a[stateSize / 8] = {0};
		// Absorb input.
		while (size >= r)
		{
			xorin(a, data, r / 8);
			keccakf1600(a);
			data += r / 8;
			size -= r;
		}
		// Xor in the DS and pad frame.
		a[size / 8] ^= 0x01; // 0x01: Keccak, 0x06: SHA3
		a[(r - 1) / 8] ^= 0x8000000000000000;
		// Xor in the last block.
		xorin(a, data, size / 8);
		keccakf1600(a);
		std::memcpy(out, a, outSize); // TODO: How about using out as a state
	}

	inline void hash_1(uint64_t* out, size_t outSize, const uint64_t* data, size_t size)
	{
		const auto r = 200 - (2 * outSize); // 256: 136, 512: 72
		uint64_t a[25] = {0}; // TODO: Can be optimized but probably compiler will do it for us?
		a[size] = 0x01;
		a[(r - 1) / 8] = 0x8000000000000000;
		xorin(a, data, size);
		keccakf1600(a);
		std::memcpy(out, a, outSize); // TODO: How about using out as a state
	}

	void dump(void const* data, uint64_t size)
	{
		auto bytes = (uint8_t const*)data;
		for (auto b = bytes; b != bytes + size; ++b)
			std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)*b;
		std::cerr << std::endl;
	}

	void dump(Hash64 const& h)
	{
		dump(&h, 64);
	}

	void dump(Hash32 const& h)
	{
		dump(&h, 32);
	}

	bool less(Hash32 const& h, Hash32 const& g)
	{
		for (uint64_t i = 0; i < h.size(); ++i)
		{
			if (h[i] < g[i])
				return true;
			else if (h[i] > g[i])
				return false;
		}
		return false;
	}

	void keccak256(uint8_t* out, uint8_t const* data, size_t size)
	{
		hash((uint64_t*)out, 32, (uint64_t*)data, size);
	}

	void keccak512(uint8_t* out, uint8_t const* data, size_t size)
	{
		hash((uint64_t*)out, 64, (uint64_t*)data, size);
	}

	void keccak256_96(uint8_t* out, uint8_t const* data)
	{
		hash_1((uint64_t*)out, 32, (uint64_t*)data, 96 / 8);
	}

	void keccak512_40(uint8_t* out, uint8_t const* data)
	{
		hash_1((uint64_t*)out, 64, (uint64_t*)data, 40 / 8);
	}

	constexpr uint32_t fnv(uint32_t x, uint32_t y)
	{
		return x * 0x01000193 ^ y;
	}

	struct SeedInput
		{
			Hash32 header;
			uint64_t nonce;
		};

	union MixElem
	{
		Hash64 hash;
		uint32_t words[sizeof(Hash64) / sizeof(uint32_t)];
	};

	struct SMix
	{
		union 
		{
			Hash64 seed;
			uint32_t seedWord;
		};	
		Mix mix;
	};

	void computeEthash(Hash32& o_ret, Mix const* slices, uint32_t nSlices, Hash32 const& header, uint64_t nonce, Hash32* o_cmix)
	{
		// TODO: How about computing many hashes for different nonces?
	    SMix smix;
	    auto& seed = smix.seed;
	    auto& mix = smix.mix;

	    auto seedInput = SeedInput{header, nonce};
	    keccak512_40((uint8_t*)&seed, (const uint8_t*)&seedInput);
	    static_assert(nMixHashes == 2, "Update seed replication");
	    mix.hashes[0] = mix.hashes[1] = seed;

	    for (uint32_t i = 0; i != nAccesses; ++i)
	    {
	        auto p = fnv(smix.seedWord ^ i, mix.words[i % nMixWords]) % nSlices;
	        auto& slice = slices[p];
	        for (uint32_t j = 0; j < nMixWords; ++j)
	        	mix.words[j] = fnv(mix.words[j], slice.words[j]);
	    }

	    for (uint64_t i = 0; i < nMixWords; i += 4)
	    {
	        auto c = fnv(mix.words[i + 0], mix.words[i + 1]);
	        c = fnv(c, mix.words[i + 2]);
	        c = fnv(c, mix.words[i + 3]);
	        mix.words[i / 4] = c;
	    }

	    if (o_cmix)
	    	std::memcpy(o_cmix, &mix, 32);
	    keccak256_96((uint8_t*)&o_ret, (uint8_t*)&smix); // TODO: Can we check target during computation of keccak?
	}

}

uint64_t search(Result* ret, Mix const* slices, uint32_t nSlices, Hash32 const& header, uint64_t nonce, uint64_t tries, Hash32 const& target)
{
	//dump(target);
	for (uint64_t i = 0; i < tries; ++i)
	{
		Hash32 h;
		computeEthash(h, slices, nSlices, header, nonce, nullptr);
		if (less(h, target))
		{
			//std::memcpy(ret, &h, sizeof(h));
			return nonce;
		}
		++nonce;
	}
	return 0;
}
