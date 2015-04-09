
#include <cstdint>
#include <array>

using Hash32 = std::array<uint8_t, 32>;
using Hash64 = std::array<uint8_t, 64>;

constexpr uint32_t nMixBytes = 128;
constexpr uint32_t nAccesses = 64;

constexpr uint32_t nMixWords = nMixBytes / sizeof(uint32_t);
constexpr uint32_t nMixHashes = nMixBytes / sizeof(Hash64);

union Mix
{
	uint32_t words[nMixWords];
	Hash64 hashes[nMixHashes];
};

struct alignas(16) Result
{
	Hash32 hash;
	Hash32 mix;
};

//void computeEthash(Hash32& o_ret, Mix const* slices, uint32_t nSlices, Hash32 const& header, uint64_t nonce, Hash32* o_cmix);
uint64_t search(Result* ret, Mix const* slices, uint32_t nSlices, Hash32 const& header, uint64_t nonce, uint64_t tries, Hash32 const& target);