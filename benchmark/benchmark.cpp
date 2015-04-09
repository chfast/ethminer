
#include <cstdint>
#include <cstring>

#include <chrono>
#include <functional>
#include <iostream>

#include "../libethminer/ethminer.h"

// void keccak256(uint8_t* out, uint8_t const* data, size_t size);
// void keccak512(uint8_t* out, uint8_t const* data, size_t size);
// void keccak256_96(uint8_t* out, uint8_t const* data);
// void keccak512_40(uint8_t* out, uint8_t const* data);

namespace
{
	// void benchmarkBigDataHash()
	// {
	// 	constexpr auto dataSize = 512 * 1024 * 1024;
	// 	auto data = new uint8_t[dataSize];

	// 	uint8_t h[32];
	// 	keccak256(h, data, dataSize);

	// 	delete[] data;
	// }

	// void benchmarkChainHash()
	// {
	// 	constexpr auto N = 4 * 1024 * 1024;
	// 	uint8_t h[32];
	// 	for (auto i = 0; i < N; ++i)
	// 		keccak256(h, h, 32);
	// }

	// void benchmarkCombine()
	// {
	// 	constexpr auto N = 2 * 1024 * 1024;
	// 	uint8_t h[96];
	// 	for (auto i = 0; i < N; ++i)
	// 	{
	// 		keccak512(h, h, 40);
	// 		keccak256(h, h, 96);
	// 	}
	// }

	// void benchmarkCombineFixed()
	// {
	// 	constexpr auto N = 2 * 1024 * 1024;
	// 	uint8_t h[96];
	// 	for (auto i = 0; i < N; ++i)
	// 	{
	// 		keccak512_40(h, h); // TODO: Check pointer alising
	// 		keccak256_96(h, h);
	// 	}
	// }

	// bool testKeccak256()
	// {
	// 	uint8_t h[32];
	// 	keccak256(h, nullptr, 0);
	// 	//"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	// 	uint8_t ref[] = {0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
	// 					 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70};
	// 	return std::memcmp(ref, h, sizeof(ref)) == 0;
	// }

	// bool testKeccak512()
	// {
	// 	// 0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e
	// 	uint8_t h[64];
	// 	keccak512(h, nullptr, 0);
	// 	uint8_t ref[] = {0x0e, 0xab};
	// 	return std::memcmp(ref, h, sizeof(ref)) == 0;
	// }

	// bool testKeccakImpls()
	// {
	// 	uint8_t h1[64];
	// 	uint8_t h2[64];
	// 	uint8_t test[96] = "hello world";

	// 	keccak256(h1, test, 96);
	// 	keccak256_96(h2, test);
	// 	if (std::memcmp(h1, h2, 32) != 0)
	// 		return false;

	// 	keccak512(h1, test, 40);
	// 	keccak512_40(h2, test);
	// 	return std::memcmp(h1, h2, 64) == 0;
	// }

	void benchmarkSearch(uint64_t iters)
	{
		constexpr uint64_t cacheSize = 1 * 1024 * 1024 * 1024;
		auto cache = new uint8_t[cacheSize];
		Hash32 header = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,};
		auto target = Hash32{0x00, 0x00, 0x01, 0x00, 0x00}; // runs forever
		Result r;
		search(&r, (Mix*)cache, cacheSize / sizeof(Mix), header, 13, iters, target);
	}

	void benchmark(char const* name, std::function<void()> f)
	{
		auto start = std::chrono::high_resolution_clock::now();
		f();
		auto d = std::chrono::high_resolution_clock::now() - start;
		std::cout << name << ": " << std::chrono::duration_cast<std::chrono::milliseconds>(d).count() << " ms\n";
	}

	void benchmark(char const* name, std::function<void(uint64_t)> f, uint64_t iters)
	{
		auto start = std::chrono::high_resolution_clock::now();
		f(iters);
		auto d = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();
		auto r = (uint64_t)(iters / (double)d);

		std::cout << name << ": " << r << " k/s\n";
	}

	void test(char const* name, std::function<bool()> f)
	{
		if (!f())
			std::cout << name << ": failed!\n";
	}
}


int main(int argv, char* argc[])
{
	//test("Keccak 256", testKeccak256);
	//test("Keccak 512", testKeccak512);
	//test("Keccak Impls", testKeccakImpls);
	benchmark("Search", benchmarkSearch, 1000*1000);
	//benchmark("Big data hash", benchmarkBigDataHash);
	//benchmark("Chain hash", benchmarkChainHash);
	//benchmark("Combine", benchmarkCombine);
	//benchmark("Combine fixed", benchmarkCombineFixed);
	return 0;
}