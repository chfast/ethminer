
#include <cstdint>
#include <cstddef>

#include <chrono>
#include <functional>
#include <iostream>

void keccak256(uint8_t* out, uint8_t const* data, size_t size);

namespace
{
	void benchmarkBigDataHash()
	{
		constexpr auto dataSize = 32 * 1024 * 1024;
		auto data = new uint8_t[dataSize];

		uint8_t h[32];
		keccak256(h, data, dataSize);

		delete[] data;
	}

	void benchmarkChainHash()
	{
		constexpr auto N = 1 * 1024 * 1024;
		uint8_t h[32];
		for (auto i = 0; i < N; ++i)
			keccak256(h, h, 32);
	}

	bool testKeccak256()
	{
		uint8_t h[32];
		keccak256(h, nullptr, 0);
		//"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
		return h[0] == 0xc5;
	}

	void benchmark(char const* name, std::function<void()> f)
	{
		auto start = std::chrono::high_resolution_clock::now();
		f();
		auto d = std::chrono::high_resolution_clock::now() - start;
		std::cout << name << ": " << std::chrono::duration_cast<std::chrono::milliseconds>(d).count() << " ms\n";
	}

	void test(char const* name, std::function<bool()> f)
	{
		if (!f())
			std::cout << name << ": failed!\n";
	}
}


int main(int argv, char* argc[])
{
	test("Keccak 256", testKeccak256);
	benchmark("Big data hash", benchmarkBigDataHash);
	benchmark("Chain hash", benchmarkChainHash);
	return 0;
}