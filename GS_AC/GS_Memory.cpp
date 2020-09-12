/*
Purpose:
Scan the memory of the game and search for suspicious patterns/signatures
and unknown memory areas
*/

#include "Includes.h"

//To Do: Scan for known string & signatures

std::uint8_t* GS_Memory::pattern_scan_ida(HMODULE h_module, const char* signature)
{
	static auto pattern_to_byte = [](const char* pattern)
	{
		auto bytes = std::vector<int>{};
		auto* const start = const_cast<char*>(pattern);
		auto* const end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto* current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?')
					++current;

				bytes.push_back(-1);
			}
			else
				bytes.push_back(strtoul(current, &current, 16));
		}
		return bytes;
	};

	auto* const dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(h_module);
	auto* const nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(h_module) + dos_header->e_lfanew);

	const auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
	auto* const scan_bytes = reinterpret_cast<std::uint8_t*>(h_module);

	auto pattern_bytes = pattern_to_byte(signature);

	const auto s = pattern_bytes.size();
	auto* const d = pattern_bytes.data();

	for (auto i = 0ul; i < size_of_image - s; ++i)
	{
		auto found = true;
		for (auto j = 0ul; j < s; ++j)
		{
			if (scan_bytes[i + j] != d[j] && d[j] != -1)
			{
				found = false;
				break;
			}
		}

		if (found)
			return &scan_bytes[i];
	}
	return nullptr;
}