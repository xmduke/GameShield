#pragma once

class GS_Memory
{
public:
	std::uint8_t* pattern_scan_ida(HMODULE h_module, const char* signature);
};