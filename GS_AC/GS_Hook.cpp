#include "Includes.h"


bool Detour32(BYTE* src, BYTE* dst, const uintptr_t len)
{
	if (len < 5)
		return false;

	DWORD oldprotection;
	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &oldprotection);

	//Calc distance to our own func from hooked func
	uintptr_t relativeAddress = dst - src - 5; //5 bytes for jmp

	//Overwrite func with jmp
	*src = 0xE9;

	//Place address right after it
	*(uintptr_t*)(src + 1) = relativeAddress; //jmp to our func

	//restore access
	VirtualProtect(src, len, oldprotection, &oldprotection);
	return true;
}

BYTE* TrampHook32(BYTE* src, BYTE* dst, const uintptr_t len)
{
	if (len < 5)
		return false;

	//Allocate memory space to place our gateway
	BYTE* Gateway = (BYTE*)VirtualAlloc(0, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//Write stolen bytes from the func we overwrite
	memcpy_s(Gateway, len, src, len);

	//Calc relative address to jump to original func back
	uintptr_t gatewayAddress = src - Gateway - 5; //distance from gateway to next codeflow after jmp

	//Add jmp to the codeflow of our original func
	*(Gateway + len) = 0xE9;

	//Place Addr right after 0xE9
	*(uintptr_t*)((uintptr_t)Gateway + len + 1) = gatewayAddress; //jmp to the follerwing codeflow

	//Call detour and place hook
	Detour32(src, dst, len);

	return Gateway; //return gateway for our func
}