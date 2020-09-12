#pragma once
bool Detour32(BYTE* src, BYTE* dst, const uintptr_t len);
BYTE* TrampHook32(BYTE* src, BYTE* dst, const uintptr_t len);


typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR lpLibFileName);
typedef HMODULE(WINAPI* tLoadLibraryW)(LPCWSTR lpLibFileName);