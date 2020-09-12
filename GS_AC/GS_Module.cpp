/*
//GameShield Anti Cheat developed by MrSn0w

Purpoose:
Enumeration and detection of suspicious modules running in address space of the game.
Check for blacklisted modules and manually mapped modules.
*/

#include "Includes.h"

EXTERN_C IMAGE_DOS_HEADER __ImageBase; //Current ImageBase
extern GS_Module* Module;

GS_Module::GS_Module()
{
	this->bIsModDetected = false;
	this->hookBytes = (BYTE*)VirtualAlloc(0, 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	this->sModule.clear();
	
	//Initialize Md5 Module Blacklist (csgo.exe)
	this->vMd5Module.push_back(_xor_("de27d95fd17341ddc4d14cb2a65e6a40")); //Hook.dll
	this->vMd5Module.push_back(_xor_("087fcf928c7c901117c7b380e577d50a")); //AssultCube Internal.dll
	this->vMd5Module.push_back(_xor_("94ecd0bfff669325660746b2a6d27c72")); //AcHook.dll 8883fe7f4c74164e5231090656c91f04
	this->vMd5Module.push_back(_xor_("8883fe7f4c74164e5231090656c91f04"));
}


GS_Module::~GS_Module()
{
	VirtualFree(this->hookBytes, 0, MEM_RELEASE);
	delete[] this->buffer_hook1;
	delete[] this->buffer_hook2;
	delete this;
}


void GS_Module::EnumModules()
{
	MODULEENTRY32 modEntry = { 0 };
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetCurrentProcessId());

	if (hSnap == INVALID_HANDLE_VALUE)
		return;

	modEntry.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnap, &modEntry))
	{
		do
		{
			std::ifstream mod;
			mod.open(modEntry.szExePath, std::ios::binary | std::ios::in);

			if (mod.is_open())
			{
				//Get Image size
				mod.seekg(0, std::ios::end);
				long len = mod.tellg();

				mod.seekg(0, std::ios::beg); //Reset

				//Read File buffer
				char* buffer = new char[len];
				mod.read(buffer, len);
				mod.close();

				//Get Hash
				std::string md5hash = md5(buffer, len);
				delete[] buffer;

				//Itarate whitelist
				for (int i = 0; i < this->vMd5Module.size(); i++)
				{
					if (this->vMd5Module[i].compare(md5hash) == 0) //Is Blacklisted
					{
						std::stringstream ss;
						ss << modEntry.szModule;
						this->sModule = ss.str();
						this->bIsModDetected = true;
						return;
					}
				}
			}

		} while (Module32Next(hSnap, &modEntry));
	}

	//No Suspicious Module found
	CloseHandle(hSnap);
}


//Filter unknown/blacklisted Modules by Hooking LdrLoadDll (ntdll.dll)
NTSTATUS __stdcall hkLdrLoadDll
(
	IN PWCHAR               PathToFile OPTIONAL,
	IN ULONG                Flags OPTIONAL,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             ModuleHandle
)
{
	NTSTATUS status = 0;
	bool bIsBlacklisted = false;

	std::stringstream ss;
	ss << PathToFile;

	std::ifstream dllFile;
	dllFile.open(PathToFile, std::ios::binary | std::ios::in);

	if (dllFile.is_open())
	{
		dllFile.seekg(std::ios::end);
		ULONG len = dllFile.tellg();
		dllFile.seekg(std::ios::beg); //Reset to base

		char* buffer = new char[len];
		dllFile.read(buffer, len);

		std::string modHash = md5(buffer, len);
		delete[] buffer;

		for (int i = 0; i < Module->vMd5Module[i].size(); i++)
		{
			if (Module->vMd5Module[i].compare(modHash) == 0)
			{
				bIsBlacklisted = true;
				break;
			}
		}

		dllFile.close();
	}

	if (bIsBlacklisted)
		return Module->oLdrLoadDll(nullptr, Flags, ModuleFileName, ModuleHandle);
	else
		return Module->oLdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
}

//Detect manual mapped modules by checking call's to CreateThread
NTSTATUS __stdcall hkRtlCreateUserThread
(
	IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN OUT PULONG           StackReserved,
	IN OUT PULONG           StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter,
	OUT PHANDLE             ThreadHandle,
	OUT PCLIENT_ID          ClientID
)
{
	uintptr_t startAddress = reinterpret_cast<uintptr_t>(StartAddress);
	HANDLE hSnap = 0;
	MODULEENTRY32 modEntry = { 0 };
	bool bIsLegitAddr = true;

	modEntry.dwSize = sizeof(modEntry);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		Module32First(hSnap, &modEntry);

		do
		{
			uintptr_t currentBase = 0;
			uintptr_t currentEnd = 0;
			currentBase = reinterpret_cast<uintptr_t>(modEntry.modBaseAddr);
			currentEnd = reinterpret_cast<uintptr_t>(modEntry.modBaseAddr + modEntry.modBaseSize);

			if (startAddress < currentBase && startAddress > currentEnd) //does not reside in legit module
			{
				bIsLegitAddr = false;
				break;
			}

		} while (Module32Next(hSnap, &modEntry));

		CloseHandle(hSnap);
	}

	if (!bIsLegitAddr)
		Module->bIsModDetected = true;


	return Module->oRtlCreateUserThread(ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits, StackReserved,
			StackCommit, StartAddress, StartParameter, ThreadHandle, ClientID);
}


//Detect Manual Mapping
HANDLE WINAPI hkCreateThread
(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
)
{
	uintptr_t startAddress = reinterpret_cast<uintptr_t>(lpStartAddress);
	HANDLE hSnap = 0;
	MODULEENTRY32 modEntry = { 0 };
	bool bIsLegitAddr = true;

	modEntry.dwSize = sizeof(modEntry);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		Module32First(hSnap, &modEntry);

		do
		{
			uintptr_t currentBase = 0;
			uintptr_t currentEnd = 0;
			currentBase = reinterpret_cast<uintptr_t>(modEntry.modBaseAddr);
			currentEnd = reinterpret_cast<uintptr_t>(modEntry.modBaseAddr + modEntry.modBaseSize);
	
			if (startAddress < currentBase && startAddress > currentEnd) //StartAddr inside legit module
			{
				bIsLegitAddr = false;
				break;
			}

		} while (Module32Next(hSnap, &modEntry));

		CloseHandle(hSnap);
	}

	if (!bIsLegitAddr)
		Module->bIsModDetected = true;

	//Call CreateThread
	return Module->oCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}



//GetThreadContext Hook
BOOL __stdcall hkGetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
	//Let GetThreadContext fail
	return Module->oGetThreadContext(INVALID_HANDLE_VALUE, lpContext);
}

//SetThreadContext Hook
BOOL __stdcall hkSetThreadContext(HANDLE hThread, const CONTEXT* lpContext)
{
	//Let SetThreadContext fail
	return Module->oSetThreadContext(INVALID_HANDLE_VALUE, lpContext);
}


//Hooks (Module Detection/Prevention)
bool GS_Module::InitializeHooks()
{
	//Inline Hook's
	this->RtlCreatUserThreadAddr = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("RtlCreateUserThread").c_str()));
	this->CreateThreadAddr = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("CreateThread").c_str()));
	this->GetThreadContextAddr = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("GetThreadContext").c_str()));
	this->SetThreadContextAddr = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("SetThreadContext").c_str()));

	this->oRtlCreateUserThread = reinterpret_cast<tRtlCreateUserThread>(TrampHook32(this->RtlCreatUserThreadAddr, (BYTE*)hkRtlCreateUserThread, 5)); //Works
	this->oCreateThread = reinterpret_cast<tCreateThread>(TrampHook32(this->CreateThreadAddr, (BYTE*)hkCreateThread, 5));
	this->oGetThreadContext = reinterpret_cast<tGetThreadContext>(TrampHook32(this->GetThreadContextAddr, (BYTE*)hkGetThreadContext, 5));
	this->oSetThreadContext = reinterpret_cast<tSetThreadContext>(TrampHook32(this->SetThreadContextAddr, (BYTE*)hkSetThreadContext, 5));
	
	if (!this->oRtlCreateUserThread || !this->oCreateThread || !this->oSetThreadContext || !this->oGetThreadContext)
		return false;

	if (!this->hookBytes)
		return false;

	//Store Hook Bytes (20 Bytes)
	memcpy((BYTE*)this->hookBytes, RtlCreatUserThreadAddr, 5);
	memcpy((BYTE*)this->hookBytes + 5, this->CreateThreadAddr, 5);
	memcpy((BYTE*)this->hookBytes + 10, this->GetThreadContextAddr, 5);
	memcpy((BYTE*)this->hookBytes + 15, this->SetThreadContextAddr, 5);

	DWORD tmp;
	if (VirtualProtect(this->hookBytes, 20, PAGE_EXECUTE_READ, &tmp))
		return true;
}