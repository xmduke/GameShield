/*
//GameShield Anti Cheat developed by MrSn0w

Purpoose:
Ensure the integrity of the own anti cheat module and the integrity of the games memory.
Check for unknown hooks and detect changes in the games memory and the anti cheat module.
*/
#include "Includes.h"


extern GS_AntiDebug* AntiDebug;
extern GS_Exit* Exit;
extern GS_Module* Module;
extern GS_Integrity* Integrity;
extern GS_Process* Proc;
extern GS_Driver* Driver;


GS_Integrity::GS_Integrity()
{
	//Thread Integrity;
	this->bIsThreadSuspended = false;
	this->bIsThreadTerminated = false;
	this->bIsTampered = false;

	//Store function Addresses

	//.text Hashes
	this->EngineDllHash.clear();
	this->ClientDllHash.clear();

	//Get Winapi function pointers
	this->WinFuncs[0] = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("ExitProcess").c_str()));
	this->WinFuncs[1] = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("TerminateProcess").c_str()));
	this->WinFuncs[2] = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtTerminateProcess").c_str()));
	this->WinFuncs[3] = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("psapi.dll").c_str()), _xor_("EnumDeviceDrivers").c_str()));
	this->WinFuncs[4] = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("CreateToolhelp32Snapshot").c_str()));
	this->WinFuncs[5] = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("Process32First").c_str()));
	this->WinFuncs[6] = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("Process32Next").c_str()));
	this->WinFuncs[7] = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtQuerySystemInformation").c_str()));

	//Get own function pointers (Not tested so may not work)
	void (GS_Integrity:: * fptr0) (void) = &GS_Integrity::HideThreads;
	void (GS_Integrity:: * fptr1) (void) = &GS_Integrity::CheckIAT;
	void (GS_Integrity:: * fptr2) (void) = &GS_Integrity::ChecksumIntegrity;

	void (GS_AntiDebug:: * fptr3) (void) = &GS_AntiDebug::DetectionGeneral;
	void (GS_AntiDebug:: * fptr4) (void) = &GS_AntiDebug::DetectionAdvanced;
	void (GS_AntiDebug:: * fptr5) (void) = &GS_AntiDebug::DetectionVEH;

	void (GS_Module:: * fptr6) (void) = &GS_Module::EnumModules;

	void (GS_Driver:: * fptr7) (void) = &GS_Driver::EnumDrivers;

	void (GS_Process:: * fptr8) (void) = &GS_Process::EnumProc;
	void (GS_Process:: * fptr9) (void) = &GS_Process::EnumWindows;

	void (GS_Exit:: * fptr10) (void) = &GS_Exit::ExitDetection;
	void (GS_Exit:: * fptr11) (void) = &GS_Exit::Detection;
	void (GS_Exit:: * fptr12) (void) = &GS_Exit::CMDExit;

	this->gsFuncs[0] = (BYTE*)&fptr0;
	this->gsFuncs[1] = (BYTE*)&fptr1;
	this->gsFuncs[2] = (BYTE*)&fptr2;

	this->gsFuncs[3] = (BYTE*)&fptr3;
	this->gsFuncs[4] = (BYTE*)&fptr4;
	this->gsFuncs[5] = (BYTE*)&fptr5;

	this->gsFuncs[6] = (BYTE*)&fptr6;

	this->gsFuncs[7] = (BYTE*)&fptr7;

	this->gsFuncs[8] = (BYTE*)&fptr8;
	this->gsFuncs[9] = (BYTE*)&fptr9;

	this->gsFuncs[10] = (BYTE*)&fptr10;
	this->gsFuncs[11] = (BYTE*)&fptr11;
	this->gsFuncs[12] = (BYTE*)&fptr12;
}

GS_Integrity::~GS_Integrity()
{
	//Close Open Handles
	CloseHandle(this->hTH1);
	CloseHandle(this->hTH2);
	CloseHandle(this->hTH3);
	CloseHandle(this->hTH4);

	delete this;
}

void GS_Integrity::HideThreads()
{
	NTSTATUS status = 0;
	tNtSetInformationThread NtSetInformationThread =
		reinterpret_cast<tNtSetInformationThread>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtSetInformationThread").c_str()));

	status = NtSetInformationThread(this->hTH1, (THREAD_INFORMATION_CLASS)ThreadHideFromDebugger, 0, 0);
	status = NtSetInformationThread(this->hTH2, (THREAD_INFORMATION_CLASS)ThreadHideFromDebugger, 0, 0);
	status = NtSetInformationThread(this->hTH3, (THREAD_INFORMATION_CLASS)ThreadHideFromDebugger, 0, 0);
	status = NtSetInformationThread(this->hTH4, (THREAD_INFORMATION_CLASS)ThreadHideFromDebugger, 0, 0);
}

bool GS_Integrity::GetEngineImageInfo()
{
	auto engineMod = GetModuleHandleA(_xor_("engine.dll").c_str());

	//Get DOS Header
	PIMAGE_DOS_HEADER pDOSHeader = 0;
	pDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(engineMod);
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false; //Not an exe file

	//Get NT Header
	PIMAGE_NT_HEADERS pNTHeader = 0;
	pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((PBYTE)engineMod + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return false; //No valid PE file

	//Get File header
	PIMAGE_FILE_HEADER pFileHeader = 0;
	pFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>((PBYTE)&pNTHeader->FileHeader);

	//Get optional header
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = 0;
	pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>((PBYTE)&pNTHeader->OptionalHeader);

	if (pNTHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return false; //Not 32 Bit

	//Get Section header
	PIMAGE_SECTION_HEADER pSectionHeader = 0;
	pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>((PBYTE)&pNTHeader->OptionalHeader + pNTHeader->FileHeader.SizeOfOptionalHeader);

	DWORD dwEntryPoint = pNTHeader->OptionalHeader.AddressOfEntryPoint;
	UINT nSectionCount = pNTHeader->FileHeader.NumberOfSections;

	//Loop sections
	for (UINT i = 0; i < nSectionCount; i++)
	{
		//Find .text section
		if (pSectionHeader->VirtualAddress <= dwEntryPoint && dwEntryPoint < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
			break; //.text section found

		pSectionHeader++; //Next section
	}

	//Store image information
	this->EngineDll.pVirtualAddress = (PVOID)pSectionHeader->VirtualAddress;
	this->EngineDll.pEntryPoint = (PVOID)(((PBYTE)engineMod) + dwEntryPoint);
	this->EngineDll.dwCodeSize = pSectionHeader->Misc.VirtualSize;
	this->EngineDll.pCodeStart = (PVOID)(((PBYTE)engineMod) + (SIZE_T)((PBYTE)this->EngineDll.pVirtualAddress));
	this->EngineDll.pCodeEnd = (PVOID)((PBYTE)this->EngineDll.pCodeStart + this->EngineDll.dwCodeSize);

	return true;
}

bool GS_Integrity::GetClientImageInfo()
{
	auto ClientMod = GetModuleHandleA(_xor_("client.dll").c_str());

	//Get DOS Header
	PIMAGE_DOS_HEADER pDOSHeader = 0;
	pDOSHeader = static_cast<PIMAGE_DOS_HEADER>((PVOID)ClientMod);
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false; //Not an exe file

	//Get NT Header
	PIMAGE_NT_HEADERS pNTHeader = 0;
	pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((PBYTE)ClientMod + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return false; //No valid PE file

	//Get File header
	PIMAGE_FILE_HEADER pFileHeader = 0;
	pFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>((PBYTE)&pNTHeader->FileHeader);

	//Get optional header
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = 0;
	pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>((PBYTE)&pNTHeader->OptionalHeader);

	if (pNTHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return false; //Not 32 Bit

	//Get Section header
	PIMAGE_SECTION_HEADER pSectionHeader = 0;
	pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>((PBYTE)&pNTHeader->OptionalHeader + pNTHeader->FileHeader.SizeOfOptionalHeader);

	DWORD dwEntryPoint = pNTHeader->OptionalHeader.AddressOfEntryPoint;
	UINT nSectionCount = pNTHeader->FileHeader.NumberOfSections;

	//Loop sections
	for (UINT i = 0; i < nSectionCount; i++)
	{
		//Find .text section
		if (pSectionHeader->VirtualAddress <= dwEntryPoint && dwEntryPoint < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
			break; //.text section found

		pSectionHeader++; //Next section
	}

	//Store image information
	this->ClientDll.pVirtualAddress = (PVOID)pSectionHeader->VirtualAddress;
	this->ClientDll.pEntryPoint = (PVOID)(((PBYTE)ClientMod) + dwEntryPoint);
	this->ClientDll.dwCodeSize = pSectionHeader->Misc.VirtualSize;
	this->ClientDll.pCodeStart = (PVOID)(((PBYTE)ClientMod) + (SIZE_T)((PBYTE)this->ClientDll.pVirtualAddress));
	this->ClientDll.pCodeEnd = (PVOID)((PBYTE)this->ClientDll.pCodeStart + this->ClientDll.dwCodeSize);

	return true;
}

//Enumerate running Thread and determine if detection Threads running
void GS_Integrity::EnumThread()
{
	HANDLE hSnap = 0;
	THREADENTRY32 thEntry = { 0 };
	thEntry.dwSize = sizeof(thEntry);
	bool bIsAliveTH1 = false;
	bool bIsAliveTH2 = false;
	bool bIsAliveTH3 = false;
	bool bIsAliveMain = false;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

	if (Thread32First(hSnap, &thEntry))
	{
		do
		{
			//Check GS_Mod
			if (thEntry.th32ThreadID == this->ID_TH1)
				bIsAliveTH1 = true;
			else if (thEntry.th32ThreadID == this->ID_TH2)
				bIsAliveTH2 = true;
			else if (thEntry.th32ThreadID == this->ID_TH3)
				bIsAliveTH3 = true;
			else if (thEntry.th32ThreadID == this->ID_TH4)
				bIsAliveMain = true; //Thread Suspend check

			if (bIsAliveTH1 && bIsAliveTH2 && bIsAliveTH3 && bIsAliveMain)
				break;

		} while (Thread32Next(hSnap, &thEntry));
	}

	CloseHandle(hSnap);

	//If any Thread has been terminated
	if (!bIsAliveTH1 || !bIsAliveTH2 || !bIsAliveTH3 || !bIsAliveMain)
		this->bIsThreadTerminated = true;
}


void GS_Integrity::AntiTamper()
{
	DWORD temp = 0;
	BYTE* buffer = new BYTE[5];
	if (buffer && Module->hookBytes)
	{
		//Check RtlCreateUserThread Hook
		VirtualProtect(Module->RtlCreatUserThreadAddr, 5, PAGE_EXECUTE_READ, &temp);
		memcpy(buffer, Module->RtlCreatUserThreadAddr, 5);
		for (int i = 0; i < 5; i++)
		{
			if (*(BYTE*)(buffer + i) != *(BYTE*)(Module->hookBytes + i))
			{
				VirtualProtect(Module->RtlCreatUserThreadAddr, 5, temp, 0);
				delete[] buffer;
				this->bIsTampered = true;
				return;
			}
		}
		VirtualProtect(Module->RtlCreatUserThreadAddr, 5, temp, 0);

		memset(buffer, 0, 5);
		//Check CreateThread Hook
		VirtualProtect(Module->CreateThreadAddr, 5, PAGE_EXECUTE_READ, &temp);
		memcpy(buffer, Module->CreateThreadAddr, 5);
		for (int i = 0; i < 5; i++)
		{
			if (*(BYTE*)(buffer + i) != *(BYTE*)(Module->hookBytes + i + 5))
			{
				delete[] buffer;
				this->bIsTampered = true;
				return;
			}
		}

		memset(buffer, 0, 5);
		//Check GetThreadContext Hook
		memcpy(buffer, Module->GetThreadContextAddr, 5);
		for (int i = 0; i < 5; i++)
		{
			if (*(BYTE*)(buffer + i) != *(BYTE*)(Module->hookBytes + i + 10))
			{
				delete[] buffer;
				this->bIsTampered = true;
				return;
			}
		}

		memset(buffer, 0, 5);
		//Check SetThreadContext Hook
		memcpy(buffer, Module->SetThreadContextAddr, 5);
		for (int i = 0; i < 5; i++)
		{
			if (*(BYTE*)(buffer + i) != *(BYTE*)(Module->hookBytes + i + 15))
			{
				delete[] buffer;
				this->bIsTampered = true;
				return;
			}
		}

		memset(buffer, 0, 5);
		//Check SetThreadContext Hook
		memcpy(buffer, Module->SetThreadContextAddr, 5);
		for (int i = 0; i < 5; i++)
		{
			if (*(BYTE*)(buffer + i) != *(BYTE*)(Module->hookBytes + i + 15))
			{
				delete[] buffer;
				this->bIsTampered = true;
				return;
			}
		}
	}
	delete[] buffer;

	//Check WinAPI Functions
	for (int i = 0; i < 8; i++)
	{
		for (int a = 0; a < 5; a++)
		{
			//Check for jmp & ret
			if (*(BYTE*)(this->WinFuncs[i] + a) == 0xE9 || *(BYTE*)(this->WinFuncs[i] + a) == 0xEB || *(BYTE*)(this->WinFuncs[i] + a) == 0xC3)
			{
				this->bIsTampered = true;
				return;
			}
		}
	}

	//Check own functions
	for (int i = 0; i < 15; i++)
	{
		for (int a = 0; a < 5; a++)
		{
			//Check for jmp & ret
			if (*(BYTE*)(this->WinFuncs[i] + a) == 0xE9 || *(BYTE*)(this->WinFuncs[i] + a) == 0xEB || *(BYTE*)(this->WinFuncs[i] + a) == 0xC3)
			{
				this->bIsTampered = true;
				return;
			}
		}
	}
}



void GS_Integrity::CheckIAT()
{
	NTSTATUS status;
	PLDR_DATA_TABLE_ENTRY modEntry = nullptr;
	PEB* peb = GetPebInternal();
	LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY curr = head;

	BYTE* functionAddr = nullptr;
	BYTE* startAddr = nullptr;
	BYTE* endAddr = nullptr;
	DWORD OldProtect = 0;

	auto currEntry = head;


	for (auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink)
	{
		LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);


		if (mod->BaseDllName.Buffer)
		{
			//Calculate Module Memory Info
			startAddr = (BYTE*)(mod->DllBase);
			endAddr = (BYTE*)(startAddr + mod->SizeOfImage);

			//Check ntdll Module for IAT Hooks
			if (!_stricmp(_xor_("ntdll.dll").c_str(), (char*)mod->BaseDllName.Buffer))
			{
				functionAddr = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtQuerySystemInformation").c_str()));
				if (functionAddr < startAddr && functionAddr > endAddr)
				{
					this->bIsTampered = true;
					break;
				}

				functionAddr = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtQueryInformationProcess").c_str()));
				if (functionAddr < startAddr && functionAddr > endAddr)
				{
					if (functionAddr < startAddr && functionAddr > endAddr)
					{
						this->bIsTampered = true;
						break;
					}
				}

				functionAddr = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtOpenProcess").c_str()));
				if (functionAddr < startAddr && functionAddr > endAddr)
				{
					if (functionAddr < startAddr && functionAddr > endAddr)
					{
						this->bIsTampered = true;
						break;
					}
				}
			}
			else if (!_stricmp(_xor_("kernel32.dll").c_str(), (char*)mod->BaseDllName.Buffer))
			{
				//ExitProcess Check
				functionAddr = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("ExitProcess").c_str()));
				if (functionAddr < startAddr && functionAddr > endAddr)
				{
					if (functionAddr < startAddr && functionAddr > endAddr)
					{
						this->bIsTampered = true;
						break;
					}
				}

				functionAddr = reinterpret_cast<BYTE*>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("TerminateProcess").c_str()));
				if (functionAddr < startAddr && functionAddr > endAddr)
				{
					if (functionAddr < startAddr && functionAddr > endAddr)
					{
						this->bIsTampered = true;
						break;
					}
				}
			}
			else
			{
				continue;
			}
		}
	}
}


void GS_Integrity::ChecksumIntegrity()
{
	NTSTATUS status;
	PLDR_DATA_TABLE_ENTRY modEntry = nullptr;
	PEB* peb = GetPebInternal();
	LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY curr = head;

	BYTE* functionAddr = nullptr;
	BYTE* startAddr = nullptr;
	BYTE* endAddr = nullptr;
	DWORD OldProtect = 0;

	auto currEntry = head;

	for (auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink)
	{
		LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		////Checksum check for client.dll
		if (mod->BaseDllName.Buffer)
		{
			if (!_wcsicmp(L"client.dll", mod->BaseDllName.Buffer))
			{
				char* buffer = new char[this->ClientDll.dwCodeSize];
				if (buffer)
				{
					memcpy(buffer, reinterpret_cast<char*>(this->ClientDll.pCodeStart), this->ClientDll.dwCodeSize);
					std::string txtHash = md5(buffer, this->ClientDll.dwCodeSize);
					delete[] buffer; //Error here

					if (!this->ClientDllHash.size())
					{
						this->ClientDllHash = txtHash;
						return;
					}

					if (this->ClientDllHash != txtHash)
					{
						this->bIsTampered = true;
						return;
					}
				}
			}

			//Checksum Check for engine.dll
			if (!_wcsicmp(L"engine.dll", mod->BaseDllName.Buffer))
			{
				char* buffer = new char[this->EngineDll.dwCodeSize];
				if (buffer)
				{
					memcpy(buffer, reinterpret_cast<char*>(this->EngineDll.pCodeStart), this->EngineDll.dwCodeSize);
					std::string txtHash = md5(buffer, this->EngineDll.dwCodeSize);
					delete[] buffer;

					if (!this->EngineDllHash.size())
					{
						this->EngineDllHash = txtHash;
						return;
					}

					if (this->EngineDllHash != txtHash)
					{
						this->bIsTampered = true;
						return;
					}
				}
			}
		}	
	}
}



PEB* GS_Integrity::GetPebInternal()
{
#ifdef _WIN64
	PEB* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
	PEB* peb = reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif // _WIN64

	return peb;
}