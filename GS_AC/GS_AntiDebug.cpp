/*
//GameShield Anti Cheat developed by MrSn0w

Purpoose:
Protect the game from being debugged by different debugging methodes VEH, Windows etc.
*/

#include "Includes.h"

__declspec(naked) void AntiAttach()
{
	__asm
	{
		jmp ExitProcess
	}
}

//Initialize
GS_AntiDebug::GS_AntiDebug()
{
	this->bIsDebugger = false;
	//AntiAttach with hooking DbgUiRemoteBreakin
	void* nt_DbgUiRemoteBreakin = GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("DbgUiRemoteBreakin").c_str());
	DWORD oProtect = 0;

	if (VirtualProtect(nt_DbgUiRemoteBreakin, 6, PAGE_EXECUTE_READWRITE, &oProtect))
	{
		//Copy hook func bytes
		memset(nt_DbgUiRemoteBreakin, 0x90, 6);
		memcpy(nt_DbgUiRemoteBreakin, (void*)AntiAttach, 6);
	}

	GSData::Func::myDebuggerPresent = reinterpret_cast<GSData::Func::tDebuggerPresent>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("IsDebuggerPresent").c_str()));
	GSData::Func::myRemoteDebuggerPresent = reinterpret_cast<GSData::Func::tRemoteDebuggerPresent>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("CheckRemoteDebuggerPresent").c_str()));
}

GS_AntiDebug::~GS_AntiDebug()
{
	delete this;
}

//IsDebuggerPresent Check //Standard Check
void GS_AntiDebug::DetectionGeneral()
{
	if (GSData::Func::myDebuggerPresent())
	{
		this->bIsDebugger = true;
		return;
	}

	BOOL found = FALSE;
	if (GSData::Func::myRemoteDebuggerPresent(GetCurrentProcess(), &found))
	{
		//Check Debugger
		if (found)
		{
			this->bIsDebugger = true;
			return;
		}
	}
}

void GS_AntiDebug::DetectionVEH()
{
	BOOL found = FALSE;

	__asm
	{
		xor eax, eax
		mov eax, fs:[0x30] //Start of PEB (frame segment)
		mov eax, [eax + 0x28] //Get CrossProcessFlags (32-Bit)
		and eax, 0x00000004 //Get VEH Flag
		mov found, eax //Store result
	}

	if (found)
		this->bIsVEH = true;
}


void GS_AntiDebug::DetectionAdvanced()
{

	//Inline Assembly Debugger Checking (Mostly PEB related)
	BOOL found = FALSE;
	// FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) | FLG_HEAP_VALIDATE_PARAMETERS (0x40)
	__asm
	{
		xor eax, eax //clear register
		mov eax, fs: [0x30] //start of the PEB
		mov eax, [eax + 0x68] //NtGlobalFlags
		and eax, 0x00000070 //Check 3 Flags
		mov found, eax //copy result
	}

	if (found)
	{
		this->bIsDebugger = true;
		return;
	}

	found = FALSE;
	//Being Debugged PEB Flag
	__asm
	{
		xor eax, eax		     //Clear eax register
		mov eax, fs: [0x30]      //Reference start of the PEB (frame segment)
		mov eax, [eax + 0x002] //Index into PEB Struct to receive BeingDebugged
		and eax, 0x000000FF   //Only reference one byte
		mov found, eax
	}

	if (found)
	{
		this->bIsDebugger = true;
		return;
	}

	HANDLE hProc = INVALID_HANDLE_VALUE;
	DWORD dwFound = FALSE;
	DWORD ProcessDebugPort = 0x07;
	DWORD ProcessDebugFlags = 0x1F;

	typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);

	//Get Process Address of NtQueryInformationProcess Function
	_NtQueryInformationProcess NtQueryInformationProcess = 0;
	NtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtQueryInformationProcess").c_str()));

	if (NtQueryInformationProcess != 0)
	{
		//Query ProcessDebugPort
		hProc = GetCurrentProcess();
		NTSTATUS status = NtQueryInformationProcess(hProc, ProcessDebugPort, &dwFound, sizeof(DWORD), 0);

		if (!status && dwFound)
		{
			this->bIsDebugger = true;
			return;
		}

		//Query ProcessDebugFlags
		status = NtQueryInformationProcess(hProc, ProcessDebugFlags, &dwFound, sizeof(DWORD), 0);

		//ProcessDebugFlags is set to 1 if no debugger was detected
		if (!status && !dwFound)
		{
			this->bIsDebugger = true;
			return;
		}
	}
}