#pragma once
#include <vector>
#include <string>
#include <Windows.h>

struct _Log
{
	unsigned int msgCode;
	const char* extraInfo;
};

namespace GSData
{
	namespace Func
	{
		//AntiDebug
		typedef BOOL(__stdcall* tDebuggerPresent)(void);
		typedef BOOL(__stdcall* tRemoteDebuggerPresent)(HANDLE hProcess, PBOOL pbDebuggerPresent);
		static tDebuggerPresent myDebuggerPresent;
		static tRemoteDebuggerPresent myRemoteDebuggerPresent;

		//Driver
		typedef BOOL(__stdcall* tEnumDeviceDrivers)(LPVOID* lpImageBase, DWORD cb, LPDWORD lpcbNeeded);
		static tEnumDeviceDrivers myEnumDeviceDrivers;

		//Exit
		typedef void(__stdcall* tExitProcess)(UINT uExitCode);
		static tExitProcess myExitProcess;
		typedef BOOL(__stdcall* tTerminateProcess)(HANDLE hProcess, UINT uExitCode);
		static tTerminateProcess myTerminateProcess;
	}

	namespace Game
	{
		static const char* szGameExe = "csgo.exe";
		static const wchar_t* wGameExe = L"csgo.exe";
		static std::vector<std::string> vModules = { "client.dll", "engine.dll" };
	}
}

//Module Flags
#define MODULE_SUSPICIOUS		0x00000001

//Memory Flags
#define MEMORY_SUSPICIOUS 		0x00000002

//Integrity Flags
#define INTEGRITY_VIOLATION		0x00000003

//Kernel Flags
#define DRIVER_BLACKLISTED		0x00000004
#define KERNEL_MODIFICATION		0x00000005

//Process
#define PROGRAM_SUSPICIOUS		0x00000006

//System
#define SYSTEM_TESTMODE			0x00000007
#define SYSTEM_NO_PATCHGUARD	0x00000008
#define SYSTEM_VM				0x00000009
#define SYSTEM_HYPERVISOR		0x0000000A

#define DEBUGGER_PRESENT		0x0000000B