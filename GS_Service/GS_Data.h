#pragma once
#include <vector>
#include <string>
#include <windowsx.h>

namespace GSData
{
	namespace Flag
	{
		//Module Flags
		#define MODULE_SUSPICIOUS			  0x00000001 //Manuelly Mapped or modified Module's
		#define MODULE_BLACKLISTED			  0x00000002

		//Memory Flags
		#define MEMORY_UNKNOWN 				  0x00000003

		//Integrity Flags
		#define INTEGRITY_CLIENT_MODIFICATION 0x00000004 //Game Integrity Coruption
		#define INTEGRITY_AC_MODIFICATION	  0x00000005 //Anti-Cheat Integrity Coruption

		//Kernel Flags
		#define DRIVER_BLACKLISTED			  0x00000006
		#define KERNEL_MODIFICATION			  0x00000007

		//Process
		#define PROCESS_SUSPICIOUS			  0x00000008
		#define WINDOW_SUSPICIOUS			  0x00000009

		//System
		#define SYSTEM_TESTMODE				  0x00000010
		#define SYSTEM_NO_PATCHGUARD		  0x00000020
		#define SYSTEM_VM					  0x00000030
		#define SYSTEM_HYPERVISOR			  0x00000040
	}

	namespace Game
	{
		static const char* szGameExe = "csgo.exe";
		static const wchar_t* wGameExe = L"csgo.exe";
		static std::vector<std::string> vModules = { "client.dll", "engine.dll" };
	}
}