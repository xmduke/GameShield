/*
//GameShield Anti Cheat developed by MrSn0w

Purpoose:
Triggered by the protection method.
On trigger the anti cheat will ensure the games gets terminated.
*/

#include "Includes.h"

GS_Exit::GS_Exit()
{
	GSData::Func::myExitProcess = reinterpret_cast<GSData::Func::tExitProcess>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("ExitProcess").c_str()));
	GSData::Func::myTerminateProcess = reinterpret_cast<GSData::Func::tTerminateProcess>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("TerminateProcess").c_str()));
}

GS_Exit::~GS_Exit()
{
	delete this;
}

void GS_Exit::ExitDetection()
{
	while (1)
	{
		//First Exit
		GSData::Func::myExitProcess(1);

		//Second Exit
		GSData::Func::myTerminateProcess(GetCurrentProcess(), 0);

		//Third (nativ) Exit
		NTSTATUS status = 0;
		tNtTerminateProcess NtTerminateProcess = reinterpret_cast<tNtTerminateProcess>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtTerminateProcess").c_str()));

		status = NtTerminateProcess(GetCurrentProcess(), 1);

		Sleep(50);
	}
}

void GS_Exit::Detection()
{
	StartLogTool();

	CMDExit();
	ExitDetection();
}

//Use CreateProcess to kill the target Process with CMD
void GS_Exit::CMDExit()
{
	DWORD pID = GetCurrentProcessId();
	std::string command = _xor_("taskkill /PID");
	char cmd[MAX_PATH];
	char cmdLine[MAX_PATH + 50];
	sprintf_s(cmdLine, "%s /c %s %ld /F", cmd, command.c_str(), pID);

	STARTUPINFOA startInfo;
	memset(&startInfo, 0, sizeof(startInfo));
	startInfo.cb = sizeof(startInfo);

	PROCESS_INFORMATION procInfo;
	memset(&procInfo, 0, sizeof(procInfo));

	BOOL createResult = CreateProcessA(0, cmdLine, 0, 0, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW,
		0, 0, &startInfo, &procInfo);

	DWORD procError;

	if (createResult)
	{
		//Wait till process completes
		WaitForSingleObject(procInfo.hProcess, INFINITE);
		//Check Process Exit Code
		GetExitCodeProcess(procInfo.hProcess, &procError);
		//Avoid Memory Leak by Closing Handle
		CloseHandle(procInfo.hProcess);
	}

	if (!createResult)
		procError = GetLastError();

	if (procError)
		GSData::Func::myExitProcess(1);
}

void GS_Exit::StartLogTool()
{
	if (!GetFileAttributesA("GS_Info.exe"))
		return;

	DWORD procError = 0;
	STARTUPINFOA startInfo = { 0 };
	PROCESS_INFORMATION procInfo = { 0 };
	startInfo.cb = sizeof(startInfo);

	BOOL createResult = CreateProcessA("GameShield\\GS_Info.exe", 0, 0, 0, FALSE, NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT, 0, 0, &startInfo, &procInfo);

	if (!createResult)
		procError = GetLastError();

	CloseHandle(procInfo.hProcess);

	if (procError)
		GSData::Func::myExitProcess(1);
}