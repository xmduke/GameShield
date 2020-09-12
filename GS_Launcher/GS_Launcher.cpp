#include "Includes.h"



GS_Launcher::GS_Launcher()
{
	GetCurrentDirectoryA(MAX_PATH, this->szDirectory);
	this->serviceHash = "";
}


GS_Launcher::~GS_Launcher()
{
	delete this;
}


bool GS_Launcher::InjectClient(HANDLE hProc)
{
	//Allocate Memory for the dll path in the target process
	DWORD tmp = 0;
	const char buffer[] = "GS_Client.dll";
	char* szDllPathMem = reinterpret_cast<char*>(VirtualAllocEx(hProc, NULL, strlen(buffer), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!szDllPathMem)
		return false;

	//Write dll name
	if (!WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(szDllPathMem), buffer, strlen(buffer), NULL))
	{
		VirtualFreeEx(hProc, szDllPathMem, MAX_PATH, MEM_RELEASE);
		return false;
	}

	HMODULE hLoadLib = GetModuleHandle("kernel32.dll");

	//Create remote thread in target process
	HANDLE hRemoteThread = INVALID_HANDLE_VALUE;
	hRemoteThread = CreateRemoteThread(hProc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(hLoadLib, "LoadLibraryA")), szDllPathMem, 0, NULL);

	if (!hRemoteThread)
	{
		FreeLibrary(hLoadLib);
		VirtualFreeEx(hProc, szDllPathMem, 0, MEM_RELEASE);
		return false;
	}

	//Wait until remote thread ends
	DWORD dwExitCode = 0;
	WaitForSingleObject(hRemoteThread, INFINITE);
	GetExitCodeThread(hRemoteThread, &dwExitCode);

	if (dwExitCode)
	{
		VirtualFreeEx(hProc, szDllPathMem, 0, MEM_RELEASE);
		CloseHandle(hRemoteThread);
		return false;
	}

	VirtualFreeEx(hProc, szDllPathMem, 0, MEM_RELEASE);
	CloseHandle(hRemoteThread);
	CloseHandle(hProc);
	return true;
}

std::string GS_Launcher::GetCSGOExePath(bool OnlyDirectory)
{
	char buffer[MAX_PATH] = { 0 };
	GetCurrentDirectoryA(MAX_PATH, buffer);
	std::string steamExe(buffer);
	int pos = steamExe.find("GameShield", 0);
	steamExe.replace(pos, steamExe.size(), "");

	if (!OnlyDirectory)
		steamExe.append("csgo.exe");

	return steamExe;
}

std::string GS_Launcher::GetDirectory()
{
	char buffer[MAX_PATH] = { 0 };
	GetCurrentDirectoryA(MAX_PATH, buffer);
	std::string steamExe(buffer);
	int pos = steamExe.find_last_of("/\\", 0);
	steamExe.substr(0, pos);
	return steamExe;
}


bool GS_Launcher::InitGame()
{
	PROCESS_INFORMATION procInfo = { 0 };
	STARTUPINFO startInfo = { 0 };
	startInfo.cb = sizeof(startInfo);
	std::string path = GetCSGOExePath(false).c_str();
	char cmdLine[1024] = { 0 };
	sprintf_s(cmdLine, 1024, "%s -steam -insecure -untrusted", path);

	//Set Directory same as csgo.exe
	std::string gameDirectory = GetCSGOExePath(true).c_str();
	SetCurrentDirectoryA(gameDirectory.c_str());

	BOOL createResult = CreateProcessA("csgo.exe", cmdLine, 0, 0, FALSE, NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT,
		0, 0, &startInfo, &procInfo);

	DWORD procError = 0;
	if (!createResult)
		procError = GetLastError();

	if (procError)
		return false;

	return true;
}

HANDLE GS_Launcher::GetGameHandle()
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	HANDLE hProc = INVALID_HANDLE_VALUE;

	if (hSnap == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;

	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);

	if (Process32First(hSnap, &procEntry))
	{
		do
		{
			if (_stricmp(procEntry.szExeFile, GSData::Game::szGameExe) == 0)
			{
				hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procEntry.th32ProcessID);
				break;
			}

		} while (Process32Next(hSnap, &procEntry));
	}

	CloseHandle(hSnap);
	return hProc;
}

//Memberfunctions
bool GS_Launcher::bIsGameRunning()
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bool IsRunning = false;

	if (hSnap == INVALID_HANDLE_VALUE)
		return true;

	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);

	if (Process32First(hSnap, &procEntry))
	{
		do
		{
			if (_stricmp(procEntry.szExeFile, GSData::Game::szGameExe) == 0)
			{
				IsRunning = true;
				break;
			}

		} while (Process32Next(hSnap, &procEntry));
	}

	CloseHandle(hSnap);
	return IsRunning;
}


bool GS_Launcher::InitService()
{
	//File Checking
	HANDLE hService = 0;

	TCHAR szCurrDirectory[MAX_PATH] = { 0 };
	GetCurrentDirectory(MAX_PATH, szCurrDirectory);
	TCHAR szBuffer[MAX_PATH + 50];
	sprintf_s(szBuffer, "%s\\GS_Service.exe", szCurrDirectory);

	hService = CreateFile(szBuffer, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hService == INVALID_HANDLE_VALUE)
		return false;

	SC_HANDLE schSCManager = 0;
	SC_HANDLE schService = 0;
	bool IsServiceRunning = false;
	//Get a Handle to the SCM database
	schSCManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);

	if (schSCManager == INVALID_HANDLE_VALUE)
		return false;

	//Check if Service Exist
		//Check if Service Exist
	schService = OpenService(schSCManager, "GSService", SC_MANAGER_ALL_ACCESS);
	if (!schService)
	{
		schService = CreateService(schSCManager, "GSService", "GameShield Usermode Service", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
			SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, szBuffer, 0, 0, 0, 0, 0);

		if (!schService)
			return false;

		StartService(schService, 0, nullptr);
		DeleteService(schService);
	}
	else
	{
		StartService(schService, 0, nullptr);
		DeleteService(schService);
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return true;
	return IsServiceRunning;
}

bool GS_Launcher::InitDriver()
{
	//File Checking
	HANDLE hDriver = 0;

	TCHAR szCurrDirectory[MAX_PATH] = { 0 };
	GetCurrentDirectory(MAX_PATH, szCurrDirectory);
	TCHAR szBuffer[MAX_PATH + 50];
	sprintf_s(szBuffer, "%s\\GS_Driver.sys", szCurrDirectory);

	hDriver = CreateFile(szBuffer, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hDriver == INVALID_HANDLE_VALUE)
		return false;

	SC_HANDLE schSCManager = 0;
	SC_HANDLE schService = 0;
	//Get a Handle to the SCM database
	schSCManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == INVALID_HANDLE_VALUE)
		return false;

	//Check if Service Exist
	schService = OpenService(schSCManager, "GameShield", SC_MANAGER_ALL_ACCESS);
	if (!schService)
	{
		schService = CreateService(schSCManager, "GameShield", "GameShield Kernel Driver", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, szBuffer, 0, 0, 0, 0, 0);

		if (!schService)
			return false;
		
		StartService(schService, 0, nullptr);
		DeleteService(schService);
	}
	else
	{
		StartService(schService, 0, nullptr);
		DeleteService(schService);
	}	

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return true;
}