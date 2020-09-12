#pragma once

typedef struct _PROCDATA
{
	ULONG Launcher;
	ULONG Steam;
	ULONG CSRSS;
	ULONG CSRSS2;
	ULONG Services;

} PROCDATA, * PPROCDATA;

//Driver Class
class KeInterface
{

private:

	HANDLE hDriver;

#define IO_REQUEST_PIDS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85100000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQUEST_INITIALIZED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85200000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQUEST_HEARTBEAT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85300000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQUEST_UNLOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85400000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

public:

	//Constructor
	KeInterface()
	{
		this->hDriver = CreateFileA("\\\\.\\GameShield", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	}

	~KeInterface()
	{
		CloseHandle(hDriver);
	}


	void SendInitStatus()
	{
		DWORD Bytes = 0;
		DeviceIoControl(hDriver, IO_REQUEST_INITIALIZED, nullptr, 0, nullptr, 0, &Bytes, 0);
	}

	void UnloadDriver()
	{
		DWORD Bytes = 0;
		DeviceIoControl(hDriver, IO_REQUEST_UNLOAD, nullptr, 0, nullptr, 0, &Bytes, 0);
	}

	//Driver Functions
	BOOL GetLegitPids()
	{
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCDATA pidData = { 0 };

		if (hSnap == INVALID_HANDLE_VALUE)
			return FALSE;

		if(this->hDriver)
			this->hDriver = CreateFileA("\\\\.\\GameShield", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (!strcmp(procEntry.szExeFile, "csrss.exe"))
				{
					if (OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, procEntry.th32ProcessID))
						continue; //Not a real csrss.exe
					
					if(!pidData.CSRSS)
						pidData.CSRSS = static_cast<ULONG>(procEntry.th32ProcessID);
					else
						pidData.CSRSS2 = static_cast<ULONG>(procEntry.th32ProcessID);
				}
				else if (!_strcmpi(procEntry.szExeFile, "steam.exe"))
				{
					pidData.Steam = static_cast<ULONG>(procEntry.th32ProcessID);
				}
				else if (!strcmp(procEntry.szExeFile, "services.exe"))
				{
					pidData.Services = static_cast<ULONG>(procEntry.th32ProcessID);
				}

			} while (Process32Next(hSnap, &procEntry));
		}
		CloseHandle(hSnap);

		//Send CSRSS Pids to Driver
		DWORD Bytes = 0;
		pidData.Launcher = static_cast<ULONG>(GetCurrentProcessId());

		return DeviceIoControl(this->hDriver, IO_REQUEST_PIDS, &pidData, sizeof(pidData), &pidData, sizeof(pidData), &Bytes, 0);
	}
};