#include "Includes.h"

GS_VM::GS_VM()
{
	this->bIsVM = false;
}

GS_VM::~GS_VM()
{
	delete this;
}

void GS_VM::CheckVMGeneral()
{
	NTSTATUS status = 0;
	SYSTEM_BASIC_INFORMATION sbi;

	tNtQuerySystemInformation NtQuerySystemInformation =
		reinterpret_cast<tNtQuerySystemInformation>(GetProcAddress(GetModuleHandle(_xor_("ntdll.dll").c_str()), _xor_("NtQuerySystemInformation").c_str()));

	status = NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), nullptr);

	//Check number of Process Cores on the system
	if (NT_ERROR(status))
		return;

	int procNum = static_cast<int>(sbi.NumberOfProcessors);
	if (procNum == 1)
		this->bIsVM = true;
	
	//Check if more than one core is available
	HKEY hKey;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, _xor_("Hardware\\Description\\System\\CentralProcessor\\1").c_str(), 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
		this->bIsVM = true;
}

void GS_VM::CheckVMServices()
{
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 procEntry = { 0 };
	procEntry.dwSize = sizeof(procEntry);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return;

	if (Process32First(hSnap, &procEntry))
	{
		do
		{
			std::stringstream ss;
			ss << procEntry.szExeFile;
			std::string sProc = ss.str();

			if (!(this->VMware.vmProc1.compare(ss.str()) || !(this->VMware.vmProc2.compare(ss.str()) || !(this->VBox.vmProc1.compare(ss.str())
				|| !(this->VBox.vmProc2.compare(ss.str()) || !(this->VBox.vmProc3.compare(ss.str())))))))
			{
				this->bIsVM = true;
				break; //Exit Loop on Detection
			}

		} while (Process32Next(hSnap, &procEntry));
	}
}