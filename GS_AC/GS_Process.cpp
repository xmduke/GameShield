/*
//GameShield Anti Cheat developed by MrSn0w

Purpoose:
Enumeration and detection of suspicious porocesses and windows on the system.
Check for blacklisted/suspicious processes & windows and scan for handles opend to the game.
*/

#include "Includes.h"

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004


GS_Process::GS_Process()
{
	this->bProcDetection = false;
	this->bWndDetection = false;
	this->procMem = 0;

	//Process Blacklist Initializing
	this->vWnd.push_back(_xor_("IDA"));
	this->vWnd.push_back(_xor_("x32dbg")); //x64 & x32-dbg
	this->vWnd.push_back(_xor_("x64dbg")); //x64 & x32-dbg
	this->vWnd.push_back(_xor_("Olly")); //OllyDbg
	this->vWnd.push_back(_xor_("Sysinternals"));
	this->vWnd.push_back(_xor_("Process Hacker"));
	this->vWnd.push_back(_xor_("WinDbg"));
	this->vWnd.push_back(_xor_("Cheat Engine"));
	this->vWnd.push_back(_xor_("ReClass"));
	this->vWnd.push_back(_xor_("CrySearch"));

	//Process Hash Blacklist
	this->vMd5Process.push_back(_xor_("ec801a7d4b72a288ec6c207bb9ff0131"));
	this->vMd5Process.push_back(_xor_("2198179ba473f08193f9c133c92fb75e"));
	this->vMd5Process.push_back(_xor_("1234abc"));
}


GS_Process::~GS_Process()
{
	delete this;
}


void GS_Process::EnumProc()
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
			int found = 0;

			for (UINT i = 0; i < this->vWnd.size(); i++)
			{
				found = static_cast<int>(sProc.find(this->vWnd[i], 0));

				if (found != std::string::npos)
				{
					this->bProcDetection = true;
					this->detectedName = sProc;
					return;
				}
			}

			//Hash Blacklist
			HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procEntry.th32ProcessID);
			char fPath[MAX_PATH] = { 0 };
			if (hProc != INVALID_HANDLE_VALUE)
			{
				if (GetModuleFileNameExA(hProc, 0, fPath, MAX_PATH))
				{
					//Check Hash
					CloseHandle(hProc);
					std::ifstream processMd5;
					processMd5.open(fPath, std::ios::binary | std::ios::in);
					if (processMd5.fail())
						continue;

					processMd5.seekg(0, std::ios::end);
					long len = processMd5.tellg();
					processMd5.seekg(0, std::ios::beg);

					//Read Filer
					char* buffer = new char[len];
					processMd5.read(buffer, len);

					std::string hash = md5(buffer, len);
					delete[] buffer;

					for (UINT i = 0; i < this->vMd5Process.size(); i++)
					{
						if (!this->vMd5Process[i].compare(hash)) //if Blacklisted
						{		
							processMd5.close();
							this->bProcDetection = true;
							return;
						}
					}
				}
			}

		} while (Process32Next(hSnap, &procEntry));
	}
}


void GS_Process::EnumHandles()
{
	DWORD pid = 0;
	NTSTATUS status = 0;
	PSYSTEM_HANDLE_INFORMATION phi = nullptr;
	ULONG handleInfoSize = 0x10000;
	ULONG PID = 0;
	HANDLE hProc = INVALID_HANDLE_VALUE;
	ULONG i = 0;


	tNtQuerySystemInformation NtQuerySystemInformation =
		reinterpret_cast<tNtQuerySystemInformation>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtQuerySystemInformation").c_str()));
	tNtDuplicateObject NtDuplicateObject =
		reinterpret_cast<tNtDuplicateObject>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtDuplicateObject").c_str()));
	tNtQueryObject NtQueryObject =
		reinterpret_cast<tNtQueryObject>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtQueryObject").c_str()));

	hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
	if (!hProc || hProc == INVALID_HANDLE_VALUE)
		return;

	phi = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(VirtualAlloc(0, handleInfoSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (!phi)
		return;

	status = NtQuerySystemInformation(SystemHandleInformation, phi, handleInfoSize, nullptr);
	
	if (status == STATUS_INFO_LENGTH_MISMATCH || !NT_SUCCESS(status))
	{
		VirtualFree(phi, 0, MEM_RELEASE);
		return;
	}

	//Loop through handles
	for (int i = 0; i < phi->NumberOfHandles; i++)
	{
		SYSTEM_HANDLE_TABLE_ENTRY_INFO sysHandle = phi->Handles[i];
		HANDLE dupHandle = INVALID_HANDLE_VALUE;
		POBJECT_TYPE_INFORMATION pObjectTypeInfo = nullptr;
		PVOID objectNameInfo = nullptr;
		UNICODE_STRING objectName = { 0 };
		ULONG returnLen = 0;

		//Check handle belongs to our given pid
		if (sysHandle.UniqueProcessId != pid)
			continue;

		//Duplicate the handle so we can query it
		if (!NT_SUCCESS(NtDuplicateObject(hProc, (PHANDLE)sysHandle.HandleValue, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
			continue;

		//Query Object type
		pObjectTypeInfo = new OBJECT_TYPE_INFORMATION;
		if (pObjectTypeInfo)
		{
			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, pObjectTypeInfo, 0x1000, 0)))
			{
				CloseHandle(dupHandle);
				continue;
			}

			//Query object name
			
		}
	}
}

//Window Name Check
void GS_Process::EnumWindows()
{
	//Current Window Handle
	HWND hCurWnd = 0;

	//Loop through all open windows
	for (auto hWnd = GetTopWindow(0); hWnd != 0; hWnd = GetNextWindow(hWnd, GW_HWNDNEXT))
	{
		auto WndLen = GetWindowTextLengthA(hWnd);
		if (!WndLen)
			continue; //Filter no Window Text

		char* wndBuffer = new char[WndLen + 1];
		GetWindowTextA(hWnd, wndBuffer, WndLen + 1);

		std::stringstream ss;
		ss << wndBuffer;

		//Loop Vector Blacklist
		for (int i = 0; i < this->vWnd.size(); i++)
		{
			if (strstr(wndBuffer, this->vWnd[i].c_str()))
			{
				this->detectedName = ss.str();
				delete[] wndBuffer;
				this->bWndDetection = true;
				return;
			}
		}
		delete[] wndBuffer;

		//To Do: More specific window detection (For Overlays and so on)

		////Get Windows Information
		/*WINDOWINFO wi = { 0 };*/

		//if (GetWindowInfo(hWnd, &wi))
		//{
		//	//Overlay detection
		//	if (wi.dwExStyle & WS_EX_TOPMOST)
		//		this->bWndDetection = true;

		//	if (wi.dwExStyle & WS_EX_TRANSPARENT && wi.dwExStyle & WS_EX_TOPMOST)
		//		this->bWndDetection = true;

		//	RECT rGame = { 0 };

		//	if (GetWindowRect(GetActiveWindow(), &rGame))
		//	{
		//		float gameWidth = rGame.right - rGame.left;
		//		float gameHeight = rGame.bottom - rGame.top;

		//		float wndWidth = wi.rcWindow.right - wi.rcWindow.left;
		//		float wndHeight = wi.rcWindow.bottom - wi.rcWindow.top;

		//		if (wndWidth == gameWidth && wndHeight == gameHeight)
		//			this->bWndDetection = true;
		//		else if (wndWidth < gameWidth + 5.f && wndHeight < gameHeight + 5.f && wndWidth > gameWidth && wndHeight > gameHeight)
		//			this->bWndDetection = true;
		//		else if (wndWidth > gameWidth - (5.f) && wndHeight > gameHeight - (5.f) && wndWidth < gameWidth && wndHeight < gameHeight)
		//			this->bWndDetection = true;
		//	}
		//}
	}
}