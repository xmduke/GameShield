#include "Includes.h"



GS_Process::~GS_Process()
{
	delete this;
}


GS_Process::GS_Process()
{
	this->bProcDetection = false;
	this->procMem = 0;

	//Process Blacklist Initializing
	this->vWnd.push_back(_xor_("IDA"));
	this->vWnd.push_back(_xor_("x32dbg")); //x64 & x32-dbg
	this->vWnd.push_back(_xor_("x64dbg")); //x64 & x32-dbg
	this->vWnd.push_back(_xor_("Olly")); //OllyDbg
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


void GS_Process::CheckBlacklisted()
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
					this->detectedProc = sProc;
					return;
				}
			}

			//Hash Blacklist
			HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procEntry.th32ProcessID);
			TCHAR fPath[MAX_PATH];
			ZeroMemory(fPath, MAX_PATH);
			if (hProc != INVALID_HANDLE_VALUE)
			{
				if (GetModuleFileNameEx(hProc, 0, fPath, MAX_PATH))
				{
					//Check Hash
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

					for (UINT i = 0; i < this->vMd5Process.size(); i++)
					{
						if (this->vMd5Process[i].compare(hash) == 0) //if Blacklisted
						{
							this->bProcDetection = true;
							this->detectedProc = sProc;
							delete[] buffer;
							processMd5.close();
							return;
						}
					}
					delete[] buffer;
					processMd5.close();
				}
				CloseHandle(hProc);
			}

		} while (Process32Next(hSnap, &procEntry));
	}
}



//Window Name Check
void GS_Process::CheckWindowNames() //Is Working
{
	//Current Window Handle
	HWND hCurWnd = 0;
	char* WndTxt = nullptr;

	//Loop through all open windows
	for (HWND hWnd = GetTopWindow(0); hWnd != 0; hWnd = GetNextWindow(hWnd, GW_HWNDNEXT))
	{
		int WndLen = GetWindowTextLength(hWnd);
		if (!WndLen)
			continue; //Filter no Window Text
		

		WndTxt = new char[WndLen + 1]; //+1 for Null-Terminator
		GetWindowTextA(hWnd, WndTxt, WndLen + 1);

		//Convert to String
		std::stringstream sWnd;
		sWnd << WndTxt;
		std::string sWndName = sWnd.str();

		//Loop Vector Blacklist
		for (UINT i = 0; i < this->vWnd.size(); i++)
		{
			auto strPos = sWndName.find(this->vWnd[i], 0);

			if (strPos != std::string::npos)
			{
				this->bProcDetection = true; //Not Allowed Window detected
				this->detectedWnd = sWndName;
				delete[] WndTxt;
				return;
			}
		}

		delete[] WndTxt; //Cleanup
	}
}