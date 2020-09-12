#pragma once
class GS_Process
{

private:

	std::vector<std::string> vWnd; //Blacklisted Window Names
	std::vector<std::string> vProcName;
	std::vector<std::string> vMd5Process;
	void* procMem;

public:

	//Memberfunctions
	GS_Process();
	~GS_Process();

	void EnumWindows();

	void EnumProc();
	void EnumHandles();
	
	//Handle Check


	//Memory Scan with NtQueryVirtualMemory

	//Detection
	bool bProcDetection;
	bool bWndDetection;
	std::string detectedName;
};
