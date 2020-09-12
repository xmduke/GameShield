#pragma once
class GS_Process
{
public:

	//Memberfunctions
	GS_Process();
	~GS_Process();

	void CheckWindowNames();
	void CheckBlacklisted();
	
	//Handle Check


	//Memory Scan with NtQueryVirtualMemory

	//Membervariables
	std::vector<std::string> vWnd; //Blacklisted Window Names
	std::vector<std::string> vProcName;
	std::vector<std::string> vMd5Process;
	void* procMem;

	//Detection
	bool bProcDetection;
	std::string detectedWnd;
	std::string detectedProc;
};
