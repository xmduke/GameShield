#pragma once

struct CSGOIMAGE
{
	//Image in Memory
	PVOID pVirtualAddress;
	PVOID pEntryPoint;
	PVOID pCodeStart; //Start of .text
	PVOID pCodeEnd; //End of .text
	SIZE_T dwCodeSize; //Size of .text
};

class GS_Integrity
{

private:

	//Image Info (client.dll & engine.dll)
	CSGOIMAGE ClientDll;
	CSGOIMAGE EngineDll;

public:

	GS_Integrity();
	~GS_Integrity();

	BYTE* WinFuncs[8];
	BYTE* gsFuncs[25]; //Own Functions

	std::string clientPath;
	bool bIsTampered;

	//Thread Integrity
	void HideThreads();
	void EnumThread();

	HANDLE hTH1, hTH2, hTH3, hTH4;
	DWORD ID_TH1, ID_TH2, ID_TH3, ID_TH4;

	//Thread Handles
	HANDLE hGSProc;
	HANDLE hGSModule;

	//Integrity Flags
	bool bIsThreadTerminated;
	bool bIsThreadSuspended;

	//Hook Integrity
	void AntiTamper();

	//Anti Hooking
	void CheckIAT();
	PEB* GetPebInternal();

	//Memory Integrity
	std::string ClientDllHash, EngineDllHash;

	void ChecksumIntegrity();

	bool GetEngineImageInfo();
	bool GetClientImageInfo();
};
