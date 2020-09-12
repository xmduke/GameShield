#pragma once

class GS_Module
{

private:


public:

	GS_Module();
	~GS_Module();

	void EnumModules();
	bool InitializeHooks();

	//RtlCreateUserThread Hook (Detect Threads from manual mapped modules)
	tRtlCreateUserThread oRtlCreateUserThread;
	BYTE* CreateThreadAddr;

	//CreateThread Hook
	tCreateThread oCreateThread;
	BYTE* RtlCreatUserThreadAddr;

	tLdrLoadDll oLdrLoadDll;
	BYTE* LdrLoadDllAddr;

	tGetThreadContext oGetThreadContext;
	BYTE* GetThreadContextAddr;

	tSetThreadContext oSetThreadContext;
	BYTE* SetThreadContextAddr;

	//Hook Integrity Checking
	BYTE* buffer_hook1; //RtlCreateUserThread
	BYTE* buffer_hook2; //CreateThread

	BYTE* hookBytes;

	std::string sModule;

	bool bIsModDetected;
	//MD5 Module Whitelist
	std::vector<std::string> vMd5Module;
};