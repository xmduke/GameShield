/*
//GameShield Anti Cheat developed by MrSn0w

Purpoose:
Entry point and initialize routins.
*/

#include "Includes.h"


//Class Objects
GS_AntiDebug* AntiDebug;
GS_Exit* Exit;
GS_Module* Module;
GS_Integrity* Integrity;
GS_Process* Proc;
GS_Driver* Driver;

_Log Log;

//Suspended Hearbeat
tNtQueryInformationThread NtQueryInformationThread;

//Initialization
void Initialize();

//Prototypes
void CreateLog();
void GS_Mod();
void GS_Debug();
void GS_Watchdog();
void GS_General();
void ThreadCreation();


//Dll Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpr)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		Initialize();
		DisableThreadLibraryCalls(hModule);
		break;

	case DLL_PROCESS_DETACH:
		FreeLibraryAndExitThread(hModule, 0);
		break;

	default:
		break;
	}
	return TRUE;
}


//Main Thread
void Initialize()
{
	//Initializing Heap
	AntiDebug = new GS_AntiDebug();
	Exit = new GS_Exit();
	Module = new GS_Module();
	Driver = new GS_Driver();
	Proc = new GS_Process();
	
	Integrity = new GS_Integrity();

	//Check if Client does not run in the context of the game process
	char buffer[MAX_PATH] = { 0 };
	if (GetModuleBaseNameA(GetCurrentProcess(), 0, buffer, sizeof(buffer)))
	{
		if (_stricmp(buffer, _xor_("csgo.exe").c_str()))
			GSData::Func::myExitProcess(1);
	}

	std::this_thread::sleep_for(std::chrono::milliseconds(3000));

	Integrity->AntiTamper();
	if(Integrity->bIsTampered)
		GSData::Func::myExitProcess(1);

	ThreadCreation();

	//Initialize Hooks and gather image information
	if (!Module->InitializeHooks() || !Integrity->GetClientImageInfo() || !Integrity->GetEngineImageInfo())
	{
		MessageBoxA(0, _xor_("Could not initialize GameShield").c_str(), _xor_("Error").c_str(), MB_OK | MB_ICONERROR);
		GSData::Func::myExitProcess(1);
	}

	NtQueryInformationThread = reinterpret_cast<tNtQueryInformationThread>(GetProcAddress(GetModuleHandleA(_xor_("ntdll.dll").c_str()), _xor_("NtQueryInformationThread").c_str()));

	if (Integrity->hTH1 && Integrity->hTH2 && Integrity->hTH3 && Integrity->hTH4)
	{
		//Hide Threads
		Integrity->HideThreads();

		//Resume Thread's
		tResumeThread myResumeThread = reinterpret_cast<tResumeThread>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("ResumeThread").c_str()));

		myResumeThread(Integrity->hTH1);
		myResumeThread(Integrity->hTH2);
		myResumeThread(Integrity->hTH3);
		myResumeThread(Integrity->hTH4);
	}
	else
	{
		Exit->Detection();
		GSData::Func::myExitProcess(1);
	}
}


void ThreadCreation()
{
	//Resolve CreateThread
	tCreateThread myCreateThread = reinterpret_cast<tCreateThread>(GetProcAddress(GetModuleHandleA(_xor_("kernel32.dll").c_str()), _xor_("CreateThread").c_str()));

	if (myCreateThread)
	{
		//Start AntiCheat Threads
		Integrity->hTH1 = myCreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(GS_Mod), 0, CREATE_SUSPENDED, &Integrity->ID_TH1);
		Integrity->hTH2 = myCreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(GS_Debug), 0, CREATE_SUSPENDED, &Integrity->ID_TH2);
		Integrity->hTH3 = myCreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(GS_Watchdog), 0, CREATE_SUSPENDED, &Integrity->ID_TH3);
		Integrity->hTH4 = myCreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(GS_General), 0, CREATE_SUSPENDED, &Integrity->ID_TH4);
	}
}

void GS_General() //Works (kinda)
{
	int counter = 0;
	while (1)
	{
		//Check TH3 Suspended
		DWORD countTH3 = 0;
		NtQueryInformationThread(Integrity->hTH3, (THREAD_INFORMATION_CLASS)ThreadSuspendCount, &countTH3, sizeof(DWORD), 0);

		if (countTH3 != 0)
			Integrity->bIsThreadSuspended = true;

		Integrity->EnumThread();

		if (counter == 2) //10s
		{
			Driver->EnumDrivers();
			Proc->EnumProc();
			Proc->EnumWindows();
			counter = 0;
		}

		if (Integrity->bIsThreadTerminated || Integrity->bIsThreadSuspended || Driver->bIsDriverDetected || Proc->bProcDetection || Proc->bWndDetection)
		{
			if (Driver->bIsDriverDetected)
			{
				Log.msgCode = DRIVER_BLACKLISTED;
				Log.extraInfo = Driver->detectedDriver.c_str();
				CreateLog();
			}
			else if (Proc->bProcDetection || Proc->bWndDetection)
			{
				Log.msgCode = PROGRAM_SUSPICIOUS;
				Log.extraInfo = Proc->detectedName.c_str();
				CreateLog();
			}
			else
			{
				Log.msgCode = INTEGRITY_VIOLATION;
				Log.extraInfo = Proc->detectedName.c_str();
				CreateLog();
			}

			Exit->Detection();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(5000));
		counter++;
	}
}



void GS_Mod() //Works
{
	int counter = 0;
	while (1)
	{
		Integrity->EnumThread();

		//Check TH2 Suspended
		DWORD countTH2 = 0;
		NtQueryInformationThread(Integrity->hTH2, (THREAD_INFORMATION_CLASS)ThreadSuspendCount, &countTH2, sizeof(DWORD), 0);

		if (countTH2 != 0)
			Integrity->bIsThreadSuspended = true;

		if (counter == 2) //10s
		{
			Module->EnumModules();
			counter = 0;
		}

		if (Module->bIsModDetected || Integrity->bIsThreadTerminated || Integrity->bIsThreadSuspended)
		{
			if (Integrity->bIsThreadTerminated || Integrity->bIsThreadSuspended)
			{
				Log.msgCode = INTEGRITY_VIOLATION;
				CreateLog();
			}
			else
			{
				Log.msgCode = MODULE_SUSPICIOUS;
				if (Module->sModule.size())
					Log.extraInfo = Module->sModule.c_str();

				CreateLog();
			}

			Exit->Detection();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(5000));
		counter++;
	}
}

void GS_Debug()
{
	int counter = 0;
	while (1)
	{
		Integrity->EnumThread();

		//Check TH1 Suspended
		DWORD countTH1 = 0;
		NtQueryInformationThread(Integrity->hTH1, (THREAD_INFORMATION_CLASS)ThreadSuspendCount, &countTH1, sizeof(DWORD), 0);

		if (countTH1 != 0)
			Integrity->bIsThreadSuspended = true;

		//AntiDebugging
		if (counter == 2) //10s
		{
			AntiDebug->DetectionGeneral();
			AntiDebug->DetectionAdvanced();
			AntiDebug->DetectionVEH();
			counter = 0;
		}

		if (AntiDebug->bIsDebugger || AntiDebug->bIsVEH || Integrity->bIsThreadTerminated || Integrity->bIsThreadSuspended)
		{
			if (Integrity->bIsThreadTerminated || Integrity->bIsThreadSuspended)
			{
				Log.msgCode = INTEGRITY_VIOLATION;
				CreateLog();
			}
			else
			{
				Log.msgCode = DEBUGGER_PRESENT;
				CreateLog();
			}

			Exit->Detection();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(5000));
		counter++;
	}
}

void GS_Watchdog()
{
	int counter = 0;
	while (1)
	{
		Integrity->EnumThread();

		//Check TH4 Suspended
		DWORD countTH4 = 0;
		NtQueryInformationThread(Integrity->hTH4, (THREAD_INFORMATION_CLASS)ThreadSuspendCount, &countTH4, sizeof(DWORD), 0);

		if (countTH4 != 0)
			Integrity->bIsThreadSuspended = true;

		//Hook Checking
		if (counter == 2) //10s
		{
			Integrity->CheckIAT();
			Integrity->AntiTamper();
			Integrity->ChecksumIntegrity();
			counter = 0;
		}

		if (Integrity->bIsThreadTerminated || Integrity->bIsThreadSuspended || Integrity->bIsTampered)
		{
			Log.msgCode = INTEGRITY_VIOLATION;
			CreateLog();
			Exit->Detection();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(5000));
		counter++;
	}
}


void CreateLog()
{
	std::ofstream ofs;
	ofs.open(_xor_("GameShield\\Log.gs").c_str(), std::ios::binary);

	if (ofs.fail())
		return;

	ofs.write((char*)&Log, sizeof(Log));
	ofs.close();
}