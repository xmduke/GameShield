#include "Includes.h"

GS_Launcher* Launcher;
GS_VM* VM;
GS_Driver* Driver;
GS_Process* Proc;

bool CheckDriver();
bool CheckProcess();
bool CheckVM();
void Checks();


int main()
{
	Launcher = new GS_Launcher();
	VM = new GS_VM();
	Driver = new GS_Driver();
	Proc = new GS_Process();

	if (Launcher)
	{
		if (Launcher->bIsGameRunning())
		{
			MessageBoxA(0, GSData::GS::MSG::err_Game.c_str(), GSData::GS::MSG::title.c_str(), MB_OK | MB_ICONERROR);
			ExitProcess(1);
		}

		Checks();

		if (!Launcher->InitDriver())
		{
			MessageBoxA(0, GSData::GS::MSG::err_DriverLoad.c_str(), GSData::GS::MSG::title.c_str(), MB_OK | MB_ICONERROR);
			ExitProcess(1);
		}	

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		KeInterface Driver = KeInterface();
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		//Send PID's to driver

		if (!Driver.GetLegitPids())
		{
			Driver.UnloadDriver();
			MessageBoxA(0, GSData::GS::MSG::err_DriverLoad.c_str(), GSData::GS::MSG::title.c_str(), MB_OK | MB_ICONERROR);
			ExitProcess(1);
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(500));

		if (!Launcher->InitService())
		{
			Driver.UnloadDriver();
			MessageBoxA(0, GSData::GS::MSG::err_ServiceLoad.c_str(), GSData::GS::MSG::title.c_str(), MB_OK | MB_ICONERROR);
			ExitProcess(1);
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(500));

		if (!Launcher->InitGame())
		{
			Driver.UnloadDriver();
			MessageBoxA(0, GSData::GS::MSG::err_Launch.c_str(), GSData::GS::MSG::title.c_str(), MB_OK | MB_ICONERROR);
			ExitProcess(1);
		}	

		std::this_thread::sleep_for(std::chrono::milliseconds(500));

		HANDLE hGame = Launcher->GetGameHandle();
		if (hGame == INVALID_HANDLE_VALUE)
		{
			Driver.UnloadDriver();
			MessageBoxA(0, GSData::GS::MSG::err_Client.c_str(), GSData::GS::MSG::title.c_str(), MB_OK | MB_ICONERROR);
			ExitProcess(1);
		}

		std::string sPath = Launcher->GetDirectory();
		sPath.append(GSData::GS::clientPath.c_str());
		std::this_thread::sleep_for(std::chrono::milliseconds(15000));
		if (!ManualMap(hGame, sPath.c_str()))
		{
			TerminateProcess(hGame, 1);
			CloseHandle(hGame);
			Driver.UnloadDriver();
			MessageBoxA(0, GSData::GS::MSG::err_Client.c_str(), GSData::GS::MSG::title.c_str(), MB_OK | MB_ICONERROR);
			ExitProcess(1);
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		Driver.SendInitStatus();
	}

	//Exit Launcher
	ExitProcess(0);
}

void Checks()
{
	char buffer[512] = { 0 };

	if (CheckVM())
	{
		MessageBoxA(0, GSData::GS::MSG::det_VM.c_str(), GSData::GS::MSG::title.c_str(), MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}
	
	if (CheckDriver())
	{
		sprintf_s(buffer, "%s: '%s'", GSData::GS::MSG::det_Driver.c_str(), Driver->detectedDriver.c_str());
		MessageBoxA(0, buffer, GSData::GS::MSG::title.c_str(), MB_OK | MB_ICONEXCLAMATION);
		ExitProcess(1);
	}

	if (CheckProcess())
	{
		if (Proc->detectedProc.size())
			sprintf_s(buffer, "%s: '%s'", GSData::GS::MSG::det_App.c_str(), Proc->detectedProc.c_str());
		else
			sprintf_s(buffer, "%s: '%s'", GSData::GS::MSG::det_App.c_str(), Proc->detectedWnd.c_str());
		
		MessageBoxA(0, buffer, GSData::GS::MSG::title.c_str(), MB_OK | MB_ICONEXCLAMATION);
		ExitProcess(1);
	}
}


bool CheckDriver()
{
	Driver->EnumDrivers();
	return Driver->bIsDriverDetected;
}


bool CheckProcess()
{
	Proc->CheckBlacklisted();
	Proc->CheckWindowNames();
	return Proc->bProcDetection;
}


bool CheckVM()
{
	VM->CheckVMGeneral();
	VM->CheckVMServices();
	return VM->bIsVM;
}
