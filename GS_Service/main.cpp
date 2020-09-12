#include "Includes.h"

//Service related
#define SVCNAME TEXT("GSService")
#define SVC_ERROR ((DWORD)0xC0020001L)

SERVICE_STATUS			gSvcStatus;
SERVICE_STATUS_HANDLE	gSvcStatusHandle;;

//Service Prototypes
VOID WINAPI SvcCtrlHandler(DWORD dwCtrl); //Service Callback Function
VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv);
VOID SvcReportEvent(LPTSTR szFunction);
VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
DWORD GetCurrentSessionId();


bool IsGameRunning();

//Objects
GS_Communication* Com;

//Process Entry Point
int __cdecl main(int argc, TCHAR* argv[])
{
	Com = new GS_Communication();

	SERVICE_TABLE_ENTRY DispatchTable[] =
	{
		{ (LPSTR)SVCNAME, (LPSERVICE_MAIN_FUNCTION)SvcMain },
		{ NULL, NULL }
	};

	if(!StartServiceCtrlDispatcher(DispatchTable))
		SvcReportEvent((LPTSTR("StartServiceCtrlDispatcher")));
}


bool IsGameRunning()
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bool bIsRunning = false;
	if (hSnap == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);

	if (Process32First(hSnap, &procEntry))
	{
		do
		{
			if (_strcmpi(procEntry.szExeFile, GSData::Game::szGameExe) == 0)
				bIsRunning = true;

		} while (Process32Next(hSnap, &procEntry));
	}

	CloseHandle(hSnap);
	return bIsRunning;
}


//Service Entry Point
VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
	//Register the handler function for the service
	gSvcStatusHandle = RegisterServiceCtrlHandler(SVCNAME, SvcCtrlHandler);

	//Tel SCM that we are up and running
	gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	gSvcStatus.dwServiceSpecificExitCode = 0;
	gSvcStatus.dwCurrentState = SERVICE_RUNNING;
	gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);


	while (!IsGameRunning())
		Sleep(25);

	while (1)
	{
		if (!IsGameRunning())
			break;

		Sleep(500);
	}

	//Unload Driver Signal
	Com->UnloadDriver();

	//Tell SCM to stop service
	gSvcStatus.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

//Set the current service status and report it to the SCM
VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;

	// Fill in the SERVICE_STATUS structure.

	gSvcStatus.dwCurrentState = dwCurrentState;
	gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
	gSvcStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		gSvcStatus.dwControlsAccepted = 0;
	else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	if ((dwCurrentState == SERVICE_RUNNING) ||
		(dwCurrentState == SERVICE_STOPPED))
		gSvcStatus.dwCheckPoint = 0;
	else gSvcStatus.dwCheckPoint = dwCheckPoint++;

	// Report the status of the service to the SCM.
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

//Callback for Service (receive commands)
VOID WINAPI SvcCtrlHandler(DWORD dwCtrl)
{
	//Handle the requested control code
	switch (dwCtrl)
	{
	case SERVICE_CONTROL_STOP:
	{
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
		ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);
		return;
	}

	case SERVICE_CONTROL_INTERROGATE:
		break;

	default:
		break;
	}
}


VOID SvcReportEvent(LPTSTR szFunction)
{
	HANDLE hEventSource;
	LPCTSTR lpszStrings[2];
	TCHAR Buffer[80];

	hEventSource = RegisterEventSource(NULL, SVCNAME);

	if (NULL != hEventSource)
	{
		StringCchPrintf(Buffer, 80, TEXT("%s failed with %d"), szFunction, GetLastError());

		lpszStrings[0] = SVCNAME;
		lpszStrings[1] = Buffer;

		ReportEvent(hEventSource,        // event log handle
			EVENTLOG_ERROR_TYPE, // event type
			0,                   // event category
			SVC_ERROR,           // event identifier
			NULL,                // no security identifier
			2,                   // size of lpszStrings array
			0,                   // no binary data
			lpszStrings,         // array of strings
			NULL);               // no binary data

		DeregisterEventSource(hEventSource);
	}
}

// Determine the session ID of the currently logged-on user
DWORD GetCurrentSessionId()
{
	WTS_SESSION_INFO* pSessionInfo;
	DWORD n_sessions = 0;
	BOOL ok = WTSEnumerateSessions(WTS_CURRENT_SERVER, 0, 1, &pSessionInfo, &n_sessions);
	if (!ok)
		return 0;

	DWORD SessionId = 0;

	for (DWORD i = 0; i < n_sessions; ++i)
	{
		if (pSessionInfo[i].State == WTSActive)
		{
			SessionId = pSessionInfo[i].SessionId;
			break;
		}
	}

	WTSFreeMemory(pSessionInfo);
	return SessionId;
}