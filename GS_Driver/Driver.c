#pragma warning (disable : 4024 6011 4047 4152)

#include "Includes.h"


//Driver Entry Point
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	//Init Vars
	GameProcID = 0;
	ServicePID = 0;
	LauncherPID = 0;
	SteamPID = 0;
	ServicesPID = 0;

	IsInit = FALSE;
	Unload = FALSE;
	ObThreadStillValid = TRUE;
	ObProcStillValid = TRUE;
	PsStillValid = TRUE;

	//Create Process Notify Callback
	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);

	//Setup ObCallbacks
	RegisterCallbackFunction(TRUE); //Process
	RegisterCallbackFunction(FALSE); //Threads

	//Init device object strings
	RtlInitUnicodeString(&dev, L"\\Device\\GameShield");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\GameShield");

	//Create Device Object
	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	//Assign IO functions
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = IoCreateCall;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = IoCloseCall;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	pDriverObject->DriverUnload = DriverUnload;

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	//Setup Main System Thread
	HANDLE hThread = NULL;
	if (PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, (PKSTART_ROUTINE)THMain, pDeviceObject) == STATUS_SUCCESS)
	{
		//Convert thread object handle into a pointer the thread object and close the handle afterwards
		ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &pThreadObject, NULL);
		ZwClose(hThread);
	}

	return STATUS_SUCCESS;
}

//Driver Unload Routine
NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	Unload = TRUE; //Set Unload Flag (for threads)
	//Wait until thread finished
	KeWaitForSingleObject(pThreadObject, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject(pThreadObject);

	//If game is still running for some reason, kill it.
	PEPROCESS pGame = NULL;
	if (PsLookupProcessByProcessId((HANDLE)GameProcID, &pGame) == STATUS_SUCCESS)
	{
		if (pGame) //Game Process still alive
			KillProcess(GameProcID);
	}

	UNREFERENCED_PARAMETER(pDriverObject); //Unused parameter

	//Clean Device Object
	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);

	//Remove Process Notify Callback
	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);

	UnRegisterCallbackFunction(TRUE); //For Process
	UnRegisterCallbackFunction(FALSE); //For Threads

	return STATUS_SUCCESS;
}


VOID KillProcess(ULONG PID)
{
	HANDLE hProc = NULL;
	OBJECT_ATTRIBUTES objA = { 0 };
	CLIENT_ID cid = { 0 };

	cid.UniqueProcess = PID;
	cid.UniqueThread = NULL;
	InitializeObjectAttributes(&objA, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	if (ZwOpenProcess(&hProc, PROCESS_ALL_ACCESS, &objA, &cid) == STATUS_SUCCESS)
		ZwTerminateProcess(hProc, STATUS_SUCCESS);
}

//Main System Thread (Purpose: Protection, Integrity...)
VOID THMain(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);

	LARGE_INTEGER delay = { 0 };
	delay.QuadPart = -1 * (100000);

	while (1)
	{
		if (Unload)
			PsTerminateSystemThread(STATUS_SUCCESS);

		//Validate created ObRegisterCallbacks
		if (RegisterCallbackFunction(TRUE) != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
		{
			ObProcStillValid = FALSE;
			KillProcess(GameProcID);
		}
		
		if (RegisterCallbackFunction(FALSE) != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
		{
			ObThreadStillValid = FALSE;
			KillProcess(GameProcID);
		}
	
		//Sleep
		KeDelayExecutionThread(KernelMode, FALSE, &delay);
	}
}
