#pragma warning (disable : 4024 4311 4022 4047 4100 4706 4189)

#include "Includes.h"

//Callback function (strips process handle access to game & service process)
OB_PREOP_CALLBACK_STATUS ObjectPreCallbackProcess(PVOID pRegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInfo)
{
	UNREFERENCED_PARAMETER(pRegistrationContext);
	//Check if PID'S are valid
	if (!ServicePID || !CSRSS1PID || !CSRSS2PID || !LauncherPID || !SteamPID || !ServicesPID)
		return OB_PREOP_SUCCESS;

	//Current Process Information
	PEPROCESS pTargetProcess = (PEPROCESS)pOperationInfo->Object; //The process or thread object that is the target of the handle operation
	ULONG TargetProcessPID = (ULONG)PsGetProcessId(pTargetProcess);

	ULONG RequesterProcessID = (ULONG)PsGetCurrentProcessId();

	//Avoid striping csrss.exe handle
	if (TargetProcessPID == CSRSS1PID || TargetProcessPID == CSRSS2PID)
		return OB_PREOP_SUCCESS;

	if (RequesterProcessID == CSRSS1PID || RequesterProcessID == CSRSS2PID)
		return OB_PREOP_SUCCESS;

	//Allow Driver to get a handle
	if (pOperationInfo->KernelHandle)
		return OB_PREOP_SUCCESS;

	//Service Striping
	if (TargetProcessPID == ServicePID) //If the target of the handle operation is our service then strip handle access
	{
		if (!IsInit)
		{
			if (RequesterProcessID == ServicesPID) //Allow Service Manager to access our service
				return OB_PREOP_SUCCESS;
		}

		if (pOperationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
			pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
		else
			pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
	}
	else if (GameProcID) //If Game PID is Valid
	{
		if (TargetProcessPID == GameProcID)
		{
			if (RequesterProcessID == GameProcID) //Let game open handle to itself
				return OB_PREOP_SUCCESS;

			if (!IsInit)
			{
				if (RequesterProcessID == SteamPID || RequesterProcessID == LauncherPID)
					return OB_PREOP_SUCCESS;
			}

			if (pOperationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_ALL_ACCESS;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
			}
			else
			{
				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_ALL_ACCESS;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;

			}
		}
	}

	//Cleanup
	return OB_PREOP_SUCCESS;
}

//Callback function (strips thread handle access to game & service process)
OB_PREOP_CALLBACK_STATUS ObjectPreCallbackThread(PVOID pRegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInfo)
{
	UNREFERENCED_PARAMETER(pRegistrationContext);
	//Check if PID'S are valid
	if (!ServicePID || !CSRSS1PID || !CSRSS2PID || !LauncherPID || !SteamPID || !ServicesPID)
		return OB_PREOP_SUCCESS;

	//Current Process and Thread Information
	PETHREAD pTargetThread = (PETHREAD)pOperationInfo->Object; //Target Thread of the handle operation
	PEPROCESS pTargetProcess = IoThreadToProcess(pTargetThread); //Get the EPROCESS ptr of the thread's process
	ULONG TargetProccesID = (ULONG)PsGetProcessId(pTargetProcess);

	//Requester Process and Thread Information
	PETHREAD pRequesterThread = PsGetCurrentThread(); //Requesters ETHREAD ptr
	PEPROCESS pRequesterProcess = IoThreadToProcess(pRequesterThread); //Get the EPROCESS ptr of the thread's process
	ULONG RequesterProcessPID = (ULONG)PsGetProcessId(pRequesterProcess);

	//Check if csrss.exe requested the handle operation
	if (RequesterProcessPID == CSRSS1PID || RequesterProcessPID == CSRSS2PID)
		return OB_PREOP_SUCCESS;

	//Allow Driver to get a handle
	if (pOperationInfo->KernelHandle)
		return OB_PREOP_SUCCESS;

	//Service Striping
	if (TargetProccesID == ServicePID) //If the target of the handle operation is our service then strip handle access
	{
		if (!IsInit)
		{
			if (RequesterProcessPID == ServicesPID) //Allow Service Manager to access our service
				return OB_PREOP_SUCCESS;
		}

		if (pOperationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
			pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
		else
			pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
	}	
	else if (GameProcID) //If the target of the handle operation is our game then strip handle access
	{
		if (TargetProccesID == GameProcID)
		{
			if (RequesterProcessPID == GameProcID)
				return OB_PREOP_SUCCESS;

			if (!IsInit)
			{
				if (RequesterProcessPID == SteamPID || RequesterProcessPID == LauncherPID) //Allow steam & Launcher to access game
					return OB_PREOP_SUCCESS;
			}

			if (pOperationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_ALL_ACCESS;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_SUSPEND_RESUME) == THREAD_SUSPEND_RESUME)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_TERMINATE) == THREAD_TERMINATE)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_SET_INFORMATION) == THREAD_SET_INFORMATION)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_INFORMATION;
			}
			else
			{
				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_ALL_ACCESS;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_SUSPEND_RESUME) == THREAD_SUSPEND_RESUME)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_TERMINATE) == THREAD_TERMINATE)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_SET_INFORMATION) == THREAD_SET_INFORMATION)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SET_INFORMATION;
			}
		}
	}

	//Cleanup
	return OB_PREOP_SUCCESS;
}

//Register Callbacks
NTSTATUS RegisterCallbackFunction(BOOLEAN ObProcess)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING Altitude;

	OB_OPERATION_REGISTRATION RegisterOperation;
	OB_CALLBACK_REGISTRATION RegisterCallback;
	REG_CONTEXT RegistrationContext;
	RegistrationContext.ulIndex = 1;
	RegistrationContext.Version = 120;

	RtlSecureZeroMemory(&RegisterOperation, sizeof(OB_OPERATION_REGISTRATION));
	RtlSecureZeroMemory(&RegisterCallback, sizeof(OB_CALLBACK_REGISTRATION));
	RtlSecureZeroMemory(&RegistrationContext, sizeof(REG_CONTEXT));

	if ((USHORT)ObGetFilterVersion() == OB_FLT_REGISTRATION_VERSION)
	{
		if (ObProcess)
		{
			RtlInitUnicodeString(&Altitude, L"ProcessPre");
			RegisterOperation.ObjectType = PsProcessType;
			RegisterOperation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
			RegisterOperation.PreOperation = ObjectPreCallbackProcess;
			RegisterOperation.PostOperation = NULL;

			RegisterCallback.Version = OB_FLT_REGISTRATION_VERSION;
			RegisterCallback.OperationRegistrationCount = (USHORT)1;
			RegisterCallback.Altitude = Altitude;
			RegisterCallback.RegistrationContext = &RegistrationContext;
			RegisterCallback.OperationRegistration = &RegisterOperation;

			//Register Callback
			status = ObRegisterCallbacks(&RegisterCallback, &pObProcHandle);
		}
		else
		{
			RtlInitUnicodeString(&Altitude, L"ThreadPre");
			RegisterOperation.ObjectType = PsThreadType;
			RegisterOperation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
			RegisterOperation.PreOperation = ObjectPreCallbackThread;
			RegisterOperation.PostOperation = NULL;

			RegisterCallback.Version = OB_FLT_REGISTRATION_VERSION;
			RegisterCallback.OperationRegistrationCount = (USHORT)1;
			RegisterCallback.Altitude = Altitude;
			RegisterCallback.RegistrationContext = &RegistrationContext;
			RegisterCallback.OperationRegistration = &RegisterOperation;

			//Register Callback
			status = ObRegisterCallbacks(&RegisterCallback, &pObThreadHandle);
		}
	}

	return status;
}

//Remove Callbacks (Cleanup)
NTSTATUS UnRegisterCallbackFunction(BOOLEAN ObProcess)
{
	if (ObProcess)
	{
		//Unregister ObRgisterCallbacks for PsProcessType
		if (pObProcHandle)
		{
			ObUnRegisterCallbacks(pObProcHandle);
			pObProcHandle = NULL;
		}
	}
	else
	{
		//Unregister ObRgisterCallbacks for PsThreadType
		if (pObThreadHandle)
		{
			ObUnRegisterCallbacks(pObThreadHandle);
			pObThreadHandle = NULL;
		}
	}

	return STATUS_SUCCESS;
}


//Create Process Callback Routine (get game & service process pid's)
PCREATE_PROCESS_NOTIFY_ROUTINE_EX ProcessNotifyCallbackEx(HANDLE parentID, HANDLE processID, PPS_CREATE_NOTIFY_INFO notifyInfo)
{
	//Check for valid Notify info data
	if (notifyInfo)
	{
		if (wcsstr(notifyInfo->ImageFileName->Buffer, L"\\csgo.exe"))
			GameProcID = (ULONG)processID;

		if (wcsstr(notifyInfo->ImageFileName->Buffer, L"\\GS_Service.exe"))
			ServicePID = (ULONG)processID;
	}
	return STATUS_SUCCESS;
}