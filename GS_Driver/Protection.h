#pragma once

//Process Security and Access Rights
#define PROCESS_CREATE_THREAD			  0x0002
#define PROCESS_CREATE_PROCESS			  0x0080
#define PROCESS_TERMINATE				  0x0001
#define PROCESS_VM_WRITE				  0x0020
#define PROCESS_VM_READ					  0x0010
#define PROCESS_VM_OPERATION			  0x0008
#define PROCESS_SUSPEND_RESUME			  0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

//Callback
PVOID pObProcHandle, pObThreadHandle;

typedef struct _OB_REG_CONTEXT {
	__in USHORT Version;
	__in UNICODE_STRING Altitude;
	__in USHORT ulIndex;
	OB_OPERATION_REGISTRATION* OperationRegistration;
} REG_CONTEXT, * PREG_CONTEXT;


//Process Notify Routine Data
PCREATE_PROCESS_NOTIFY_ROUTINE_EX ProcessNotifyCallbackEx(HANDLE parentID, HANDLE processID, PPS_CREATE_NOTIFY_INFO notifyInfo);
ULONG CSRSS1PID, CSRSS2PID, LauncherPID, ServicePID, GameProcID, SteamPID, ServicesPID; //PID's
BOOLEAN IsInit;

//Prototypes for ObCallbacks
OB_PREOP_CALLBACK_STATUS ObjectPreCallbackProcess(PVOID pRegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInfo);
OB_PREOP_CALLBACK_STATUS ObjectPreCallbackThread(PVOID pRegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInfo);
NTSTATUS RegisterCallbackFunction(BOOLEAN ObProcess);
NTSTATUS UnRegisterCallbackFunction(BOOLEAN ObProcess);