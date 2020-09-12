#pragma once


#define DebugMessage(x, ...) DbgPrintEx(0, 0, x, __VA_ARGS__)

//Prototypes
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject);



//IO Device Object related data
UNICODE_STRING dev;
UNICODE_STRING dos;
PDEVICE_OBJECT pDeviceObject;

//Thread
VOID THMain(PVOID Context);
VOID KillProcess(ULONG PID);
PETHREAD pThreadObject;

//Integrity Flags
BOOLEAN ObProcStillValid, ObThreadStillValid, PsStillValid;

//Killswitch
BOOLEAN Unload;