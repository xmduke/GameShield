#pragma warning (disable : 4459)

#include "Includes.h"


NTSTATUS IoControl(PDEVICE_OBJECT pDeviceObject, PIRP pIRP)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG ByteIO = 0;

	//Setup Stack
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIRP);
	ULONG CodeIO = pStack->Parameters.DeviceIoControl.IoControlCode;

	//Check for IO codes
	if (CodeIO == IO_REQUEST_PIDS)
	{
		//Get PID of first CSRSS Process
		PPROCDATA ReadInput = (PPROCDATA)pIRP->AssociatedIrp.SystemBuffer;
		DebugMessage("PID's received\n");

		if (ReadInput->Services)
			ServicesPID = ReadInput->Services; //Service Manager
		if (ReadInput->Steam)
			SteamPID = ReadInput->Steam;
		if (ReadInput->Launcher)
			LauncherPID = ReadInput->Launcher;
		if (ReadInput->CSRSS)
			CSRSS1PID = ReadInput->CSRSS; //Assign first csrss pid
		if (ReadInput->CSRSS2)
			CSRSS2PID = ReadInput->CSRSS2; //Assign second csrss pid

		DebugMessage("PIDS: %d %d %d %d %d", ServicesPID, SteamPID, LauncherPID, CSRSS1PID, CSRSS2PID);
		status = STATUS_SUCCESS;
	}
	else if (CodeIO == IO_REQUEST_INITIALIZED)
	{
		DebugMessage("Init\n");
		IsInit = FALSE;
		status = STATUS_SUCCESS;
	}
	else if (CodeIO == IO_REQUEST_UNLOAD)
	{
		status = STATUS_SUCCESS;
		UNICODE_STRING DriverName = { 0 };
		RtlInitUnicodeString(&DriverName, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\GameShield");
		ZwUnloadDriver(&DriverName);
	}
	else
	{
		ByteIO = 0;
		status = STATUS_SUCCESS;
	}

	pIRP->IoStatus.Status = status;
	pIRP->IoStatus.Information = ByteIO;
	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return status;
}


NTSTATUS IoCloseCall(PDEVICE_OBJECT pDeviceObject, PIRP pIRP)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	pIRP->IoStatus.Status = STATUS_SUCCESS;
	pIRP->IoStatus.Information = 0;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS IoCreateCall(PDEVICE_OBJECT pDeviceObject, PIRP pIRP)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	pIRP->IoStatus.Status = STATUS_SUCCESS;
	pIRP->IoStatus.Information = 0;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}