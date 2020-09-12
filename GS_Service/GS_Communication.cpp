/*
Used to communicate with the driver and client.
Information from the driver and client will be retrieved
and maybe sent to the remote server in order to detect certain events.
*/

#include "Includes.h"



GS_Communication::GS_Communication()
{
	this->drvStillAlive = true;
}

GS_Communication::~GS_Communication()
{
	//Init IOCTL
	CloseHandle(hDriver);
	delete this;
}

//Driver Communication (IOCTL)
void GS_Communication::UnloadDriver()
{
	//Init IOCTL
	this->hDriver = CreateFileA("\\\\.\\GameShield", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (this->hDriver == INVALID_HANDLE_VALUE)
		return;

	DWORD Bytes = 0;
	DeviceIoControl(hDriver, IO_REQUEST_UNLOAD, nullptr, 0, nullptr, 0, &Bytes, 0);
}

void GS_Communication::DriverHeartbeat()
{
	HEARTBEAT HeartbeatData = { 0 };
	DWORD Bytes = 0;
	HeartbeatData.ObCallbacks = FALSE;
	HeartbeatData.PsCallbacks = FALSE;
	HeartbeatData.SenderPID = GetCurrentProcessId();
	this->drvStillAlive = false;

	if (DeviceIoControl(hDriver, IO_REQUEST_HEARTBEAT, &HeartbeatData, sizeof(HeartbeatData), &HeartbeatData, sizeof(HeartbeatData), &Bytes, nullptr))
	{
		if (HeartbeatData.ObCallbacks && HeartbeatData.PsCallbacks)
			this->drvStillAlive = true;
	}
}