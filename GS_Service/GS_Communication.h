#pragma once


class GS_Communication
{
private:
	HANDLE hDriver;


#define IO_REQUEST_PIDS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85100000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQUEST_INITIALIZED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85200000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQUEST_HEARTBEAT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85300000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQUEST_UNLOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x85400000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

	typedef struct _HEARTBEAT
	{
		BOOLEAN PsCallbacks;
		BOOLEAN ObCallbacks;

		//For IOCTL Validation
		ULONG SenderPID;

	} HEARTBEAT, * PHEARTBEAT;

public:
	GS_Communication();
	~GS_Communication();

	//Driver Communication (IOCTL)
	void UnloadDriver();
	void DriverHeartbeat();
	bool drvStillAlive;


	//Game Communication (named pipe)
};