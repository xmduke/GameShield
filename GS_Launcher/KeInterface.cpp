#include <Windows.h>
#include <iostream>
#include "KeInterface.hpp"
#include "Com.hpp"

//Constructor
KeInterface::KeInterface(LPCSTR RegistryPath)
{
	this->hDriver = CreateFileA(RegistryPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
}

//Driver Functions
uintptr_t KeInterface::GetClientAddress()
{
	if (hDriver == INVALID_HANDLE_VALUE)
		return 0;

	ULONG address = 0;
	DWORD Bytes = 0;

	if (DeviceIoControl(hDriver, IO_GET_CLIENTBASE, &address, sizeof(address), &address, sizeof(address), &Bytes, nullptr))
	{
		if (Bytes)
			return address;
	}

	return 0;
}


DWORD KeInterface::GetProcessID()
{
	if (hDriver == INVALID_HANDLE_VALUE)
		return 0;

	ULONG ProcID = 0;
	DWORD Bytes = 0;

	if (DeviceIoControl(hDriver, IO_PROCID_REQUEST, &ProcID, sizeof(ProcID), &ProcID, sizeof(ProcID), &Bytes, nullptr))
	{
		if (Bytes)
			return ProcID;
	}

	return 0;
}