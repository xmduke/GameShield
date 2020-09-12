#include "Form1.h"
#include <Windows.h>
#include <fstream>

#pragma comment(lib, "user32.lib")

_Log GetInfo()
{
	char buffer[MAX_PATH] = { 0 };
	GetCurrentDirectoryA(MAX_PATH, buffer);
	strcat(buffer, "\\GameShield");

	SetCurrentDirectoryA(buffer);

	_Log tmpLog;
	std::ifstream ifs;
	ifs.open("Log.gs", std::ios::binary);

	if (ifs.fail())
	{
		MessageBoxA(0, "Failed to read logfile", "GameShield", MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}

	ifs.read((char*)&tmpLog, sizeof(tmpLog));
	ifs.close();
	Sleep(500);
	DeleteFileA("Log.gs");

	return tmpLog;
}