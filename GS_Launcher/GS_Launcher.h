#pragma once

class GS_Launcher
{
public:

	GS_Launcher();
	~GS_Launcher();

	//Memberfunctions
	bool bIsGameRunning();
	bool InitService();
	bool InitDriver();
	bool InitGame();
	HANDLE GetGameHandle();
	bool InjectClient(HANDLE hProc);

	std::string GetCSGOExePath(bool OnlyDirectory);
	std::string GetDirectory();

	//Membervariables
	char szDirectory[MAX_PATH];

	std::string serviceHash;
};