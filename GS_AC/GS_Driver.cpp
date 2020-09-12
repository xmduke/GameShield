/*
//GameShield Anti Cheat developed by MrSn0w

Purpoose:
Enumeration and detection of suspicious device driver running on the system.
Check for unsigned drivers, blacklisted drivers and drivers with suspicious certificate.
*/

#include "Includes.h"


GS_Driver::GS_Driver()
{
	GSData::Func::myEnumDeviceDrivers = reinterpret_cast<GSData::Func::tEnumDeviceDrivers>(GetProcAddress(GetModuleHandleA(_xor_("psapi.dll").c_str()), _xor_("EnumDeviceDrivers").c_str()));

	this->detectedDriver = { "" };
	//Detection Variables
	this->bIsDriverDetected = false;

	//Driver Blacklist Initializing
	this->Blacklist.push_back(_xor_("iqvw64e.sys")); //Intel Driver
	this->Blacklist.push_back(_xor_("iqvw32.sys")); //Intel Driver
	this->Blacklist.push_back(_xor_("ADV64DRV.sys"));
	this->Blacklist.push_back(_xor_("Agent64.sys"));
	this->Blacklist.push_back(_xor_("ALSysIO64.sys"));
	this->Blacklist.push_back(_xor_("amifldrv64.sys"));
	this->Blacklist.push_back(_xor_("AsIO.sys"));
	this->Blacklist.push_back(_xor_("AsrAutoChkUpdDrv.sys"));
	this->Blacklist.push_back(_xor_("AsrDrv10.sys"));
	//this->Blacklist.push_back("AsrDrv101.sys");
	this->Blacklist.push_back(_xor_("AsrIbDrv.sys"));
	this->Blacklist.push_back(_xor_("AsrOmgDrv.sys"));
	this->Blacklist.push_back(_xor_("AsrRapidStartDrv.sys"));
	this->Blacklist.push_back(_xor_("AsrSmartConnectDrv.sys"));
	this->Blacklist.push_back(_xor_("AsUpIO.sys"));
	this->Blacklist.push_back(_xor_("atillk64.sys"));
	this->Blacklist.push_back(_xor_("BS_Def64.sys"));
	this->Blacklist.push_back(_xor_("AsUpIO.sys"));
	this->Blacklist.push_back(_xor_("atillk64.sys"));
	this->Blacklist.push_back(_xor_("CITMDRV_AMD64.sys"));
	this->Blacklist.push_back(_xor_("CITMDRV_IA64.sys"));
	this->Blacklist.push_back(_xor_("cpuz_x64.sys"));
	this->Blacklist.push_back(_xor_("GLCKIO2.sys"));
	this->Blacklist.push_back(_xor_("inpoutx64.sys"));
	this->Blacklist.push_back(_xor_("kprocesshacker.sys")); //ProcessHacker
	this->Blacklist.push_back(_xor_("rzpnk.sys")); //Razer Driver
	this->Blacklist.push_back(_xor_("v0eDkxSUIvz.sys")); //WindowsKernelExplorer
	this->Blacklist.push_back(_xor_("gdrv.sys")); //Gigabyte Driver
	this->Blacklist.push_back(_xor_("Driver.sys"));

	//Blacklisted Driver Hashes
	this->vMd5Driver.push_back(_xor_("b0f07cbfe6b0e61cc3a6083b8665ab4e"));
	this->vMd5Driver.push_back(_xor_("00dfcfa3da8c5e7c15e89a1a2ed510d6"));
	this->vMd5Driver.push_back(_xor_("f7c8b0ffff5b1257e04afbbdbf1a017f"));
	this->vMd5Driver.push_back(_xor_("8624611ff499a6041966d6a60c2bcca7"));
	this->vMd5Driver.push_back(_xor_("3dcb21d5cb2dbd5839dbcbb6a85ee147"));
	this->vMd5Driver.push_back(_xor_("c469ea1ce72b97796bc2da13c8f75ce2"));
	this->vMd5Driver.push_back(_xor_("c77db772dc21d40708c522614c92619f"));
	this->vMd5Driver.push_back(_xor_("e10fbe976fd4b1a9bf7e6e8ec02d4d5c"));
	this->vMd5Driver.push_back(_xor_("4f66b719c3dceb50a4a568fa93cd2dc3"));
	this->vMd5Driver.push_back(_xor_("8d6f97f949e686d243843aab74994fcb"));
	this->vMd5Driver.push_back(_xor_("4076ed8b6325a79d4550514d2a959473"));
	this->vMd5Driver.push_back(_xor_("0190e2c9e5d53be9cd22fb12a7f95eec"));
	this->vMd5Driver.push_back(_xor_("396295f41e24623fb4ee8e3813b9c375"));

	this->driverMem = VirtualAlloc(0, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

GS_Driver::~GS_Driver()
{
	delete this;
}

void GS_Driver::EnumDrivers()
{
	LPVOID Drivers[1024];
	DWORD cbNeeded;
	int cDrivers;

	if (GSData::Func::myEnumDeviceDrivers(Drivers, sizeof(Drivers), &cbNeeded) && cbNeeded < sizeof(Drivers))
	{
		char szDriver[1024];
		std::string sDriver = { 0 };
		char buffer_name[MAX_PATH] = { 0 };
		char buffer_path[MAX_PATH] = { 0 };
		cDrivers = cbNeeded / sizeof(Drivers[0]);

		//Disable filesystem redirection (if WOW64)
		if (Wow64EnableWow64FsRedirection)
			Wow64EnableWow64FsRedirection(0);

		//Loop Drivers
		for (int i = 0; i < cDrivers; i++)
		{
			if (GetDeviceDriverBaseNameA(Drivers[i], buffer_name, MAX_PATH)) //Get Base name
			{
				for (int i = 0; i < this->Blacklist.size(); i++)
				{
					std::stringstream ss;
					ss << buffer_name;
					sDriver = ss.str();

					if (sDriver.compare(this->Blacklist[i]) == 0) //Match
					{
						this->detectedDriver = sDriver;
						this->bIsDriverDetected = true;
						return;
					}
				}
			}

			if (GetDeviceDriverFileNameA(Drivers[i], buffer_path, MAX_PATH)) //Get driver path
			{
				//Open device driver file handle
				std::ifstream processMd5;
				processMd5.open(buffer_path, std::ios::binary | std::ios::in);
				if (processMd5.fail())
					continue;

				processMd5.seekg(0, std::ios::end);
				long len = processMd5.tellg();
				processMd5.seekg(0, std::ios::beg);

				//Read Filer
				char* buffer = new char[len];
				processMd5.read(buffer, len);

				if (buffer)
				{
					std::string driverHash = md5(buffer, len);
					delete[] buffer;

					for (int i = 0; i < this->vMd5Driver.size(); i++)
					{
						if (driverHash == this->vMd5Driver[i])
						{
							this->detectedDriver = sDriver;
							this->bIsDriverDetected = true;
							return;
						}
					}
				}
			}
		}
	}
}