#pragma once
class GS_Driver
{

public:

	GS_Driver();
	~GS_Driver();

	bool NtEnumDrivers();

	void EnumDrivers();

	//Membervariables
	bool bIsDriverDetected;
	void* driverMem;
	std::string detectedDriver;

	std::vector<std::string> vMd5Driver;
	std::vector<std::string> Blacklist;
};