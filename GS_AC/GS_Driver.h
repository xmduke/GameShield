#pragma once
class GS_Driver
{

private:

	std::vector<std::string> vMd5Driver;
	std::vector<std::string> Blacklist;

public:

	GS_Driver();
	~GS_Driver();

	void EnumDrivers();

	//Membervariables
	bool bIsDriverDetected;
	void* driverMem;
	std::string detectedDriver;
};