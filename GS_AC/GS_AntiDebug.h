#pragma once
class GS_AntiDebug
{
public:

	//Memberfunctions
	GS_AntiDebug();
	~GS_AntiDebug();

	void DetectionGeneral();	
	void DetectionAdvanced();
	void DetectionVEH();

	//Membervariables
	bool bIsDebugger;
	bool bIsVEH;
};