#pragma once

struct _VMware
{
	//Process Names
	std::string vmProc1 = _xor_("vmtoolsd.exe");
	std::string vmProc2 = _xor_("vmacthlp.exe");
};

struct _VBox
{
	//Process Names
	std::string vmProc1 = _xor_("vmboxservice.exe");
	std::string vmProc2 = _xor_("vboxtray.exe");
	std::string vmProc3 = _xor_("vboxcontrol.exe");
};

class GS_VM
{

private:

	_VMware VMware;
	_VBox VBox;

public:

	//Memberfunctions
	GS_VM();
	~GS_VM();
	void CheckVMServices();
	void CheckVMGeneral();

	//Membervariables
	bool bIsVM;
};