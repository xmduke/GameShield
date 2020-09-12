#pragma once

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <Psapi.h>
#include <thread>
#include <chrono>

#include "xorstr.hpp"
#include "ntdll.h" //Used for NtQueryInformationProcess
#include "GS_AntiDebug.h"
#include "GS_Exit.h"
#include "GS_Integrity.h"
#include "GS_Module.h"
#include "GS_Hook.h"
#include "GS_Process.h"
#include "GS_Driver.h"
#include "GS_Memory.h"
#include "GS_Data.h"

/* interface header */
#include "md5.h"

/* system implementation headers */
#include <cstdio>