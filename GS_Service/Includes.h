#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <algorithm>
#include <strsafe.h>
#include <wtsapi32.h>
#include <userenv.h>

#include "GS_Communication.h"
#include "GS_Network.h"
#include "MD5.h"
#include "XOR.h"
#include "ntdll.h"
#include "GS_Data.h"

#pragma comment (lib, "user32.lib")
#pragma comment (lib, "wtsapi32.lib")
#pragma comment (lib, "userenv.lib")
#pragma comment (lib, "advapi32.lib")