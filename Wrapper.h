#pragma once

#define _WIN32_WINNT	0x0501
#include <SME_Prefix.h>
#include <MemoryHandler.h>
#include <INIManager.h>
#include <windows.h>

#include "common/IDebugLog.h"

void PatchIAT(void);

enum
{
	kGetFileVersionInfoA,
	kGetFileVersionInfoByHandle,
	kGetFileVersionInfoExW,
	kGetFileVersionInfoSizeA,
	kGetFileVersionInfoSizeExW,
	kGetFileVersionInfoSizeW,
	kGetFileVersionInfoW,
	kVerFindFileA,
	kVerFindFileW,
	kVerInstallFileA,
	kVerInstallFileW,
	kVerLanguageNameA,
	kVerLanguageNameW,
	kVerQueryValueA,
	kVerQueryValueW,

	kMax
};

extern HMODULE	DLLInstance;
extern FARPROC	OriginalProcs[kMax];

class MoreHeapINIManager : public SME::INI::INIManager
{
public:
	virtual ~MoreHeapINIManager()
	{
		;//
	}

	virtual void							Initialize(const char* INIPath, void* Parameter);

	static MoreHeapINIManager				Instance;
};

extern SME::INI::INISetting					kRuntimeFormHeapSize;
extern SME::INI::INISetting					kEditorFormHeapSize;