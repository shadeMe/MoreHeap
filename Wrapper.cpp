#include "Wrapper.h"

IDebugLog		gLog("MoreHeap.log");

void* OrgIATProc = NULL;
HMODULE DLLInstance = NULL;
FARPROC	OriginalProcs[kMax] = {0};

void __stdcall IATWrapperProc(LPSTARTUPINFO Info)
{
	static bool DoOnce = false;

	if (DoOnce == false)
	{
		DoOnce = true;

		const char* RuntimeHostTest = (const char*)0x00A2FC44;
		const char* EditorHostTest = (const char*)0x0096EA7C;

		if (!_stricmp(RuntimeHostTest, "Main"))
		{
			// runtime
			UInt32 DefaultHeap = kRuntimeFormHeapSize.GetData().i;
			if (DefaultHeap > 1024 || DefaultHeap < 256)
				DefaultHeap = 256;

			SME::MemoryHandler::SafeWrite32(0x00A2FC24, DefaultHeap);
			_MESSAGE("Set runtime heap initial allocation size to %d MB", DefaultHeap);
		}
		else if (!_stricmp(EditorHostTest, "Rainy?"))
		{
			// editor
			UInt32 DefaultHeap = kEditorFormHeapSize.GetData().i;
			if (DefaultHeap > 1024 || DefaultHeap < 256)
				DefaultHeap = 256;

			SME::MemoryHandler::SafeWrite32(0x0092E4B0, DefaultHeap);
			_MESSAGE("Set editor heap initial allocation size to %d MB", DefaultHeap);
		}
		else
		{
			// some other process
			_MESSAGE("Activated Universal Migrator");
		}
	}

	SME_ASSERT(OrgIATProc);

	typedef VOID (CALLBACK* _Fn)(LPSTARTUPINFO Info);
	((_Fn)OrgIATProc)(Info);
}

void PatchIAT(void)
{
	UInt8* Base = (UInt8*)GetModuleHandle(NULL);
	IMAGE_DOS_HEADER* DOSHeader = (IMAGE_DOS_HEADER*)Base;
	IMAGE_NT_HEADERS* NTHeader = (IMAGE_NT_HEADERS*)(Base + DOSHeader->e_lfanew);
	void* PatchLoc = NULL;

	IMAGE_IMPORT_DESCRIPTOR* IAT = (IMAGE_IMPORT_DESCRIPTOR*)(Base + NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for(; IAT->Characteristics && PatchLoc == NULL; ++IAT)
	{
		if(!_stricmp("kernel32.dll", (const char*)(Base + IAT->Name)))
		{
			IMAGE_THUNK_DATA* ThunkData = (IMAGE_THUNK_DATA*)(Base + IAT->OriginalFirstThunk);
			UInt32* DLLIAT = (UInt32*)(Base + IAT->FirstThunk);

			for(; ThunkData->u1.Ordinal; ++ThunkData, ++DLLIAT)
			{
				if(!IMAGE_SNAP_BY_ORDINAL(ThunkData->u1.Ordinal))
				{
					IMAGE_IMPORT_BY_NAME* ImportInfo = (IMAGE_IMPORT_BY_NAME*)(Base + ThunkData->u1.AddressOfData);

					if(!_stricmp((char *)ImportInfo->Name, "GetStartupInfoA"))
					{
						PatchLoc = DLLIAT;
						break;
					}
				}
			}
		}
	}

	if (PatchLoc)
	{
		OrgIATProc = *((void**)PatchLoc);
		SME::MemoryHandler::SafeWrite32((UInt32)PatchLoc, (UInt32)IATWrapperProc);
	}

	HMODULE OrgDLL = LoadLibraryEx(".\\version.dll", NULL, 0x00000800);
	SME_ASSERT(OrgDLL && OrgDLL != DLLInstance);


	OriginalProcs[kGetFileVersionInfoA] = GetProcAddress(OrgDLL, "GetFileVersionInfoA");
	OriginalProcs[kGetFileVersionInfoByHandle] = GetProcAddress(OrgDLL, "GetFileVersionInfoByHandle");
	OriginalProcs[kGetFileVersionInfoExW] = GetProcAddress(OrgDLL, "GetFileVersionInfoExW");
	OriginalProcs[kGetFileVersionInfoSizeA] = GetProcAddress(OrgDLL, "GetFileVersionInfoSizeA");
	OriginalProcs[kGetFileVersionInfoSizeExW] = GetProcAddress(OrgDLL, "GetFileVersionInfoSizeExW");
	OriginalProcs[kGetFileVersionInfoSizeW] = GetProcAddress(OrgDLL, "GetFileVersionInfoSizeW");
	OriginalProcs[kGetFileVersionInfoW] = GetProcAddress(OrgDLL, "GetFileVersionInfoW");
	OriginalProcs[kVerFindFileA] = GetProcAddress(OrgDLL, "VerFindFileA");
	OriginalProcs[kVerFindFileW] = GetProcAddress(OrgDLL, "VerFindFileW");
	OriginalProcs[kVerInstallFileA] = GetProcAddress(OrgDLL, "VerInstallFileA");
	OriginalProcs[kVerInstallFileW] = GetProcAddress(OrgDLL, "VerInstallFileW");
	OriginalProcs[kVerLanguageNameA] = GetProcAddress(OrgDLL, "VerLanguageNameA");
	OriginalProcs[kVerLanguageNameW] = GetProcAddress(OrgDLL, "VerLanguageNameW");
	OriginalProcs[kVerQueryValueA] = GetProcAddress(OrgDLL, "VerQueryValueA");
	OriginalProcs[kVerQueryValueW] = GetProcAddress(OrgDLL, "VerQueryValueW");
}

MoreHeapINIManager		MoreHeapINIManager::Instance;

SME::INI::INISetting	kRuntimeFormHeapSize("DefaultHeapSize", "Runtime::MemAlloc", "", (SInt32)256);
SME::INI::INISetting	kEditorFormHeapSize("DefaultHeapSize", "Editor::MemAlloc", "", (SInt32)256);


void MoreHeapINIManager::Initialize( const char* INIPath, void* Parameter )
{
	this->INIFilePath = INIPath;
	_MESSAGE("INI Path: %s", INIPath);
	
	RegisterSetting(&kRuntimeFormHeapSize);
	RegisterSetting(&kEditorFormHeapSize);
	
	Save();
}


extern "C"
{
	BOOL WINAPI DllMain(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved)
	{
		if (dwReason == DLL_PROCESS_ATTACH)
		{
			DisableThreadLibraryCalls((HMODULE)hDllHandle);
			DLLInstance = (HMODULE)hDllHandle;
			_MESSAGE("Initializing INI Manager");

			char INIPath[MAX_PATH] = {0};
			GetModuleFileName(DLLInstance, INIPath, sizeof(INIPath));
			*strrchr(INIPath, '\\') = 0;
			lstrcat(INIPath, "\\MoreHeap.ini");

			MoreHeapINIManager::Instance.Initialize(INIPath, NULL);

			PatchIAT();
		}

		return TRUE;
	}

	__declspec(naked) void __stdcall Wrapper_GetFileVersionInfoA()
	{
		__asm	jmp		OriginalProcs[kGetFileVersionInfoA * 4]
	}

	__declspec(naked) void __stdcall Wrapper_GetFileVersionInfoByHandle()
	{
		__asm	jmp		OriginalProcs[kGetFileVersionInfoByHandle * 4]
	}

	__declspec(naked) void __stdcall Wrapper_GetFileVersionInfoExW()
	{
		__asm	jmp		OriginalProcs[kGetFileVersionInfoExW * 4]
	}

	__declspec(naked) void __stdcall Wrapper_GetFileVersionInfoSizeA()
	{
		__asm	jmp		OriginalProcs[kGetFileVersionInfoSizeA * 4]
	}

	__declspec(naked) void __stdcall Wrapper_GetFileVersionInfoSizeExW()
	{
		__asm	jmp		OriginalProcs[kGetFileVersionInfoSizeExW * 4]
	}

	__declspec(naked) void __stdcall Wrapper_GetFileVersionInfoSizeW()
	{
		__asm	jmp		OriginalProcs[kGetFileVersionInfoSizeW * 4]
	}

	__declspec(naked) void __stdcall Wrapper_GetFileVersionInfoW()
	{
		__asm	jmp		OriginalProcs[kGetFileVersionInfoW * 4]
	}

	__declspec(naked) void __stdcall Wrapper_VerFindFileA()
	{
		__asm	jmp		OriginalProcs[kVerFindFileA * 4]
	}

	__declspec(naked) void __stdcall Wrapper_VerFindFileW()
	{
		__asm	jmp		OriginalProcs[kVerFindFileW * 4]
	}

	__declspec(naked) void __stdcall Wrapper_VerInstallFileA()
	{
		__asm	jmp		OriginalProcs[kVerInstallFileA * 4]
	}

	__declspec(naked) void __stdcall Wrapper_VerInstallFileW()
	{
		__asm	jmp		OriginalProcs[kVerInstallFileW * 4]
	}

	__declspec(naked) void __stdcall Wrapper_VerLanguageNameA()
	{
		__asm	jmp		OriginalProcs[kVerLanguageNameA * 4]
	}

	__declspec(naked) void __stdcall Wrapper_VerLanguageNameW()
	{
		__asm	jmp		OriginalProcs[kVerLanguageNameW * 4]
	}

	__declspec(naked) void __stdcall Wrapper_VerQueryValueA()
	{
		__asm	jmp		OriginalProcs[kVerQueryValueA * 4]
	}

	__declspec(naked) void __stdcall Wrapper_VerQueryValueW()
	{
		__asm	jmp		OriginalProcs[kVerQueryValueW * 4]
	}
};
