// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <string>
#include <fstream>

// EA DRM function that checks entitlements
void* (__fastcall* oGetEntitlements)(void*);
void* __fastcall hkGetEntitlements(void* arg)
{
	struct Entitlement
	{
		char entitlementTag[0x80];
		char longId[0x80];
		char type[0x10];
		char group[0x10];
		int32_t version;
		int32_t __padding;
	};

	struct Entitlements
	{
		Entitlement* entitlements;
		uint32_t count;
	};

	auto result = (Entitlements*)oGetEntitlements(arg);
	if (result)
	{
		char iniPath[MAX_PATH];
		GetModuleFileNameA(NULL, iniPath, MAX_PATH);
		*strrchr(iniPath, '\\') = '\0';
		strcat_s(iniPath, MAX_PATH, "\\g_The Sims 4.ini");

		int dlcCount = GetPrivateProfileIntA("config", "CNT", 0, iniPath);
		if (dlcCount > 0)
		{
			auto newEntitlements = new Entitlement[result->count + dlcCount];
			if (result->count > 0)
				memcpy(newEntitlements, result->entitlements, result->count * sizeof(Entitlement));

			for (int i = 1; i <= dlcCount; i++)
			{
				auto dest = &newEntitlements[result->count + i - 1];

				char iidKey[6];
				sprintf_s(iidKey, 6, "IID%i", i);

				char iid[256];
				GetPrivateProfileStringA("config", iidKey, "", iid, 256, iniPath);

				if (*iid != '\0' && *iid != ';')
				{
					char etgKey[6];
					sprintf_s(etgKey, 6, "ETG%i", i);
					char grpKey[6];
					sprintf_s(grpKey, 6, "GRP%i", i);
					char typKey[6];
					sprintf_s(typKey, 6, "TYP%i", i);

					GetPrivateProfileStringA("config", etgKey, "", dest->entitlementTag, 0x80, iniPath);
					strcpy_s(dest->longId, 0x80, iid);
					GetPrivateProfileStringA("config", typKey, "", dest->type, 0x10, iniPath);
					GetPrivateProfileStringA("config", grpKey, "", dest->group, 0x10, iniPath);
					dest->version = 0;
					dest->__padding = 0;
				}
				else
				{
					// Move to the previous one to overwrite
					i--;
					dlcCount--;
				}
			}

			result->entitlements = newEntitlements;
			result->count += dlcCount;
		}
	}
	return result;
}

void hook()
{
	char exePath[MAX_PATH];
	GetModuleFileNameA(NULL, exePath, MAX_PATH);
	if (stricmp(strrchr(exePath, '\\') + 1, "TS4_x64.exe") == 0)
	{
		MODULEINFO mi;
		HMODULE hPso = NULL;
		do
		{
			hPso = GetModuleHandleA("PSO.dll");
			Sleep(100);
		} while (hPso == NULL);

		GetModuleInformation(GetCurrentProcess(), hPso, &mi, sizeof(mi));

		// Find signature
		const char* pat = "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20\x48\x8B\xDA\xE8";
		for (DWORD i = 0; i < mi.SizeOfImage - 0x1000; i++)
		{
			if (memcmp((void*)((UINT64)mi.lpBaseOfDll + i), pat, 19) == 0)
			{
				// Get address and install hook
				oGetEntitlements = (decltype(oGetEntitlements))((UINT64)mi.lpBaseOfDll + i);

				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourAttach(&(PVOID&)oGetEntitlements, hkGetEntitlements);
				DetourTransactionCommit();
				return;
			}
		}
	}
}

// Proxy stuff
HMODULE hMod = NULL;

extern "C" {
	FARPROC p[8] = { 0 };
	const char* export_names[] = {
		"DirectInput8Create",
		"DllCanUnloadNow",
		"DllGetClassObject",
		"DllRegisterServer",
		"DllUnregisterServer",
		"GetdfDIJoystick",
		"Getdi সংকোচন",
		"Newdiid"
	};
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		char path[MAX_PATH];
		GetSystemDirectoryA(path, MAX_PATH);
		strcat_s(path, "\\dinput8.dll");
		hMod = LoadLibraryA(path);
		if (hMod)
		{
			for (int i = 0; i < 8; i++)
				p[i] = GetProcAddress(hMod, export_names[i]);
		}

		hook();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		if (hMod)
			FreeLibrary(hMod);
	}
	return TRUE;
}