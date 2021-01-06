// dllmain.cpp : Defines the entry point for the DLL application.
#include "HookService.h"
#include <iostream>
HookCreator g_hookCreator;
bool isDetached = false;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
		isDetached = true;
		break;
    }
    return TRUE;
}

//exported functions
extern "C" __declspec(dllexport)
bool __cdecl CreateHook(LPVOID pOriginFun, LPVOID pNewFun)
{
	return g_hookCreator.createHook(pOriginFun, pNewFun);
}

extern "C" __declspec(dllexport)
bool __cdecl DisableHook(LPVOID pOriginFun, LPVOID pNewFun)
{
	//if process ends, then it can unload HookService first. Then we don't want disableHook
	if (isDetached)
		return true;

	return g_hookCreator.disableHook(pOriginFun);
}

extern "C" __declspec(dllexport)
BYTE* __cdecl GetBufferWithOriginFun(LPVOID currFun)
{
	return g_hookCreator.getBufferWithOriginFun(currFun);
}

extern "C" __declspec(dllexport)
bool __cdecl RestoreOriginFun(LPVOID currFun, BYTE jmpBuffer[16])
{
	return g_hookCreator.restoreOriginFun(currFun, jmpBuffer);
}

extern "C" __declspec(dllexport)
bool __cdecl RestoreHook(LPVOID currFun, BYTE jmpBuffer[16])
{
	return g_hookCreator.restoreHook(currFun, jmpBuffer);
}