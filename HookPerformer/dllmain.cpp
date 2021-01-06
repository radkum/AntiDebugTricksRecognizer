#include "HookPerformer.h"
#include <fstream>
#include <string>

HookPerformer* g_pHookPerformer;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		char pathBuff[MAX_PATH];
		if (!::GetEnvironmentVariableA("REPORT_FILE_PATH", pathBuff, MAX_PATH))
		{
			//std::cout << "Failed to get environmental variable" << std::endl;
			return FALSE;
		}
		//std::cout << "SUCCESS to get environmental variable" << std::endl;

		g_pHookPerformer = new HookPerformer(pathBuff);
		if (!g_pHookPerformer->loadHookApi())
		{
			return FALSE;
		}

		if (!g_pHookPerformer->createHooks())
		{
			return FALSE;
		}

		
		//std::cout << "HooInjector: DLL_PROCESS_ATTACH" << std::endl;
		
		//std::cout << "::IsDebuggerPresent address:" << std::hex << (ULONG_PTR) ::IsDebuggerPresent << std::endl;
		//std::cout << "myIsDebuggerPresent address:" << std::hex << (ULONG_PTR) myIsDebuggerPresent << std::endl;
		//std::cout << "Hook created" << std::endl;
		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
		//std::cout << "HooInjector: DLL_PROCESS_DETACH" << std::endl;
		g_pHookPerformer->printReport();

		if (!g_pHookPerformer->disableHooks())
		{
			return FALSE;
		}
		delete g_pHookPerformer;
        break;
    }
    return TRUE;
}