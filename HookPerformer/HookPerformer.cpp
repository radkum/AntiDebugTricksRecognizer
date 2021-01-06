#include "HookPerformer.h"
#include <fstream>

extern HookPerformer* g_pHookPerformer;

bool HookPerformer::loadHookApi()
{
	//load hook services
	m_hHookServiceMod = ::LoadLibraryW(L"HookService.dll");
	if (m_hHookServiceMod == nullptr)
	{
		std::cout << "Can't load HookService.dll" << std::endl;
		return true;
	}

	createHook = (CreateHook_FunType) ::GetProcAddress(m_hHookServiceMod, "CreateHook");
	disableHook = (DisableHook_FunType) ::GetProcAddress(m_hHookServiceMod, "DisableHook");
	getBufferWithOriginFun = (GetBufferWithOriginFun_FunType) ::GetProcAddress(m_hHookServiceMod, "GetBufferWithOriginFun");
	restoreOriginFun = (RestoreOriginFun_FunType) ::GetProcAddress(m_hHookServiceMod, "RestoreOriginFun");
	restoreHook = (RestoreHook_FunType) ::GetProcAddress(m_hHookServiceMod, "RestoreHook");

	if (!createHook || !disableHook || !getBufferWithOriginFun || !restoreOriginFun || !restoreHook)
	{
		std::cout << "Failed to import functions" << std::endl;
		return true;
	}
	return true;
}

bool HookPerformer::createHooks()
{
	if (!createHook(::IsDebuggerPresent, myIsDebuggerPresent))
	{
		std::cout << "IsDebuggerPresent Hook creation failed" << std::endl;
		return FALSE;
	}

	if (!createHook(::CheckRemoteDebuggerPresent, myCheckRemoteDebuggerPresent))
	{
		std::cout << "CheckRemoteDebuggerPresent Hook creation failed" << std::endl;
		return FALSE;
	}

	//there is needed ntdll
	m_hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (m_hNtdll == nullptr)
	{
		std::cout << "Failed to load ntdll.dll" << std::endl;
		return FALSE;
	}
	//END loading ntdll


	//NtQueryInformationProcess
	NTDLL_NtQueryInformationProcess = (NtQueryInformationProcess_FunType) ::GetProcAddress(m_hNtdll, "NtQueryInformationProcess");

	if (NTDLL_NtQueryInformationProcess == nullptr)
	{
		std::cout << "Failed to load NTDLL_NtQueryInformationProcess" << std::endl;
		return FALSE;
	}

	if (!createHook(NTDLL_NtQueryInformationProcess, myNtQueryInformationProcess))
	{
		std::cout << "NtQueryInformationProcess Hook creation failed" << std::endl;
		return FALSE;
	}

	//NtSetInformationThread
	NTDLL_NtSetInformationThread = (NtSetInformationThread_FunType) ::GetProcAddress(m_hNtdll, "NtSetInformationThread");

	if (NTDLL_NtSetInformationThread == nullptr)
	{
		std::cout << "Failed to load NTDLL_NtSetInformationThread" << std::endl;
		return FALSE;
	}

	if (!createHook(NTDLL_NtSetInformationThread, myNtSetInformationThread))
	{
		std::cout << "NtSetInformationThread Hook creation failed" << std::endl;
		return FALSE;
	}

	//NTDLL_NtCreateThreadEx
	NTDLL_NtCreateThreadEx = (NtCreateThreadEx_FunType) ::GetProcAddress(m_hNtdll, "NtCreateThreadEx");

	if (NTDLL_NtCreateThreadEx == nullptr)
	{
		std::cout << "Failed to load NTDLL_NtCreateThreadEx" << std::endl;
		return FALSE;
	}

	if (!createHook(NTDLL_NtCreateThreadEx, myNtCreateThreadEx))
	{
		std::cout << "myNtCreateThreadEx Hook creation failed" << std::endl;
		return FALSE;
	}
	return true;
}

bool HookPerformer::disableHooks()
{
	if (!disableHook(::IsDebuggerPresent))
	{
		std::cout << "Can't erased IsDebuggerPresent hook. Mabye you want disable not existing hook?" << std::endl;
		return false;
	}

	if (!disableHook(::CheckRemoteDebuggerPresent))
	{
		std::cout << "Can't erased CheckRemoteDebuggerPresent hook. Mabye you want disable not existing hook?" << std::endl;
		return false;
	}

	if (!disableHook(NTDLL_NtQueryInformationProcess))
	{
		std::cout << "Can't erased NTDLL_NtQueryInformationProcess hook. Mabye you want disable not existing hook?" << std::endl;
		return false;
	}

	if (!disableHook(NTDLL_NtSetInformationThread))
	{
		std::cout << "Can't erased NTDLL_NtSetInformationThread hook. Mabye you want disable not existing hook?" << std::endl;
		return false;
	}

	if (!disableHook(NTDLL_NtCreateThreadEx))
	{
		std::cout << "Can't erased NTDLL_NtCreateThreadEx hook. Mabye you want disable not existing hook?" << std::endl;
		return false;
	}

	//std::cout << "Hook erased" << std::endl;
	if (m_hHookServiceMod)
		::FreeLibrary(m_hHookServiceMod);

	if (m_hNtdll)
		::FreeLibrary(m_hNtdll);
	return true;
}

void HookPerformer::printReport()
{
	std::ofstream reportStream(m_reportFileName);
	if (!reportStream)
	{
		return;
	}

	reportStream << "API Calls Report:" << std::endl;
	reportStream << "<function_name> - <call number>\n" << std::endl;
	if (m_IsDebuggerPresentCounter)
		reportStream << "IsDebuggerPresent()   -   " << m_IsDebuggerPresentCounter << std::endl;

	if (m_CheckRemoteDebuggerPresentCounter)
		reportStream << "CheckRemoteDebuggerPresent()   -   " << m_CheckRemoteDebuggerPresentCounter << std::endl;

	if (m_NtQueryInformationProcessCounter)
		reportStream << "NtQueryInformationProcess()   -   " << m_NtQueryInformationProcessCounter << std::endl;

	if (m_NtSetInformationThreadCounter)
		reportStream << "NtSetInformationThread()   -   " << m_NtSetInformationThreadCounter << std::endl;

	if (m_NtCreateThreadExCounter)
		reportStream << "NtCreateThreadEx()   -   " << m_NtCreateThreadExCounter << std::endl;

	reportStream.close();
}

BOOL WINAPI myIsDebuggerPresent()
{
	g_pHookPerformer->m_IsDebuggerPresentCounter++;

	IsDebuggerPresent_FunType pOryginFunProlog =
		(IsDebuggerPresent_FunType)g_pHookPerformer->getBufferWithOriginFun((LPVOID)::IsDebuggerPresent);

	return pOryginFunProlog();
}

BOOL WINAPI myCheckRemoteDebuggerPresent(HANDLE hProcess, BOOL* debuggerIsPresent)
{
	g_pHookPerformer->m_CheckRemoteDebuggerPresentCounter++;

	CheckRemoteDebuggerPresent_FunType pOryginFunProlog =
		(CheckRemoteDebuggerPresent_FunType)g_pHookPerformer->getBufferWithOriginFun((LPVOID)::CheckRemoteDebuggerPresent);

	return pOryginFunProlog(hProcess, debuggerIsPresent);
}

NTSTATUS NTAPI myNtQueryInformationProcess(HANDLE processHandle, PROCESSINFOCLASS processInformationClass,
	PVOID processInformation, ULONG processInformationLength, PULONG returnLength)
{
	g_pHookPerformer->m_NtQueryInformationProcessCounter++;

	BYTE jmpBuffer[16];
	g_pHookPerformer->restoreOriginFun((LPVOID)g_pHookPerformer->NTDLL_NtQueryInformationProcess, jmpBuffer);

	NTSTATUS status = g_pHookPerformer->NTDLL_NtQueryInformationProcess(processHandle, processInformationClass,
		processInformation, processInformationLength, returnLength);

	g_pHookPerformer->restoreHook((LPVOID)g_pHookPerformer->NTDLL_NtQueryInformationProcess, jmpBuffer);
	return status;
}

NTSTATUS NTAPI myNtSetInformationThread(HANDLE threadHandle, ULONG threadInformationClass,
	PVOID threadInformation, ULONG threadInformationLength)
{
	g_pHookPerformer->m_NtSetInformationThreadCounter++;

	BYTE jmpBuffer[16];
	g_pHookPerformer->restoreOriginFun((LPVOID)g_pHookPerformer->NTDLL_NtSetInformationThread, jmpBuffer);

	NTSTATUS status = g_pHookPerformer->NTDLL_NtSetInformationThread(threadHandle, threadInformationClass,
		threadInformation, threadInformationLength);

	g_pHookPerformer->restoreHook((LPVOID)g_pHookPerformer->NTDLL_NtSetInformationThread, jmpBuffer);
	return status;
}

NTSTATUS NTAPI myNtCreateThreadEx(PHANDLE threadHandle, ACCESS_MASK desiredAccess,
	POBJECT_ATTRIBUTES objectAttributes, HANDLE processHandle, PVOID startRoutine,
	PVOID argument, ULONG createFlags, ULONG_PTR zeroBits, SIZE_T stackSize,
	SIZE_T maximumStackSize, PVOID attributeList)
{
	g_pHookPerformer->m_NtCreateThreadExCounter++;

	BYTE jmpBuffer[16];
	g_pHookPerformer->restoreOriginFun((LPVOID)g_pHookPerformer->NTDLL_NtCreateThreadEx, jmpBuffer);

	NTSTATUS status = g_pHookPerformer->NTDLL_NtCreateThreadEx(threadHandle, 
		desiredAccess, objectAttributes, processHandle, startRoutine, argument, 
		createFlags, zeroBits, stackSize, maximumStackSize, attributeList);

	g_pHookPerformer->restoreHook((LPVOID)g_pHookPerformer->NTDLL_NtCreateThreadEx, jmpBuffer);
	return status;
}