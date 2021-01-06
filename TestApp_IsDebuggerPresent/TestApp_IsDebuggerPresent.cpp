#include <iostream>
#include <Windows.h>
#include <fstream>
#include <string>

#include <winternl.h>

using std::cout;
// Get PEB for WOW64 Process

// Current PEB for 64bit and 32bit processes accordingly
PVOID GetPEB()
{
#ifdef _WIN64
	return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
#else
	return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}

PVOID GetPEB64()
{
	PVOID pPeb = 0;
#ifndef _WIN64
	// 1. There are two copies of PEB - PEB64 and PEB32 in WOW64 process
	// 2. PEB64 follows after PEB32
	// 3. This is true for versions lower than Windows 8, else __readfsdword returns address of real PEB64
	//if (IsWin8OrHigher())
	{
		BOOL isWow64 = FALSE;
		typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
		pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
			GetProcAddress(GetModuleHandleA("Kernel32.dll"), "IsWow64Process");
		if (fnIsWow64Process(GetCurrentProcess(), &isWow64))
		{
			if (isWow64)
			{
				pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
				//pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
			}
		}
	}
#endif
	return pPeb;
}
ULONG_PTR getHardwareBreakpoint(HANDLE hThread)
{
	CONTEXT context = {};
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (::GetThreadContext(hThread, &context))
	{
		return context.Dr0;
	}
	return 0;
}
int main()
{
	std::ofstream out("log.txt");
	out << "AntiDebug_IsDebuggerPresent started!" << std::endl;



	ULONG_PTR elo = (ULONG_PTR) ::IsDebuggerPresent;
	std::wstring libPath = L"HookPerformer.dll";
	/*HMODULE hMod = ::LoadLibraryW(libPath.data());

	if (hMod)
	{
		std::cout << "Module loaded" << std::endl;
	}*/

	//PEB
	
	PVOID peb = GetPEB();
	PBYTE beingDebuggedAddr = ((BYTE*)peb + 2);
	BYTE beingDebugged = *beingDebuggedAddr;
	
	out << "beingDebuggedAddr: " << std::hex << (ULONG_PTR)beingDebuggedAddr << std::endl;
	out << "beingDebugged: " << (int)beingDebugged << std::endl;
	//PEB
	OutputDebugStringA(std::to_string((ULONG_PTR)beingDebuggedAddr).data());
	
	//int eo = 2;


	/*::IsDebuggerPresent();
	::IsDebuggerPresent();
	::IsDebuggerPresent();
	::IsDebuggerPresent();*/

	BOOL isRemoteDebuggerPresent = false;
	//::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &isRemoteDebuggerPresent);
	//using some hooked functions
	/*BOOL isRemoteDebuggerPresent = false;
	if (::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &isRemoteDebuggerPresent))
	{
		if (isRemoteDebuggerPresent)
		{

		}
	}

	
	HMODULE m_hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (m_hNtdll == nullptr)
	{
		std::cout << "test: Failed to load ntdll.dll" << std::endl;
		return -1;
	}

	//NtSetInformationThread
	using NtSetInformationThread_FunType = NTSTATUS(NTAPI *)(HANDLE, ULONG, PVOID, ULONG);

	NtSetInformationThread_FunType NTDLL_NtSetInformationThread = (NtSetInformationThread_FunType) ::GetProcAddress(m_hNtdll, "NtSetInformationThread");
	if (NTDLL_NtSetInformationThread == nullptr)
	{
		std::cout << "Failed to load NTDLL_NtSetInformationThread" << std::endl;
		return FALSE;
	}

	const ULONG ThreadHideFromDebugger = 0x11;
	LONG status = NTDLL_NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);

	//NtCreateThreadEx
	using NtCreateThreadEx_FunType = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID,
		PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);

	NtCreateThreadEx_FunType NTDLL_NtCreateThreadEx = (NtCreateThreadEx_FunType) ::GetProcAddress(m_hNtdll, "NtCreateThreadEx");
	if (NTDLL_NtCreateThreadEx == nullptr)
	{
		std::cout << "Failed to load NTDLL_NtCreateThreadEx" << std::endl;
		return FALSE;
	}
	NTDLL_NtCreateThreadEx(nullptr, NULL, nullptr, nullptr, nullptr, nullptr, 0, 0, 0, 0, nullptr);
	*/

	out << "AntiDebug_IsDebuggerPresent finished!" << std::endl;
	out.close();
	//::FreeLibrary(hMod);
	return 0;
}