#pragma once

#include <SDKDDKVer.h>

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <Windows.h>
#include <winternl.h>

// reference additional headers your program requires here
#include <iostream>

//typedefs
using IsDebuggerPresent_FunType = BOOL(WINAPI *)();
using CheckRemoteDebuggerPresent_FunType = BOOL(WINAPI *)(HANDLE, PBOOL);
using NtQueryInformationProcess_FunType = NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
using NtSetInformationThread_FunType = NTSTATUS(NTAPI *)(HANDLE, ULONG, PVOID, ULONG);
using NtCreateThreadEx_FunType = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID,
	PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);

//hook api
using CreateHook_FunType = bool(__cdecl *)(LPVOID, LPVOID);
using DisableHook_FunType = bool(__cdecl *)(LPVOID);
using GetBufferWithOriginFun_FunType = BYTE * (__cdecl *)(LPVOID);
using RestoreOriginFun_FunType = BYTE * (__cdecl *)(LPVOID, BYTE[16]);
using RestoreHook_FunType = BYTE * (__cdecl *)(LPVOID, BYTE[16]);

BOOL WINAPI myIsDebuggerPresent();
BOOL WINAPI myCheckRemoteDebuggerPresent(HANDLE hProcess, BOOL* debuggerIsPresent);

NTSTATUS NTAPI myNtQueryInformationProcess(HANDLE processHandle, PROCESSINFOCLASS processInformationClass,
	PVOID processInformation, ULONG processInformationLength, PULONG returnLength);

NTSTATUS NTAPI myNtSetInformationThread(HANDLE threadHandle, ULONG threadInformationClass,
	PVOID threadInformation, ULONG threadInformationLength);

NTSTATUS NTAPI myNtCreateThreadEx(PHANDLE threadHandle, ACCESS_MASK desiredAccess, 
	POBJECT_ATTRIBUTES objectAttributes, HANDLE processHandle, PVOID startRoutine, 
	PVOID argument, ULONG createFlags, ULONG_PTR zeroBits, SIZE_T stackSize, 
	SIZE_T maximumStackSize, PVOID attributeList);

class HookPerformer
{
public:
	HookPerformer(const char* reportFileNameCStr) : m_reportFileName(reportFileNameCStr) {}

	bool loadHookApi();
	bool createHooks();
	bool disableHooks();
	void printReport();

	//function declarations
	GetBufferWithOriginFun_FunType getBufferWithOriginFun = nullptr;
	RestoreOriginFun_FunType restoreOriginFun = nullptr;
	RestoreHook_FunType restoreHook = nullptr;
	NtQueryInformationProcess_FunType NTDLL_NtQueryInformationProcess = nullptr;
	NtSetInformationThread_FunType NTDLL_NtSetInformationThread = nullptr;
	NtCreateThreadEx_FunType NTDLL_NtCreateThreadEx = nullptr;

	//counters
	size_t m_IsDebuggerPresentCounter = 0;
	size_t m_CheckRemoteDebuggerPresentCounter = 0;
	size_t m_NtQueryInformationProcessCounter = 0;
	size_t m_NtSetInformationThreadCounter = 0;
	size_t m_NtCreateThreadExCounter = 0;

private:
	HMODULE m_hHookServiceMod = nullptr;
	HMODULE m_hNtdll = nullptr;

	CreateHook_FunType createHook = nullptr;
	DisableHook_FunType disableHook = nullptr;

	std::string m_reportFileName;
};