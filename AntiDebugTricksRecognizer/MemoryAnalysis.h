#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>

#include "Windows.h"
#include "winternl.h"

using NtQueryInformationProcess_FunType = NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

struct DllEndAndName
{
	PVOID dllEnd;
	std::string dllName;
};
class MemoryAnalysis
{
private:
	//consts
	const char* Kernel_Base_Lib_Name = "KernelBase.dll";
	const char* Kernel32_Lib_Name = "kernel32.dll";
	const char* Ntdll_Lib_Name = "ntdll.dll";
	const char* Bcryptprimitives_Lib_Name = "bcryptprimitives.dll";
	const char* Rpcrt4_Lib_Name = "rpcrt4.dll";

	//members
	ULONG_PTR m_relativeCloseHandleAddr = 0;
	NtQueryInformationProcess_FunType m_NTDLL_NtQueryInformationProcess = nullptr;
	size_t m_closeHandleFunSize = 0;
	std::string m_architectureSpecificCallDllName_1;
	std::string m_architectureSpecificCallDllName_2;

	std::map<PVOID, DllEndAndName> m_mapDllBase_On_PairDLLEndAndDllName;
	std::vector<PVOID> m_vecDllAddresses;
	std::map<PVOID, size_t> m_mapBreakAddressessToOccurrance;
	std::vector<PVOID> m_vecExceptionAddresses;

public:
	bool init();
	void deInit();
	bool performMemoryAnalysis(std::wstring wzFileName);

private:
	bool interceptNtDll32(HANDLE hProcess, HANDLE hThread, PVOID& pebBeingDebuggedAddr);
	bool debugLoop(PROCESS_INFORMATION pi, bool& processFinished);
	bool getDllFromAddress(PVOID exceptionAddress, std::string& refDllName, bool& refIsCloseHandle);
	std::vector<std::string> split(std::string inputString, std::string delimiter);
	bool getFileInfo(HANDLE hFile, std::string& refFileName, ULONG_PTR& refFileSize, std::string& refStr);
	bool checkIfItIsTypicalBreak(size_t i, const size_t exceptionListCount, std::string dllName);
	bool analyzeBreakAddresses();

	template< typename T >
	std::string int_to_hex(T i)
	{
		std::stringstream stream;
		stream << "0x"
			<< std::setfill('0') << std::setw(sizeof(T) * 2)
			<< std::hex << i;
		return stream.str();
	}
};


