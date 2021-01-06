#include <algorithm>
#include <set>
#include <sstream>

#include "MemoryAnalysis.h"
#include "HardwareBreakpoint.h"
#include "LogHelper.h"
#include "asserts.h"

#define TEB32OFFSET 0x2000

bool MemoryAnalysis::init()
{
	//init closeHandle
	HMODULE hKernelBase = ::LoadLibraryA(Kernel_Base_Lib_Name);
	if (hKernelBase == nullptr)
	{
		LogHelper::PrintLog(LogLevel::Error, "Failed to load KernelBase.dll");
		return false;
	}

	ULONG_PTR closeHandleAddr = (ULONG_PTR) ::GetProcAddress(hKernelBase, "CloseHandle");

	if (closeHandleAddr == 0)
	{
		LogHelper::PrintLog(LogLevel::Error, "Failed to load closeHandleAddr");
		return false;
	}
	m_relativeCloseHandleAddr = closeHandleAddr - (ULONG_PTR)hKernelBase;

	::FreeLibrary(hKernelBase);

	//load NTDLL_NtQueryInformationProcess
	HMODULE hNtdll = ::LoadLibraryA("ntdll.dll");
	if (hNtdll == nullptr)
	{
		LogHelper::PrintLog(LogLevel::Error, "Failed to load ntdll.dll");
		return false;
	}

	//NtQueryInformationProcess
	m_NTDLL_NtQueryInformationProcess = (NtQueryInformationProcess_FunType) ::GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (m_NTDLL_NtQueryInformationProcess == nullptr)
	{
		LogHelper::PrintLog(LogLevel::Error, "Failed to load NTDLL_NtQueryInformationProcess");
		return false;
	}

	::FreeLibrary(hNtdll);

	if (sizeof(size_t) == 4) //x32
	{
		m_closeHandleFunSize = 0xBE;
		m_architectureSpecificCallDllName_1 = Kernel_Base_Lib_Name;
		m_architectureSpecificCallDllName_2 = Bcryptprimitives_Lib_Name;
	}
	else
	{
		m_closeHandleFunSize = 0xDD;
		m_architectureSpecificCallDllName_1 = Ntdll_Lib_Name;
		m_architectureSpecificCallDllName_2 = Kernel_Base_Lib_Name;
	}

	return true;
}

void MemoryAnalysis::deInit()
{

}

bool MemoryAnalysis::performMemoryAnalysis(std::wstring wzFileName)
{
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	si.cb = sizeof(si);
	if (!::CreateProcessW(wzFileName.data(), NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi))
	{
		std::wstring msg = L"Failed to create process for: " + wzFileName;
		LogHelper::PrintLog(LogLevel::Error, msg.data());
		return false;
	}

	PVOID pebBeingDebuggedAddr = nullptr;
	bool processFinished = false;
	
	ASSERT_BOOL(interceptNtDll32(pi.hProcess, pi.hThread, pebBeingDebuggedAddr));
	LogHelper::PrintLog(LogLevel::Info, "Successful to getting beindDebugged flag address");

	ASSERT_BOOL(setHardwareBreakpoint(pi.hThread, (ULONG_PTR)pebBeingDebuggedAddr, 0, Access::Read_Write, 1));
	LogHelper::PrintLog(LogLevel::Info, "Successful to set breakpoint on beindDebugged");

	ASSERT_BOOL(debugLoop(pi, processFinished));
	LogHelper::PrintLog(LogLevel::Info, "Process debugged succesfully");

	//analyze break addresses
	analyzeBreakAddresses();

	if (!processFinished)
	{
		::ResumeThread(pi.hThread);
		DWORD dwRet = ::WaitForSingleObject(pi.hProcess, INFINITE);
	}

	return true;
}

bool MemoryAnalysis::interceptNtDll32(HANDLE hProcess, HANDLE hThread, PVOID& pebBeingDebuggedAddr)
{
	if (!hProcess || !hThread)
	{
		return false;
	}

	PROCESS_BASIC_INFORMATION pbi;


	if (m_NTDLL_NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), NULL))
	{
		LogHelper::PrintLog(LogLevel::Error, "Failed to read process basic information");
		return false;
	}

	PVOID peb32addr = (char *)pbi.PebBaseAddress;

	pebBeingDebuggedAddr = (BYTE*)peb32addr + 2;

	LogHelper::PrintLog(LogLevel::Error, "peb32addr: ", (int) (ULONG_PTR)pebBeingDebuggedAddr);

	return true;
}

bool MemoryAnalysis::debugLoop(PROCESS_INFORMATION pi, bool& processFinished)
{
	bool printVerboseConsoleLogs = false;
	
	::DebugActiveProcess(pi.dwProcessId);

	DEBUG_EVENT dbgEvent;
	while (true)
	{
		DWORD dwContinueStatus = DBG_CONTINUE;
		if (::WaitForDebugEventEx(&dbgEvent, INFINITE) == 0)
		{
			::ResumeThread(pi.hThread);
			continue;
		}

		switch (dbgEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			const CREATE_PROCESS_DEBUG_INFO& info = dbgEvent.u.CreateProcessInfo;
			if (printVerboseConsoleLogs)
				std::cout << "Process Created. Pid: " << ::GetProcessId(info.hProcess) << std::endl;

			break;
		}
		case EXIT_PROCESS_DEBUG_EVENT:
		{
			const EXIT_PROCESS_DEBUG_INFO& info = dbgEvent.u.ExitProcess;
			if (printVerboseConsoleLogs)
				std::cout << "Process finished. ExitCode: " << info.dwExitCode << std::endl;
			processFinished = true;
			break;
		}
		case CREATE_THREAD_DEBUG_EVENT:
		{
			const CREATE_THREAD_DEBUG_INFO& info = dbgEvent.u.CreateThread;
			if (printVerboseConsoleLogs)
				std::cout << "Thread created. Tid: " << ::GetThreadId(info.hThread) << std::endl;
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT:
		{
			const EXIT_THREAD_DEBUG_INFO& info = dbgEvent.u.ExitThread;
			DWORD tid = info.dwExitCode;
			if (printVerboseConsoleLogs)
				std::cout << "Thread finished. Exit Code:  " << tid << std::endl;
			break;
		}
		case LOAD_DLL_DEBUG_EVENT:
		{
			const LOAD_DLL_DEBUG_INFO& info = dbgEvent.u.LoadDll;

			std::string infoStr;
			std::string fileName;
			ULONG_PTR fileSize;
			if (getFileInfo(info.hFile, fileName, fileSize, infoStr))
			{
				m_vecDllAddresses.push_back(info.lpBaseOfDll);
				m_mapDllBase_On_PairDLLEndAndDllName[info.lpBaseOfDll] = { (PVOID)((ULONG_PTR)info.lpBaseOfDll + fileSize), fileName };
				if(printVerboseConsoleLogs)
					std::cout << "Dll loaded. BaseAddr: " << std::hex << info.lpBaseOfDll << " "<< infoStr<< std::endl;
			}
			else
			{
				if (printVerboseConsoleLogs)
					std::cout << "Dll loaded. BaseAddr: " << std::hex << info.lpBaseOfDll << std::endl;
			}
				
			break;
		}
		case UNLOAD_DLL_DEBUG_EVENT:
		{
			const UNLOAD_DLL_DEBUG_INFO& info = dbgEvent.u.UnloadDll;
			if (printVerboseConsoleLogs)
				std::cout << "Dll unloaded. BaseAddr: " << std::hex << info.lpBaseOfDll << std::endl;
			break;
		}
		case EXCEPTION_DEBUG_EVENT:
		{
			const EXCEPTION_RECORD& er = dbgEvent.u.Exception.ExceptionRecord;
			if (er.ExceptionCode == EXCEPTION_BREAKPOINT)
			{
				//dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				if (dbgEvent.u.Exception.dwFirstChance)
				{
					//should I process it?
				}
			}
			else if (er.ExceptionCode == EXCEPTION_SINGLE_STEP)
			{
				if (printVerboseConsoleLogs)
					std::cout << "ExceptionAddress: " << std::hex << er.ExceptionAddress << std::endl;
					
				if (m_mapBreakAddressessToOccurrance.count(er.ExceptionAddress) < 1)
				{
					m_mapBreakAddressessToOccurrance[er.ExceptionAddress] = 1;
					m_vecExceptionAddresses.push_back(er.ExceptionAddress);
				}
				else
					m_mapBreakAddressessToOccurrance[er.ExceptionAddress]++;
				
			}
			break;
		}
		case OUTPUT_DEBUG_STRING_EVENT:
		{
			OUTPUT_DEBUG_STRING_INFO & info = dbgEvent.u.DebugString;
			if (printVerboseConsoleLogs)
			{
				if (info.fUnicode)
				{
					std::wstring msg;
					msg.resize(info.nDebugStringLength);
					SIZE_T readBytes;
					if (::ReadProcessMemory(pi.hProcess, info.lpDebugStringData, (PVOID)msg.data(), info.nDebugStringLength, &readBytes))
					{
						std::wcout << L"UNICODE: " << msg << std::endl;
					}
				}
				else
				{
					std::string msg;
					msg.resize(info.nDebugStringLength);
					SIZE_T readBytes;
					if (::ReadProcessMemory(pi.hProcess, info.lpDebugStringData, (PVOID)msg.data(), info.nDebugStringLength, &readBytes))
					{
						std::cout << "ANSI: " << std::hex << atoi(msg.data()) << std::endl;
					}
				}
			}
			
			break;
		}
		}

		if (processFinished)
			break;

		::ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, dwContinueStatus);
	}
	return true;
}

bool MemoryAnalysis::getDllFromAddress(PVOID address, std::string& refDllName, bool& refIsCloseHandle)
{
	refIsCloseHandle = false;
	for (std::vector<PVOID>::iterator it = m_vecDllAddresses.end() - 1; it != m_vecDllAddresses.begin(); --it)
	{
		if (*it < address)
		{
			if (address < m_mapDllBase_On_PairDLLEndAndDllName[*it].dllEnd)
			{
				auto dllName = m_mapDllBase_On_PairDLLEndAndDllName[*it].dllName;

				//begin: check CloseHandle
				if (!dllName.compare(Kernel_Base_Lib_Name) == 0)
				{
					ULONG_PTR currRelativeAddr = (ULONG_PTR)address - (ULONG_PTR)*it;

					if (currRelativeAddr > m_relativeCloseHandleAddr)
					{
						//so it is some code after closeHandle begin. CHeck if it is closeHandle or other following func
						ULONG_PTR relativeAddressFromCloseHandleBegin = currRelativeAddr - m_relativeCloseHandleAddr;
						if (relativeAddressFromCloseHandleBegin < m_closeHandleFunSize)
						{
							//probably closeHandle
							refIsCloseHandle = true;
						}
					}
				}
				//end: check CloseHandle

				refDllName = dllName;
				return true;
			}
			else
			{
				//log it
				LogHelper::PrintLog(LogLevel::Warning, "Failed to recognize dll. Check it");
				return false;
			}

		}
	}
	return false;
}

std::vector<std::string> MemoryAnalysis::split(std::string inputString, std::string delimiter)
{
	std::vector<std::string> output;
	std::string input = inputString;
	size_t pos = 0;
	std::string token;
	while ((pos = input.find(delimiter)) != std::string::npos) {
		token = input.substr(0, pos);
		output.push_back(token);
		input.erase(0, pos + delimiter.length());
	}
	output.push_back(input);
	return output;
}

bool MemoryAnalysis::getFileInfo(HANDLE hFile, std::string& refFileName, ULONG_PTR& refFileSize, std::string& refStr)
{
	refStr = "";
	char buffer[MAX_PATH] = { 0 };
	if (!::GetFinalPathNameByHandleA(hFile, buffer, sizeof(buffer), FILE_NAME_NORMALIZED | VOLUME_NAME_NONE))
	{
		LogHelper::PrintLog(LogLevel::Warning, "Can't get a file path from handle");
		return false;
	}

	auto vec = split(buffer, "\\");
	if (vec.size() == 0)
	{
		LogHelper::PrintLog(LogLevel::Warning, "Failed to split");
		return false;
	}
	refFileName = vec.back();
	refStr += "FileName: " + refFileName;

	DWORD higher;
	DWORD lower = ::GetFileSize(hFile, &higher);
	if (lower == INVALID_FILE_SIZE)
	{
		LogHelper::PrintLog(LogLevel::Warning, "Failed to to get file name");
		return false;
	}

	refFileSize = 0;
	if (sizeof(size_t) == 4) //x32
	{
		refFileSize = lower;
	}
	else
	{
		refFileSize = ((ULONG_PTR)higher << 32) + lower;
	}
	refStr += " FileSize: " + int_to_hex(refFileSize);
	return true;
}

bool MemoryAnalysis::checkIfItIsTypicalBreak(size_t i, const size_t exceptionListCount, std::string dllName)
{
	switch (i)
	{
	case 0:
		if (dllName.compare(Ntdll_Lib_Name) == 0) //everything ok
			return true;
		break;

	case 1:
		if (dllName.compare(Kernel32_Lib_Name) == 0) //everything ok
			return true;
		break;

	case 2:
		if (dllName.compare(Ntdll_Lib_Name) == 0) //everything ok
			return true;
		break;

	default:

		if (i == exceptionListCount - 3 && dllName.compare(m_architectureSpecificCallDllName_1) == 0)
			return true;
		else if (i == exceptionListCount - 2 && dllName.compare(m_architectureSpecificCallDllName_2) == 0)
			return true;
		else if (i == exceptionListCount - 1 && dllName.compare(Rpcrt4_Lib_Name) == 0)
			return true;
	}

	return false;
}

bool MemoryAnalysis::analyzeBreakAddresses()
{
	std::sort(m_vecDllAddresses.begin(), m_vecDllAddresses.end());

	if (m_vecExceptionAddresses.size() < 6)
	{
		LogHelper::PrintLog(LogLevel::Warning, "Exception number is less than 6");
		return false;
	}

	const size_t exceptionCount = m_vecExceptionAddresses.size();
	
	for (size_t i = 0; i < exceptionCount; i++)
	{

		std::string dllName;
		bool isCloseHandle;
		PVOID breakAddress = m_vecExceptionAddresses[i];
		if (getDllFromAddress(breakAddress, dllName, isCloseHandle))
		{
			//dll
			std::stringstream stream;
			stream << "Address: " << breakAddress << " triggered " << m_mapBreakAddressessToOccurrance[breakAddress] <<
				" time and belongs to " << dllName << " section.";

			if (isCloseHandle)
				stream << " Probably CloseHandle()";

			if (checkIfItIsTypicalBreak(i, exceptionCount, dllName))
			{
				LogHelper::PrintLog(LogLevel::Info, stream.str().data());
				
			}
			else
			{
				//report
				LogHelper::PrintReport(stream.str().data());
			}
		}
		else
		{
			//code
			std::stringstream stream;
			stream << "Address: " << breakAddress << " triggered " << m_mapBreakAddressessToOccurrance[breakAddress] <<
				" time and belongs to code section";
			LogHelper::PrintReport(stream.str().data());
		}
	}
	return true;
}