#include "ApiCallAnalysis.h"
#include "LogHelper.h"

bool performApiCallAnalysis(std::wstring wzFileName, std::string apiCallsReportPath)
{
	//create suspended process
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	si.cb = sizeof(si);

	const char envVarName[] = "REPORT_FILE_PATH=";
	const size_t envVarNameLenght = sizeof(envVarName) - 1;

	char * envVarBuffer = new char[sizeof(envVarName) + apiCallsReportPath.size() + 1]{ 0 };
	::memcpy(envVarBuffer, envVarName, envVarNameLenght);
	::memcpy(envVarBuffer + envVarNameLenght, apiCallsReportPath.data(), apiCallsReportPath.size());

	LogHelper::PrintLog(LogLevel::Info, envVarBuffer);

	if (!::CreateProcessW(wzFileName.data(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, (LPVOID)envVarBuffer, NULL, &si, &pi))
	{
		LogHelper::PrintLog(LogLevel::Error, "Failed to create process to perform ApiCallAnalysis");
		return false;
	}

	delete[] envVarBuffer;

	//get process handle
	const std::wstring libPath = L"HookPerformer.dll";
	if (!injectDll(pi.hProcess, libPath))
	{
		LogHelper::PrintLog(LogLevel::Error, "Failed to inject dll");
	}
	// Modify suspended process

	::ResumeThread(pi.hThread);
	DWORD dwRet = ::WaitForSingleObject(pi.hProcess, INFINITE);
	return true;
}

DWORD injectDll(HANDLE hProcess, std::wstring libPath)
{
	DWORD hLibModule;
	HMODULE hKernel32 = ::GetModuleHandleW(L"Kernel32");

	size_t libPathBufferSize = (libPath.size() + 1) * sizeof(wchar_t);
	if (libPath.size() > MAX_PATH)
	{
		LogHelper::PrintLog(LogLevel::Error, "Incorrect dll path to inject");
		return NULL;
	}
	WCHAR libPathBuffer[MAX_PATH];
	wcsncpy_s(libPathBuffer, libPath.data(), libPath.size());

	// 1. Allocate memory in the remote process for szLibPath
	// 2. Write szLibPath to the allocated memory
	VOID* pRemoteLibPathAddress = ::VirtualAllocEx(hProcess, NULL, libPathBufferSize,
		MEM_COMMIT, PAGE_READWRITE);

	::WriteProcessMemory(hProcess, pRemoteLibPathAddress, (VOID*)libPath.data(),
		libPathBufferSize, NULL);

	//Load DLL into the remote process

	LPTHREAD_START_ROUTINE loadLibraryWProcAddress =
		(LPTHREAD_START_ROUTINE) ::GetProcAddress(hKernel32, "LoadLibraryW");

	HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0,
		loadLibraryWProcAddress, pRemoteLibPathAddress, 0, NULL);

	if (hThread == NULL)
	{
		LogHelper::PrintLog(LogLevel::Error, "Error. Can't createRemoteThread ");
		return NULL;
	}

	::WaitForSingleObject(hThread, INFINITE);

	//Get handle of the loaded module
	::GetExitCodeThread(hThread, &hLibModule);

	::CloseHandle(hThread);
	::VirtualFreeEx(hProcess, pRemoteLibPathAddress, libPathBufferSize, MEM_RELEASE);
	return hLibModule;
}