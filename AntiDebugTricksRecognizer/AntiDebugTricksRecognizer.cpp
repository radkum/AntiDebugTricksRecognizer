#include <iostream>
#include <string>

#include <Windows.h>

#include "LogHelper.h"
#include "ApiCallAnalysis.h"
#include "MemoryAnalysis.h"

std::string GetLastErrorAsString();
std::wstring s2ws(const std::string& str);
BOOL FileExistsA(LPCSTR szPath);

int main(int argc, char* argv[])
{
	std::string szFileName;
	std::string reportsDir = "reports";

	if (argc != 2 && argc != 3)
	{
		std::cout << "CheckAntiDebuggingTricks.exe <process_to_check> or" << std::endl;
		std::cout << "CheckAntiDebuggingTricks.exe <process_to_check> <report_dir>" << std::endl;
		return -1;
		
	}

	//get file to analyze
	if (argc >= 2)
	{
		szFileName = std::string(argv[1]);

		if (!FileExistsA(szFileName.data()))
		{
			std::cout << "Given msi file not exists" << std::endl;
			return -3;
		}
	}

	//get output dir
	if (argc == 2)
	{
		std::cout << "Default reports directory: \"reports\" " << std::endl;
	}
	else if (argc == 3)
	{
		reportsDir = std::string(argv[2]);
	}

	else
	{
		szFileName = std::string(argv[1]);
		std::cout << "CheckAntiDebuggingTricks.exe <process_to_check>" << std::endl;
		return -2;
	}
	std::wstring wzFileName = s2ws(szFileName);

	//create reports dir
	if (!::CreateDirectoryA(reportsDir.data(), NULL))
	{
		if (::GetLastError() == ERROR_ALREADY_EXISTS)
		{
			std::cout << "WARNING: Given output dir exists" << std::endl;
		}
		else
		{
			std::cout << "Can't create \"" << reportsDir << "\" dir" << std::endl;
			return -2;
		}
	}

	if (reportsDir[reportsDir.size() - 1] != '\\')
	{
		reportsDir += '\\';
	}

	std::string memoryReportName = "memoryReport.txt";
	std::string memoryReportPath = reportsDir + "memoryReport.txt";

	std::string apiCallsReportName = "apiCallsReport.txt";
	std::string apiCallsReportPath = reportsDir + "apiCallsReport.txt";

	LogHelper::init(memoryReportPath.data(), "logOutput.txt");

	if (!performApiCallAnalysis(wzFileName, apiCallsReportPath))
	{
		std::cout << "Failed to perform api call analysis: " << GetLastErrorAsString() << std::endl;
		return -1;
	}

	MemoryAnalysis mem;
	if (!mem.init() || !mem.performMemoryAnalysis(wzFileName))
	{
		std::cout << "Failed to perform read memory analysis: " << GetLastErrorAsString() << std::endl;
		return -1;
	}
	mem.deInit();
	LogHelper::deinit();

	std::cout << "SUCCESS"<< std::endl;
	return 0;
}

std::wstring s2ws(const std::string& str)
{
	int cchWideChar = ::MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(cchWideChar, 0);
	::MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], cchWideChar);
	return wstrTo;
}

std::string GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

BOOL FileExistsA(LPCSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesA(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}