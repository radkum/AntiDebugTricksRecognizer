#include <iostream>
#include <string>
#include <fstream>
#include <locale>
#include <codecvt>

#include "LogHelper.h"

std::ofstream LogHelper::logFile;
std::ofstream LogHelper::reportFile;
ReportOutput LogHelper::reportFileOutputType = ReportOutput::Undefined;

bool LogHelper::init(const char* reportFilePath, const char* logFilePath)
{
	logFile.open(logFilePath);
	if (!logFile)
	{
		logFile.open("logFile.txt");
		if (!logFile)
		{
			return false;
		}
	}

	init(reportFilePath);
	return true;
}

void LogHelper::init(const char* reportFilePath)
{
	reportFile.open(reportFilePath);
	reportFileOutputType = ReportOutput::File;

	if (!reportFile)
	{
		init();
	}
}

void LogHelper::init()
{
	reportFileOutputType = ReportOutput::Std;
}

void LogHelper::deinit()
{
	if (logFile)
		logFile.close();

	if (reportFile)
		reportFile.close();
}

void LogHelper::PrintLog(LogLevel lvl, const char* msg)
{
	const char * logLevelStr = "";
	if (lvl == LogLevel::Warning)
	{
		logLevelStr = "Warning: ";
	}
	else if (lvl == LogLevel::Error)
	{
		logLevelStr = "ERROR: ";
	}

	logFile << logLevelStr << msg << std::endl;
}

void LogHelper::PrintLog(LogLevel lvl, const wchar_t* msg)
{
	const char * logLevelStr = "";
	if (lvl == LogLevel::Warning)
	{
		logLevelStr = "Warning: ";
	}
	else if (lvl == LogLevel::Error)
	{
		logLevelStr = "ERROR: ";
	}
	
	logFile << logLevelStr << msg << std::endl;
}

void LogHelper::PrintLog(LogLevel lvl, const char* msg, int val)
{
	std::string stringMsg = msg + std::to_string(val);
	PrintLog(lvl, stringMsg.data());
}

void LogHelper::PrintLog(LogLevel lvl, const wchar_t* msg, int val)
{
	std::wstring wstringMsg = msg + std::to_wstring(val);
	PrintLog(lvl, wstringMsg.data());
}

void LogHelper::PrintReport(const char* msg)
{
	if (reportFileOutputType == ReportOutput::File)
	{
		reportFile << msg << std::endl;
	}
	else if (reportFileOutputType == ReportOutput::Std)
	{
		std::cout << msg << std::endl;
	}
}

//helper funcion
std::string LogHelper::ws2s(const std::wstring& wstr)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}