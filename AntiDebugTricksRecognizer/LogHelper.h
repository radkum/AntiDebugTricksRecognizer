#pragma once
#include <fstream>

enum class ReportOutput
{
	Undefined,
	Std,
	File,
};

enum class LogLevel
{
	Info,
	Warning,
	Error,
};

class LogHelper
{
private:
	static std::ofstream logFile;
	static std::ofstream reportFile;
	static ReportOutput reportFileOutputType;

private:
	static std::string ws2s(const std::wstring& wstr);

public:
	static bool init(const char* reportFilePath, const char* logFilePath);
	static void init(const char* reportFilePath);
	static void init();
	static void deinit();

	static void PrintLog(LogLevel lvl, const char* msg);
	static void PrintLog(LogLevel lvl, const wchar_t* msg);
	static void PrintLog(LogLevel lvl, const char* msg, int val);
	static void PrintLog(LogLevel lvl, const wchar_t* msg, int val);

	static void PrintReport(const char* msg);
};