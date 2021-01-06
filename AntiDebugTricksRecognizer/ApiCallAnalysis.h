#pragma once
#include <iostream>

#include "Windows.h"

bool performApiCallAnalysis(std::wstring wzFileName, std::string apiCallsReportPath);
DWORD injectDll(HANDLE hProcess, std::wstring libPath);