#pragma once
#include <Windows.h>

enum Access
{
	None = 0,
	Write = 1,
	Read_Write = 3
};

bool setHardwareBreakpoint(HANDLE hThread, ULONG_PTR bpAddress, size_t index, Access access, size_t size);
ULONG_PTR getHardwareBreakpoint(HANDLE hThread, size_t index);