#include "HardwareBreakpoint.h"

void setBits(ULONG_PTR& targetDw, size_t firstBit, size_t bitsNum, size_t newValue)
{
	int mask = (1 << bitsNum) - 1; // e.g. 1 becomes 0001, 2 becomes 0011, 3 becomes 0111

	targetDw = (targetDw & ~(mask << firstBit)) | (newValue << firstBit);
}

void turnOnBp(ULONG_PTR& bp, size_t index)
{
	setBits(bp, index * 2, 1, 1);
}

void turnOffBp(ULONG_PTR& bp, size_t index)
{
	setBits(bp, index * 2, 1, 0);
}

void setBpSize(ULONG_PTR& bp, size_t index, size_t size)
{
	setBits(bp, 18 + (index * 4), 2, size);
}

void setBpAccess(ULONG_PTR& bp, size_t index, Access access)
{
	setBits(bp, 16 + (index * 4), 2, access);
}

bool setHardwareBreakpoint(HANDLE hThread, ULONG_PTR bpAddress, size_t index, Access access, size_t size)
{
	if (index > 3)
	{
		return false;
	}

	if (--size > 3)
	{
		return false;
	}

	CONTEXT context = {};
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (::GetThreadContext(hThread, &context))
	{
		ULONG_PTR* currDrAddr = ((ULONG_PTR*)&context.Dr0 + index);
		*currDrAddr = bpAddress;
		setBpAccess(context.Dr7, index, access);
		setBpSize(context.Dr7, index, size);
		turnOnBp(context.Dr7, index);

		::SetThreadContext(hThread, &context);
	}
	return true;
}

ULONG_PTR getHardwareBreakpoint(HANDLE hThread, size_t index)
{
	CONTEXT context = {};
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (::GetThreadContext(hThread, &context))
	{
		return *((ULONG_PTR*)&context.Dr0 + index);
	}
	return 0;
}