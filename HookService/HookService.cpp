#include "HookService.h"
#include <iostream>
BYTE* HookCreator::getBufferWithOriginFun(LPVOID pOriginFun)
{
	LPVOID pNewFun = m_mapOriginFunToNewFun[pOriginFun];
	return m_mapNewFunToOriginFunPrologBuf[pNewFun].data();
}

bool HookCreator::restoreOriginFun(LPVOID pOriginFun, BYTE jmpBuffer[16])
{
	//set read write permits 
	DWORD oldProtect = 0, dummy = 0;
	ASSERT_BOOL(::VirtualProtect(pOriginFun, JMP_BUF_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect));
	::memcpy(jmpBuffer, pOriginFun, JMP_BUF_SIZE);

	LPVOID pNewFun = m_mapOriginFunToNewFun[pOriginFun];
	::memcpy(pOriginFun, m_mapNewFunToOriginFunPrologBuf[pNewFun].data(), JMP_BUF_SIZE);
	ASSERT_BOOL(::VirtualProtect(pOriginFun, JMP_BUF_SIZE, oldProtect, &dummy));
	return true;
}

bool HookCreator::restoreHook(LPVOID pOriginFun, BYTE jmpBuffer[16])
{
	//set read write permits 
	DWORD oldProtect = 0, dummy = 0;
	ASSERT_BOOL(::VirtualProtect(pOriginFun, JMP_BUF_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect));

	//restore hook
	::memcpy(pOriginFun, jmpBuffer, JMP_BUF_SIZE);

	//restore permits
	ASSERT_BOOL(::VirtualProtect(pOriginFun, JMP_BUF_SIZE, oldProtect, &dummy));
	return true;
}

/*
absolute jmp
	to consider:
	 9A cp CALL ptr16:32 Call far, absolute, address given in operand
*/
void HookCreator::createJmp(ULONG_PTR pFun, BYTE jmpBuffer[16])
{
	//set buffer
	::memset(jmpBuffer, 0xCC, JMP_BUF_SIZE);

	BYTE* ptr = jmpBuffer;

	*(WORD*)ptr = Far_Jmp_Opc;
	ptr += sizeof(Far_Jmp_Opc);
#ifndef _WIN64
	//x32
	*(DWORD*)ptr = (DWORD)ptr + sizeof(DWORD);
#else
	*(DWORD*)ptr = 0;
#endif
	ptr += sizeof(DWORD);

	*(ULONG_PTR*)ptr = pFun;
}

bool HookCreator::createHook(LPVOID pOriginFun, LPVOID pNewFun)
{
	//up -> ULONG_PTR
	ULONG_PTR upNewFun = (ULONG_PTR)pNewFun;

	//set read write permits 
	DWORD oldProtect = 0;
	ASSERT_BOOL(::VirtualProtect(pOriginFun, JMP_BUF_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect));

	//create originFunPrologBuf and set there execute permission
	::memcpy(m_mapNewFunToOriginFunPrologBuf[pNewFun].data(), pOriginFun, JMP_BUF_SIZE);
	m_mapNewFunToOriginFunToRestoreFun[pNewFun] = m_mapNewFunToOriginFunPrologBuf[pNewFun];
	
	BYTE* originFunPrologBuf = m_mapNewFunToOriginFunPrologBuf[pNewFun].data();

	//often there is relative jmp at the beginning
	bool thereIsAJump = false;
	BYTE* currMem = originFunPrologBuf;
	size_t relativeAddressPosition = 0;
	for (size_t i = 0; i < JMP_BUF_SIZE - sizeof(Far_Jmp_Opc); i++)
	{
		if (*((WORD*)currMem) == Far_Jmp_Opc)
		{
			//here is jmp
			relativeAddressPosition = i + sizeof(Far_Jmp_Opc);
			thereIsAJump = true;
			break;
		}
		currMem++;
	}

	if (thereIsAJump)
	{
#ifndef _WIN64

		ULONG_PTR pTargetedFunAddress = *((DWORD*)(originFunPrologBuf + relativeAddressPosition));
		//ULONG_PTR pTargetedFunAddress = (ULONG_PTR)pOriginFun + relativeAddress + relativeAddressPosition + sizeof(DWORD);
		ULONG_PTR pTargetedFun = *(ULONG_PTR*)pTargetedFunAddress;
		createJmp(pTargetedFun, originFunPrologBuf + relativeAddressPosition - sizeof(Far_Jmp_Opc));
#else
		ULONG_PTR relativeAddress = *((DWORD*)(originFunPrologBuf + relativeAddressPosition));
		ULONG_PTR pTargetedFunAddress = (ULONG_PTR)pOriginFun + relativeAddress + relativeAddressPosition + sizeof(DWORD);
		ULONG_PTR pTargetedFun = *(ULONG_PTR*)pTargetedFunAddress;
		createJmp(pTargetedFun, originFunPrologBuf + relativeAddressPosition - 1 - sizeof(Far_Jmp_Opc));
#endif
	}
	else
	{
		createJmp(upNewFun + JMP_BUF_SIZE, originFunPrologBuf + JMP_BUF_SIZE);
	}

	DWORD dummy = 0;
	ASSERT_BOOL(::VirtualProtect(originFunPrologBuf, PROLOG_FUN_BUF_SIZE, PAGE_EXECUTE_READWRITE, &dummy));
	//end


	//replace origin fun prolog with jmp to our newFun
	createJmp(upNewFun, (BYTE*)pOriginFun);

	//restore old permits for orginFun
	ASSERT_BOOL(::VirtualProtect(pOriginFun, JMP_BUF_SIZE, oldProtect, &dummy));

	m_mapOriginFunToNewFun[pOriginFun] = pNewFun;
	return true;
}

bool HookCreator::disableHook(LPVOID pOriginFun)
{
	DWORD oldProtect = 0;
	::VirtualProtect(pOriginFun, JMP_BUF_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);

	ASSERT_BOOL(m_mapOriginFunToNewFun.count(pOriginFun) > 0);
	LPVOID pNewFun = m_mapOriginFunToNewFun[pOriginFun];

	ASSERT_BOOL(m_mapNewFunToOriginFunToRestoreFun.count(pNewFun) > 0);
	BYTE* originFunPrologBuf = m_mapNewFunToOriginFunToRestoreFun[pNewFun].data();
	::memcpy(pOriginFun, originFunPrologBuf, JMP_BUF_SIZE);

	DWORD dummy = 0;
	ASSERT_BOOL(::VirtualProtect(pOriginFun, JMP_BUF_SIZE, oldProtect, &dummy));

	//we can restore previous permits for buffer but it is not neccessary, because in next step we erase it
	//ASSERT_BOOL(::VirtualProtect(originFunPrologBuf, JMP_BUF_SIZE, bufferOldProtect, &dummy));
	m_mapNewFunToOriginFunToRestoreFun.erase(pNewFun);
	m_mapNewFunToOriginFunPrologBuf.erase(pNewFun);
	m_mapOriginFunToNewFun.erase(pOriginFun);
	return true;
}
