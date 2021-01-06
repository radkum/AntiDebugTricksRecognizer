#pragma once

#include <SDKDDKVer.h>

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

#include <map>
#include <array>

#define ASSERT_BOOL(x)		if((x) == false) return false;
#define JMP_BUF_SIZE		16
#define PROLOG_FUN_BUF_SIZE 2*JMP_BUF_SIZE
constexpr WORD Far_Jmp_Opc = 0x25FF;

class HookCreator
{
private:
	//members
	std::map<LPVOID, std::array<BYTE, PROLOG_FUN_BUF_SIZE>> m_mapNewFunToOriginFunPrologBuf;
	std::map<LPVOID, std::array<BYTE, PROLOG_FUN_BUF_SIZE>> m_mapNewFunToOriginFunToRestoreFun;
	std::map<LPVOID, LPVOID> m_mapOriginFunToNewFun;

	//methods
	void createJmp(ULONG_PTR pFun, BYTE jmpBuffer[16]);

public:
	bool createHook(LPVOID pOriginFun, LPVOID pNewFun);
	bool disableHook(LPVOID pOriginFun);

	BYTE* getBufferWithOriginFun(LPVOID currFun);
	bool restoreOriginFun(LPVOID pOriginFun, BYTE jmpBuffer[16]);
	bool restoreHook(LPVOID pOriginFun, BYTE jmpBuffer[16]);
};