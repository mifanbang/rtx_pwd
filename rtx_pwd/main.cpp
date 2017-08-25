/*
 *  Copyright (C) 2011-2017 Mifan Bang <https://debug.tw>.
 *  This program is licensed under the MIT License
 */

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <stdio.h>



using DecryptProc = DWORD(*)(char* cipher, int cipher_size, wchar_t* key, char* buffer, int* buffer_size);



// only for Vista and later
const wchar_t* GetRTXConfigPath()
{
	static wchar_t szPath[MAX_PATH];
	SHGetFolderPath(NULL, CSIDL_MYDOCUMENTS, NULL, 0, szPath);
	PathAppend(szPath, L"RTXC File List\\C_Program Files (x86)_Tencent_RTXC\\Accounts\\rtx.cfg");
	return szPath;
}


// only for Vista and later
const wchar_t* GetRTXCryptModulePath()
{
	static wchar_t szPath[MAX_PATH] = L"C:\\Program Files (x86)\\Tencent\\RTXC\\crypt.dll";
	return szPath;
}


wchar_t* GetRTXConfigContent()
{
	HANDLE hFile = CreateFile(GetRTXConfigPath(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;

	DWORD fileSize = GetFileSize(hFile, NULL);
	DWORD dwRead;
	char* fileData = new char[fileSize + 2];
	ReadFile(hFile, fileData, fileSize, &dwRead, NULL);
	fileData[fileSize] = fileData[fileSize + 1] = NULL;
	CloseHandle(hFile);

	return (wchar_t*)fileData;
}


void ReleaseRTXConfigContent(wchar_t* data)
{
	if (data != NULL)
		delete[] data;
}


DWORD GetRTXPasswordFromConfig()
{
	HMODULE hMod = LoadLibrary(GetRTXCryptModulePath());
	if (hMod == NULL) {
		DWORD lastErr = GetLastError();
		puts("cannot load crypt.dll. exiting!");
		return lastErr;
	}

	FARPROC proc = GetProcAddress(hMod, "oi_symmetry_decrypt2");
	if (proc == NULL) {
		DWORD lastErr = GetLastError();
		puts("cannot find oi_symmetry_decrypt2() in crypt.dll. exiting!");
		return lastErr;
	}

	wchar_t* fileContent = GetRTXConfigContent();
	if (fileContent == NULL) {
		DWORD lastErr = GetLastError();
		puts("cannot open RTX config file. exiting!");
		return lastErr;
	}
	if (wcsstr(fileContent, L"nSavePwd=1") == NULL) {
		puts("RTX didn't save your password.");
		return -1;
	}
	wchar_t* rawPass = wcsstr(fileContent, L"strPassword=");
	if (rawPass == NULL) {
		puts("unable to match pattern of saved password in config file. exiting!");
		return -1;
	}
	char cipher[128];
	int cipherSize = 0;
	rawPass += 12;  // strlen("strPassword=") = 12
	int rawSize = wcsstr(rawPass, L"\r\n") - rawPass;
	for (int i = 0; i < rawSize; i += 2) {
		char buffer = 0;

		if (rawPass[i] - 0x30 < 10)
			buffer += (rawPass[i] - 0x30) << 4;
		else
			buffer += ((rawPass[i] - 0x41) + 10) << 4;

		if (rawPass[i + 1] - 0x30 < 10)
			buffer += rawPass[i + 1] - 0x30;
		else
			buffer += (rawPass[i + 1] - 0x41) + 10;

		if (buffer == 0)
			break;
		cipher[cipherSize++] = buffer;
	}

	char plain[0x400];
	int plainSize = sizeof(plain);
	WCHAR key[8] = L"RTX!3";
	DecryptProc decrypt = reinterpret_cast<DecryptProc>(proc);
	if (decrypt(cipher, cipherSize, key, plain, &plainSize) > 0) {
		plain[plainSize] = NULL;
		plain[plainSize + 1] = NULL;
		wprintf(L"your password is: %s\n", plain);
	}
	else {
		puts("failed to decrypt saved password");
		ReleaseRTXConfigContent(fileContent);
		return -1;
	}

	ReleaseRTXConfigContent(fileContent);

	return NO_ERROR;
}


DWORD GetSystemPageSize()
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	return sysInfo.dwPageSize;
}


DWORD GetRTXPasswordFromProcess()
{
	DWORD dwPid = 0xFFFFFFFF;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);
	Process32First(snapshot, &procEntry);
	if (_wcsicmp(procEntry.szExeFile, L"RTX.exe") != 0) {
		while (Process32Next(snapshot, &procEntry)) {
			if (_wcsicmp(procEntry.szExeFile, L"RTX.exe") == 0) {
				dwPid = procEntry.th32ProcessID;
				break;
			}
		}
	}
	else {
		dwPid = procEntry.th32ProcessID;
	}
	CloseHandle(snapshot);

	if (dwPid == 0xFFFFFFFF) {
		DWORD lastErr = GetLastError();
		puts("cannot find RTX process.");
		return lastErr;
	}

	printf("RTX pid: %d\n", dwPid);
	HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, dwPid);
	if (hProc == NULL) {
		DWORD lastErr = GetLastError();
		puts("failed to open RTX process.");
		return lastErr;
	}

	// first pass, find related structure
	MEMORY_BASIC_INFORMATION memInfo;
	DWORD baseAddr = 0;
	DWORD pwdStrAddr;
	while (baseAddr < 0x7FFF0000) {
		SIZE_T result = VirtualQueryEx(hProc, (LPCVOID)baseAddr, &memInfo, sizeof(memInfo));
		if (result == 0) {
			puts("failed to query RTX memory.");
			CloseHandle(hProc);
			return GetLastError();
		}
		if (memInfo.State == MEM_COMMIT && memInfo.Type != MEM_IMAGE && memInfo.Protect == PAGE_READWRITE) {
			DWORD dwRead;
			wchar_t strAccountType[] = L"AccountType";
			wchar_t strPassword[] = L"Password";

			char* buffer = new char[memInfo.RegionSize];
			ReadProcessMemory(hProc, memInfo.BaseAddress, buffer, memInfo.RegionSize, &dwRead);
			for (unsigned int i = 0; i < memInfo.RegionSize - 0x2D0; i++) {
				if (memcmp(buffer + i, (void*)strAccountType, sizeof(strAccountType) - 2) == 0) {
					if (memcmp(buffer + i + 0x240, (void*)strPassword, sizeof(strPassword) - 2) == 0)
						pwdStrAddr = baseAddr + i + 0x240;  // address of L"Password" string
				}
			}
			delete[] buffer;
		}
		baseAddr += memInfo.RegionSize;
	}

	// second pass, find actual password
	bool isPwdFound = false;
	baseAddr = 0;
	while (baseAddr < 0x7FFF0000) {
		SIZE_T result = VirtualQueryEx(hProc, (LPCVOID)baseAddr, &memInfo, sizeof(memInfo));
		if (result == 0) {
			puts("failed to query RTX memory.");
			CloseHandle(hProc);
			return GetLastError();
		}
		if (memInfo.State == MEM_COMMIT && memInfo.Type != MEM_IMAGE && memInfo.Protect == PAGE_READWRITE) {
			DWORD dwRead;

			char* buffer = new char[memInfo.RegionSize];
			ReadProcessMemory(hProc, memInfo.BaseAddress, buffer, memInfo.RegionSize, &dwRead);
			for (unsigned int i = 0; i < memInfo.RegionSize - 4; i += 4) {
				if (*(DWORD*)(buffer + i) == pwdStrAddr) {
					wchar_t plain[32];
					ReadProcessMemory(hProc, (LPCVOID)*((DWORD*)(buffer + i) + 1), plain, sizeof(plain), &dwRead);
					wprintf(L"your password is: %s\n", plain);
					isPwdFound = true;
					break;
				}
			}
			delete[] buffer;
		}
		baseAddr += memInfo.RegionSize;
	}

	CloseHandle(hProc);

	if (!isPwdFound) {
		puts("failed to find password in RTX process.");
		return -1;
	}
	else {
		return NO_ERROR;
	}
}


BOOL EnableDebugPrivilege(BOOL bEnable)
{
	BOOL fOK = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOK = (GetLastError() == NO_ERROR);
		CloseHandle(hToken);
	}
	return fOK;
}


int main()
{
	DWORD result;

	EnableDebugPrivilege(TRUE);

	puts("try to obtain saved password from config file...");
	result = GetRTXPasswordFromConfig();
	if (result != NO_ERROR) {
		if ((int)result > 0)
			printf("ErrorCode: %d\n", result);
		putchar('\n');

		puts("try to obtain password from running RTX process...");
		result = GetRTXPasswordFromProcess();
		if (result != NO_ERROR)
			printf("ErrorCode: %d\n", result);
	}

	system("pause");

	return result;
}

