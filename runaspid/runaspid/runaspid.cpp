//Modified by gaearrow @20170908

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <UserEnv.h>
#pragma comment(lib, "Userenv.lib")

//#define DEBUG 1
#define DEBUG 0

BOOL runaspid(DWORD dwPid, LPSTR lpCmdLine);

int main(int argc, char* argv[])
{
	DWORD dwPid = 0;

	if (argc == 3)
	{
		dwPid = _tstoi(argv[1]);
		if (dwPid == 0)
		{
			printf("Invalid Pid\n");
			return 0;
		}

		runaspid(dwPid, argv[2]);
		return 0;
	}

	printf("\nusage: runaspid.exe [pid] [*.exe or *.bat] \n");

	return 0;
}

BOOL runaspid(DWORD dwPid, LPSTR lpCmdLine)
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	BOOL bResult = FALSE;
	DWORD dwSessionId = 0, winlogonPid = 0;
	HANDLE hUserToken, hUserTokenDup, hPToken, hProcess;
	DWORD dwCreationFlags;


	typedef DWORD(WINAPI *__pfnWTSGetActiveConsoleSessionId)();
	typedef BOOL(WINAPI *__pfnWTSQueryUserToken)(ULONG SessionId, PHANDLE phToken);

	__pfnWTSGetActiveConsoleSessionId pfnWTSGetActiveConsoleSessionId =
		(__pfnWTSGetActiveConsoleSessionId)GetProcAddress(LoadLibraryA("kernel32.dll"), "WTSGetActiveConsoleSessionId");

	__pfnWTSQueryUserToken pfnWTSQueryUserToken =
		(__pfnWTSQueryUserToken)GetProcAddress(LoadLibraryA("Wtsapi32.dll"), "WTSQueryUserToken");

	if (pfnWTSGetActiveConsoleSessionId == NULL)
	{
		if (DEBUG) printf("WTSGetActiveConsoleSessionId Error\n");
		return 0;
	}
	if (pfnWTSQueryUserToken == NULL)
	{
		if (DEBUG) printf("WTSQueryUserToken Error\n");
		return 0;
	}

	ProcessIdToSessionId(dwPid, &dwSessionId);
	if (DEBUG) printf("SessionID is %d \n", dwSessionId);
	winlogonPid = dwPid;

	////////////////////////////////////////////////////////////////////////

	dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = "winsta0\\default";
	ZeroMemory(&pi, sizeof(pi));

	LUID luid;
	LPVOID TokenInformation;
	DWORD RetLen = 0;

	if (!pfnWTSQueryUserToken(dwSessionId, &hUserToken))
	{
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);

		if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS_P, &hPToken))
		{
			if (DEBUG) printf("Open Process Token Error: %u\n", GetLastError());
		}

		if (hPToken == NULL)
		{
			if (DEBUG) printf("Get Process Token Error\n");
		}
	}
	else
	{
		hPToken = hUserToken;
	}
	if (GetTokenInformation(hPToken, TokenLinkedToken, &TokenInformation, 4, &RetLen))
	{
		hUserTokenDup = TokenInformation;
	}
	else
	{
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			if (DEBUG) printf("Lookup Privilege value Error: %u\n", GetLastError());
		}

		if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hUserTokenDup))
		{
			if (DEBUG) printf("DuplicateTokenEx Error: %u\n", GetLastError());
		}
	}

	LPVOID pEnv = NULL;

	if (CreateEnvironmentBlock(&pEnv, hUserTokenDup, TRUE))
	{
		dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
	}
	else
	{
		if (DEBUG) printf("CreateEnvironmentBlock Failed\n");
		pEnv = NULL;
	}

	// Run the process as the client's logon session.
	bResult = CreateProcessAsUser(
		hUserTokenDup,            // client's access token
		NULL,       // file to execute
		lpCmdLine,         // command line     
		NULL,              // pointer to process SECURITY_ATTRIBUTES
		NULL,              // pointer to thread SECURITY_ATTRIBUTES
		FALSE,             // handles are not inheritable
		//0,
		dwCreationFlags,   // creation flags
		pEnv,              // pointer to new environment block
		NULL,              // name of current directory
		&si,               // pointer to STARTUPINFO structure
		&pi                // receives information about new process
		);
	// End impersonation of client.

	printf("\nProcess %d Created \n", pi.dwProcessId);
	
	//GetLastError
	int iResultOfCreateProcessAsUser = GetLastError();

	if (bResult == FALSE && iResultOfCreateProcessAsUser != 0)
	{
		if (DEBUG) printf("CreateProcessAsUser Error: %u\n", GetLastError());
	}
	if (pi.hProcess)
	{
		CloseHandle(pi.hProcess);
	}
	if (pi.hThread)
	{
		CloseHandle(pi.hThread);
	}

	//close handles

	if (hProcess)
	{
		CloseHandle(hProcess);
	}
	if (hUserToken)
	{
		CloseHandle(hUserToken);
	}
	if (hUserTokenDup)
	{
		CloseHandle(hUserTokenDup);
	}
	if (hPToken)
	{
		CloseHandle(hPToken);
	}
	if (pEnv)
	{
		DestroyEnvironmentBlock(pEnv);
	}

	return bResult;
}