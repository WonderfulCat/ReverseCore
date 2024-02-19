#include "windows.h"
#include "Tlhelp32.h"
#include "tchar.h"

typedef struct _THREAD_PARAM {
	FARPROC pFunc[2];		//LoadLibraryA,GetProcAddress
	char szBuf[4][128];		//user32.dll,MessageBoxA,CodeInjection,ReverseCore
}THREAD_PARAM,*PTHREAD_PARAM;

//LoadLibraryA
typedef HMODULE(WINAPI* PFLOADLIBRARYA)(LPCSTR lpLibFileName);
//GetProcAddress
typedef FARPROC (WINAPI* PFGETPROCADDRESS)(HMODULE hModule,  LPCSTR  lpProcName);
//MessageBoxA
typedef int (WINAPI* PFMESSAGEBOXA)(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT type);

//查找指定进程PID
DWORD FindProcess(LPCTSTR szProcessName) {
	DWORD dwPID = 0xFFFFFFFF;	//return pid
	HANDLE hSnapShot = NULL;	//snapshot handle
	PROCESSENTRY32 pe;			//processentrty32

	//需要初始化dwSize
	pe.dwSize = sizeof(PROCESSENTRY32);

	//得到快照句柄
	if ((hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0)) == INVALID_HANDLE_VALUE) {
		_tprintf(L"CreateToolhelp32Snapshot(%s) faild !!! [%d]\n", szProcessName, GetLastError());
		return dwPID;
	}

	//遍历进程
	Process32First(hSnapShot, &pe);

	do {
		if (!_tcsicmp(szProcessName, pe.szExeFile)) {
			dwPID = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);

	return dwPID;
}


//线程运行函数
DWORD WINAPI ThreadProc(LPVOID lParam) {
	PTHREAD_PARAM param = (PTHREAD_PARAM)lParam;
	HMODULE hMod = NULL;
	FARPROC pFunc = NULL;
	//LoadLibraryA
	hMod = ((PFLOADLIBRARYA)param->pFunc[0])(param->szBuf[0]);
	if (!hMod)
		return 1;

	//GetProcAddress
	pFunc = ((PFGETPROCADDRESS)param->pFunc[1])(hMod, param->szBuf[1]);
	if (!pFunc)
		return 1;

	//MessageBoxA
	((PFMESSAGEBOXA)pFunc)(NULL, param->szBuf[2], param->szBuf[3], MB_OK);

	return 0;
}

BOOL InjectCode(DWORD dwPID) {
	THREAD_PARAM param = { 0 };			//注入资源结构体
	DWORD dwSize = 0;					//资源结构体大小
	HMODULE hMod = NULL;				//kernel32.dll句柄
	HANDLE hProcess = NULL;				//目标进程句柄
	LPVOID pRemoteBuf[2] = { 0 };		//目标进程内存地址
	HANDLE hThread = NULL;				//远程线程句柄

	//初始化需要注入的资源
	if ((hMod = GetModuleHandleA("kernel32.dll")) == NULL) {
		_tprintf(L"GetModuleHandleA faild!!! [%d]\n", GetLastError());
		return FALSE;
	}

	param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
	param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");

	strcpy_s(param.szBuf[0], "user32.dll");
	strcpy_s(param.szBuf[1], "MessageBoxA");
	strcpy_s(param.szBuf[2], "CodeInjection");
	strcpy_s(param.szBuf[3], "ReverseCore");

	//得到目标线程句柄
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) == NULL) {
		_tprintf(L"OpenProcess faild!!! [%d]\n", GetLastError());
		return FALSE;
	}

	//分配注入参数所需内存
	dwSize = sizeof(THREAD_PARAM);
	if (!(pRemoteBuf[0] = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE))) {
		_tprintf(L"VirtualAllocEx() fail : err_code = %d\n", GetLastError());
		return FALSE;
	}

	//写入注入参数
	if (!WriteProcessMemory(hProcess, pRemoteBuf[0], (LPVOID)&param,  dwSize,  NULL)) {
		_tprintf(L"WriteProcessMemory() fail : err_code = %d\n", GetLastError());
		return FALSE;
	}

	//分配注入线程执行代码所需内存. 注意此时分配的内存标识为 PAGE_EXECUTE_READWRITE
	dwSize = (DWORD)InjectCode - (DWORD)ThreadProc;
	if (!(pRemoteBuf[1] = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
		_tprintf(L"VirtualAllocEx() fail : err_code = %d\n", GetLastError());
		return FALSE;
	}

	//写入注入线程执行代码
	if (!WriteProcessMemory(hProcess, pRemoteBuf[1], (LPVOID)ThreadProc, dwSize, NULL)) {
		_tprintf(L"WriteProcessMemory() fail : err_code = %d\n", GetLastError());
		return FALSE;
	}

	//创建远程线程,运行注入代码
	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuf[1], pRemoteBuf[0], 0, 0))) {
		_tprintf(L"CreateRemoteThread() fail : err_code = %d\n", GetLastError());
		return FALSE;
	}
	
	WaitForSingleObject(hThread,INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}


//必须release才可以注入成功
int _tmain(int argc, char* argv[]) {
	InjectCode(FindProcess(L"notepad.exe"));
}
