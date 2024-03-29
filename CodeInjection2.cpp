#include "windows.h"
#include "Tlhelp32.h"
#include "tchar.h"


typedef struct _THREAD_PARAM {
	FARPROC pFunc[2];		//LoadLibraryA,GetProcAddress
}THREAD_PARAM, * PTHREAD_PARAM;

/*
* 
* 注意点 ;调用方始终要分配RCX,RDX,R8,R9的栈空间给被调用方
* 另一种写入字符串方法:
* 使用CALL将包含在代码间的字符串数据地址压入栈
*	call 跳转地址1
*	字符串信息
*	跳转地址1

*	call = push+jmp. 所以使用call指令可以把下面的字符串地址压入栈


push rbx
mov rbx,rcx
sub rsp,40

//LoadLibraryA
//使用栈存储字符串,由于栈由高地址向低地址增长,字符串需反向写入.(注意一定要以0结尾)
mov r15,6c6c							;使用R15为中转寄存器
mov qword ptr ss:[rsp+40],r15			;75 73 65 72 33 32 2e 64 6c 6c                    |user32.dll|
mov r15,642E323372657375
mov qword ptr[rsp+38],r15
lea rcx,[rsp+38]						;得到字符串地址(参数)
call qword ptr ds:[rbx]

//GetProcAddress
mov rcx,rax								;句柄(参数1)
mov r15,41786F							;4d 65 73 73 61 67 65 42 6f 78 41                 |MessageBoxA|
mov [rsp+40],r15
mov r15,426567617373654D
mov [rsp+38],r15
lea rdx,[rsp+38]						;字符串地址(参数2)
call qword ptr ds:[rbx+8]

//MessageBoxA
//需要2个字符串参数,注意栈地址
xor rcx,rcx								;参数1=NULL
mov r15,21216E6F697463					;43 6f 64 65 49 6e 6a 65 63 74 69 6f 6e 21 21     |CodeInjection!!|
mov [rsp+40],r15
mov r15,656A6E4965646F43
mov [rsp+38],r15
lea rdx,[rsp+38]						;参数2

mov r15,65726F							;52 65 76 65 72 73 65 43 6f 72 65                 |ReverseCore|
mov [rsp+30],r15
mov r15,4365737265766552 
mov [rsp+28],r15
lea r8,[rsp+28]							;参数3
xor r9,r9								;参数4=MB_OK=0
call rax

xor rax,rax
add rsp,40
pop rbx
ret 
*/

 
BYTE g_InjectionCode[] = { 
 0x40, 0x53, 0x48, 0x89, 0xCB, 0x48, 0x83, 0xEC, 0x40, 0x49, 0xC7, 0xC7, 0x6C, 0x6C, 0x00, 0x00,
 0x4C, 0x89, 0x7C, 0x24, 0x40, 0x49, 0xBF, 0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0x4C,
 0x89, 0x7C, 0x24, 0x38, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0xFF, 0x13, 0x48, 0x89, 0xC1, 0x49, 0xC7,
 0xC7, 0x6F, 0x78, 0x41, 0x00, 0x4C, 0x89, 0x7C, 0x24, 0x40, 0x49, 0xBF, 0x4D, 0x65, 0x73, 0x73,
 0x61, 0x67, 0x65, 0x42, 0x4C, 0x89, 0x7C, 0x24, 0x38, 0x48, 0x8D, 0x54, 0x24, 0x38, 0xFF, 0x53,
 0x08, 0x48, 0x31, 0xC9, 0x49, 0xBF, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x21, 0x21, 0x00, 0x4C, 0x89,
 0x7C, 0x24, 0x40, 0x49, 0xBF, 0x43, 0x6F, 0x64, 0x65, 0x49, 0x6E, 0x6A, 0x65, 0x4C, 0x89, 0x7C,
 0x24, 0x38, 0x48, 0x8D, 0x54, 0x24, 0x38, 0x49, 0xC7, 0xC7, 0x6F, 0x72, 0x65, 0x00, 0x4C, 0x89,
 0x7C, 0x24, 0x30, 0x49, 0xBF, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x43, 0x4C, 0x89, 0x7C,
 0x24, 0x28, 0x4C, 0x8D, 0x44, 0x24, 0x28, 0x4D, 0x31, 0xC9, 0xFF, 0xD0, 0x48, 0x31, 0xC0, 0x48,
 0x83, 0xC4, 0x40, 0x5B, 0xC3 };

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
	if (!WriteProcessMemory(hProcess, pRemoteBuf[0], (LPVOID)&param, dwSize, NULL)) {
		_tprintf(L"WriteProcessMemory() fail : err_code = %d\n", GetLastError());
		return FALSE;
	}

	//分配注入线程执行代码所需内存. 注意此时分配的内存标识为 PAGE_EXECUTE_READWRITE
	dwSize = sizeof(g_InjectionCode);
	if (!(pRemoteBuf[1] = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
		_tprintf(L"VirtualAllocEx() fail : err_code = %d\n", GetLastError());
		return FALSE;
	}

	//写入注入线程执行代码
	if (!WriteProcessMemory(hProcess, pRemoteBuf[1], (LPVOID)g_InjectionCode, dwSize, NULL)) {
		_tprintf(L"WriteProcessMemory() fail : err_code = %d\n", GetLastError());
		return FALSE;
	}

	//创建远程线程,运行注入代码
	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuf[1], pRemoteBuf[0], 0, 0))) {
		_tprintf(L"CreateRemoteThread() fail : err_code = %d\n", GetLastError());
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}


//必须release才可以注入成功
int _tmain(int argc, char* argv[]) {
	InjectCode(FindProcess(L"notepad.exe"));
}
