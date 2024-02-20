#include "windows.h"
#include "stdio.h"
#include "tchar.h"
#include "Tlhelp32.h"

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

LPVOID g_pfWriteFile = NULL;            //WriteFile地址
CREATE_PROCESS_DEBUG_INFO g_cpdi;       //原始进程数据
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;  //变更数据和原始数据

/*
typedef struct _CREATE_PROCESS_DEBUG_INFO {
  HANDLE                 hFile;
  HANDLE                 hProcess;
  HANDLE                 hThread;
  LPVOID                 lpBaseOfImage;
  DWORD                  dwDebugInfoFileOffset;
  DWORD                  nDebugInfoSize;
  LPVOID                 lpThreadLocalBase;
  LPTHREAD_START_ROUTINE lpStartAddress;
  LPVOID                 lpImageName;
  WORD                   fUnicode;
} CREATE_PROCESS_DEBUG_INFO, *LPCREATE_PROCESS_DEBUG_INFO;
*/
void OnCreateProcessDebugEvent(LPDEBUG_EVENT de) {
    //获取WriteFile地址
    g_pfWriteFile = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "WriteFile");
    _tprintf(L"g_pfWriteFile =  %p\n", g_pfWriteFile);
    //保存原始进程数据
    memcpy(&g_cpdi, &de->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
    //读取原始数据保存
    ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chOrgByte, sizeof(BYTE), NULL);
    _tprintf(L"g_chOrgByte =  %x\n", g_chOrgByte);
    //写入变更数据
    WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chINT3, sizeof(BYTE), NULL);
}

/*typedef struct _EXCEPTION_DEBUG_INFO {
  EXCEPTION_RECORD ExceptionRecord;
  DWORD            dwFirstChance;
} EXCEPTION_DEBUG_INFO, *LPEXCEPTION_DEBUG_INFO;

typedef struct _EXCEPTION_RECORD {
  DWORD                    ExceptionCode;       //异常原因 EXCEPTION_BREAKPOINT遇到断点。
  DWORD                    ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID                    ExceptionAddress;    //异常地址
  DWORD                    NumberParameters;
  ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD;
*/
BOOL OnExceptionDebugEvent(LPDEBUG_EVENT de) {
    //判断是否为断点异常(INT3)
    if (de->u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT)
        return FALSE;

    //判断断点地址是否为设置的地址
    if (de->u.Exception.ExceptionRecord.ExceptionAddress != g_pfWriteFile)
        return FALSE;

    //#1. 解除HOOK
    WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chOrgByte, sizeof(BYTE), NULL);

    //#2. 获取线程上下文CONTEXT(x64前4个参数使用寄存器传递)
    // CONTEXT_CONTROL specifies SegSs, Rsp, SegCs, Rip, and EFlags.
    // CONTEXT_INTEGER specifies Rax, Rcx, Rdx, Rbx, Rbp, Rsi, Rdi, and R8-R15
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    GetThreadContext(g_cpdi.hThread, &ctx);

    //#3. 读取WriteFile()的参数2,参数3(RDX,R8)
    PBYTE lpBuffer = NULL;
    DWORD64 dwAddrOfBuffer = ctx.Rdx, dwNumOfBytesToWrite=ctx.R8;    //字符串地址和长度

    //#4. 分配临时缓冲区
    lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite + 1);
    memset(lpBuffer, 0, dwNumOfBytesToWrite + 1);   //清0缓冲区

    //#5. 复制WriteFile()缓冲区到临时缓冲区
    ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer, lpBuffer, dwNumOfBytesToWrite, NULL);
    printf("Original string : %s\n", lpBuffer);

    //#6. 将小写字符串转换为大写
    for (DWORD i = 0; i < dwNumOfBytesToWrite; i++) {
        if (0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7A)
            lpBuffer[i] -= 0x20;
    }
    printf("Converted string : %s\n", lpBuffer);

    //#7. 将数据写回WriteFile()缓冲区
    WriteProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer, lpBuffer, dwNumOfBytesToWrite, NULL);

    //#8. 释放临时缓冲区
    free(lpBuffer);

    //#10. 设置RIP为WriteFile()首地址,当前RIP = WriteFile() + 1
    ctx.Rip = (DWORD64)g_pfWriteFile;
    SetThreadContext(g_cpdi.hThread, &ctx);

    //#11. 运行被调试进程
    ContinueDebugEvent(de->dwProcessId, de->dwThreadId, DBG_CONTINUE);

    //使当前线程放弃CPU时间片,如果不放弃有可能造成后面代码在被调试进程运行前执行,导致结果错误.
    Sleep(0);

    //#12. 设置HOOK
    WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chINT3, sizeof(BYTE), NULL);

    return TRUE;
}


/*
typedef struct _DEBUG_EVENT {
  DWORD dwDebugEventCode;       //标识调试事件类型的代码
  DWORD dwProcessId;
  DWORD dwThreadId;
  union {
    EXCEPTION_DEBUG_INFO      Exception;
    CREATE_THREAD_DEBUG_INFO  CreateThread;
    CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
    EXIT_THREAD_DEBUG_INFO    ExitThread;
    EXIT_PROCESS_DEBUG_INFO   ExitProcess;
    LOAD_DLL_DEBUG_INFO       LoadDll;
    UNLOAD_DLL_DEBUG_INFO     UnloadDll;
    OUTPUT_DEBUG_STRING_INFO  DebugString;
    RIP_INFO                  RipInfo;
  } u;
} DEBUG_EVENT, *LPDEBUG_EVENT;
*/


void DebugLoop() {
    DEBUG_EVENT de;
    DWORD dwContinueStatus;

    while (WaitForDebugEvent(&de, INFINITE)) {
        dwContinueStatus = DBG_CONTINUE;

        switch (de.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:    //报告创建进程调试事件 (包括进程及其main线程) 。 u.CreateProcessInfo 的值指定CREATE_PROCESS_DEBUG_INFO结构。
            OnCreateProcessDebugEvent(&de);
            break;
        case EXCEPTION_DEBUG_EVENT:         //报告异常调试事件。 u.Exception 的值指定EXCEPTION_DEBUG_INFO结构。
            if (OnExceptionDebugEvent(&de))
                continue;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:      //报告退出进程调试事件。 u.ExitProcess 的值指定EXIT_PROCESS_DEBUG_INFO结构。
            break;
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
    }
}


int _tmain(int argc, char* argv[]) {
    if (!DebugActiveProcess(FindProcess(L"notepad.exe"))) {
        _tprintf(L"DebugActiveProcess failed!!! Error Code = %d\n", GetLastError());
        return 1;
    }
    DebugLoop();
    return 0;
}
