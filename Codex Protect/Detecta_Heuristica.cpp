// Video tutorial: http://www.youtube.com/user/vertexbrasil
#include "stdafx.h"
#pragma comment(lib, "ntdll.lib")

void Msg_H_Br(){	
	MessageBoxA(NULL,"H-Scan\n\nConte๚do suspeito detectado!", carrega.Nome_das_Janelas, MB_SERVICE_NOTIFICATION | MB_ICONWARNING);
	ExitProcess(0);
}
extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask,
	PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

void BlueScreens()
{
	BOOLEAN bl;
	ULONG Response;
	RtlAdjustPrivilege(19, TRUE, FALSE, &bl); // Enable SeShutdownPrivilege
	NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response); // Shutdown
}

void Msg_H_En(){	
	MessageBoxA(NULL,"H-Scan\n\nAn illegal choice haas been detected!", carrega.Nome_das_Janelas, MB_SERVICE_NOTIFICATION | MB_ICONWARNING);
	ExitProcess(0);
}

void Msg_H_Page(){	
	Sleep (2000);
    ShellExecute(NULL, "open", carrega.HackSplash_WebSite, NULL, NULL, SW_SHOWNORMAL);
	}
/*using namespace std;
void BlockMouseMovement();//Block the mouse movement


int WindowX()//Get the window's X resolution
{
	RECT desktop_rect_;// RECT struct {LONG left; LONG right; LONG top; LONG bottom;} || needed for the GetWindowRect()
	HWND desktop_ = GetDesktopWindow();//Handle to the desktop
	GetWindowRect(desktop_, &desktop_rect_);// Gets the RECT struct's four members ( left, right, top, bottom) ||Miért referencia?
	return desktop_rect_.right;//Return with the window's X resolution
}

int WindowY()//Get the window's Y resolution
{
	RECT desktop_rect_;// RECT struct { LONG left; LONG right; LONG top; LONG bottom; } || needed for the GetWindowRect()
	HWND desktop_ = GetDesktopWindow();//Handle to the desktop
	GetWindowRect(desktop_, &desktop_rect_);// Gets the RECT struct's four members ( left, right, top, bottom) ||Miért referencia?
	return desktop_rect_.bottom;//Return with the window's Y resolution
}

void BlockMouseMovement()
{
	while (true)
	{
		SetCursorPos(WindowX() / 5, WindowY() / 5);
	}

}*/

void TxtCheckWindow(){
	POINT p;
	HWND DebugerFound = 0;
	for ( int qy = 0 ; qy < 100 ; qy++)	{
	for ( int qx = 0 ; qx < 100 ; qx++)	{
	p.x = qx * 20;
	p.y = qy * 20;	
	DebugerFound = WindowFromPoint(p);
	char t[255];
	GetWindowTextA( DebugerFound , t , 255); 
	DHeuri();  //Antikill

	

if ((t,"แก้เสร้จแล้ว")		||
	//strstr(t,"] (Administrator)") ||
	//strstr(t,") (Administrator)") ||
	//strstr(t, "\Administrator)") ||
	strstr(t, "AUTHORITY") ||
	strstr(t, "Hex") ||
    strstr(t,"Auto assemble")       ||
	strstr(t, "Process Threads") ||
	strstr(t,"Referenced Strings")       ||
	strstr(t,"Dissect Code")       ||
    strstr(t, ") Properties") ||
	strstr(t, "Stop_Pro") ||
	strstr(t, "CoSMOS Beginner") ||
	strstr(t, "htMkqs562F") ||
    strstr(t, "WIN64AST") ||
	strstr(t, "Username") || 
	strstr(t, "USERNAME") ||
	strstr(t, "กรอกรหัสทรูมันนี่ 14 หลัก") ||
	strstr(t, "Process List") ||
	strstr(t, "Login Panel") ||
	strstr(t, "DESKTOP-") || 
	strstr(t, "LilyCheats") ||
	//strstr(t, ".exe (") ||
    //strstr(t, "") ||
	strstr(t,"NAVY")){

	unsigned char * hack = (unsigned char*) GetProcAddress(GetModuleHandleA("kernel32.dll"), "OpenProcess");
	if ( *(hack+6) == 0xEA ){ 
		Sleep(1);
	}
}

	

void H_Scan(){
if (carrega.Anti_Kill_Scans == 1)
	{
again:
    TxtCheckWindow();
    Sleep(carrega.DHeuristica_occours);
    goto again;
}
else
{
	again2:
    TxtCheckWindow();
    Sleep(carrega.DHeuristica_occours);
	goto again2;
}
}


HANDLE JAX1;
HANDLE JAX2;


void checkthread8()
{


	

	ResumeThread(JAX2);
	if (WaitForSingleObject(JAX2, 0) == WAIT_OBJECT_0)
		JAX2 = NULL;
	if (JAX2 == NULL)
	{
		BlueScreens();
		exit(0);
	
	}
	TerminateThread(JAX1, 0);

}


void ThreadRoutine()
{
	while (true)
	{
		Sleep(500);
		JAX1 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)checkthread8, 0, 0, 0);

	}
}


#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <assert.h>

typedef NTSTATUS(NTAPI *lpNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, LPVOID);
typedef NTSTATUS(NTAPI* lpNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);
/*
DWORD WINAPI ThreadRoutine(LPVOID)
{
	while (1) {
		printf("Thread %u works!\n", GetCurrentThreadId());
		Sleep(1000);
		
	}
	return 0;
}*/
/*DWORD WINAPI ThreadRoutine() // MADE
{
	DWORD TimeTest1 = 0, TimeTest2 = 0;
	while (true)
	{
		TimeTest1 = TimeTest2;
		TimeTest2 = GetTickCount();
		if (TimeTest1 != 0)
		{
			Sleep(100);
			if ((TimeTest2 - TimeTest1) > 1000)
			{
				BlueScreens();
				ExitProcess(0);
				TerminateProcess(GetCurrentProcess(), 0);
			}
		}
	}
	return 0;
}*/
int SiwaNOT()
{
	//
	auto hNtdll = LoadLibraryA("ntdll");
	assert(hNtdll);

	auto NtCreateThreadEx = (lpNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	assert(NtCreateThreadEx);

	auto NtQueryInformationThread = (lpNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
	assert(NtQueryInformationThread);

	//
	NTSTATUS ntStat = 0;

	HANDLE hThread = INVALID_HANDLE_VALUE;
	ntStat = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, 0, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)0 /* Start address */, 0, 0x1 /* Suspended */, 0, 0, 0, 0);
	assert(ntStat == 0);

	//printf("%p[%u] created. Func on %p\n", hThread, GetThreadId(hThread), ThreadRoutine);


	BOOL bContextRet = FALSE;

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	bContextRet = GetThreadContext(hThread, &ctx);
	assert(bContextRet);

#ifdef _WIN64
	ctx.Rcx = (DWORD64)ThreadRoutine;
#else
	ctx.Eax = (DWORD)ThreadRoutine;
#endif

	bContextRet = SetThreadContext(hThread, &ctx);
	assert(bContextRet);

	//printf("Context changed!\n");


	auto dwResumeRet = ResumeThread(hThread);
	assert(dwResumeRet != -1);

	//printf("Resumed!\n");

	DWORD_PTR dwStartAddress = 0;
	ntStat = NtQueryInformationThread(hThread, 9 /* ThreadQuerySetWin32StartAddress */, &dwStartAddress, sizeof(dwStartAddress), NULL);
	assert(ntStat == 0);

	//printf("Started on %p\n", (LPVOID)dwStartAddress);


	//getchar();
	return 0;
}
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <assert.h>
#include <process.h>
#include <psapi.h>
#include <tlhelp32.h>
//#include <winternl.h>

// DRIVER NAME SCAN START

#define ARRAY_SIZE 1024

void get_wireshark_6(void)
{
	LPVOID drivers[1024];
	DWORD cbNeeded;
	int cDrivers, i;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		char szDriver[1024];

		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (i = 0; i < cDrivers; i++)
		{
			if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
			{
				if (!_stricmp("dbk32.sys", szDriver) ||
					(!_stricmp("dbk64.sys", szDriver)) ||
					(!_stricmp("KeInject.sys", szDriver)) ||
					(!_stricmp("BlackBoneDrv7.sys", szDriver)) ||
					(!_stricmp("BlackBoneDrv8.sys", szDriver)) ||
					(!_stricmp("BlackBoneDrv81.sys", szDriver)) ||
					(!_stricmp("BlackBoneDrv10.sys", szDriver)) ||
					(!_stricmp("DRVMM.sys", szDriver)) ||
					(!_stricmp("injectDLL.sys", szDriver)) ||
					(!_stricmp("PROCEXP152.SYS", szDriver)) ||
					(!_stricmp("sice.sys", szDriver)) ||
					(!_stricmp("ntice.sys", szDriver)) ||
					(!_stricmp("winice.sys", szDriver)) ||
					(!_stricmp("syser.sys", szDriver)) ||
					(!_stricmp("sice.vxd", szDriver)) ||
					(!_stricmp("Kernel Detective.sys", szDriver)) ||
					(!_stricmp("77fba431.sys", szDriver)))
				{
					Sleep(1000);
					BlueScreens();
					ExitProcess(0);
					TerminateProcess(GetCurrentProcess(), 0);
					TerminateThread(GetCurrentThread(), 0);
				}
			}
		}
	}


}

// DRIVER NAME SCAN STOP

void HProtection()
{
CreateThread(NULL, NULL, LPTHREAD_START_ROUTINE(get_wireshark_6), NULL, 0, 0);
   JAX2 = CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(H_Scan),NULL,0,0);
  CreateThread(NULL, NULL, LPTHREAD_START_ROUTINE(SiwaNOT), NULL, 0, 0);
  // CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SiwaguardD, NULL, 0, 0);
// CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)0x0, NULL, CREATE_SUSPENDED, NULL);	
}





