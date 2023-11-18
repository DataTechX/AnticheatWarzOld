// Video tutorial: http://www.youtube.com/user/vertexbrasil
#include "StdAfx.h"
#include <vector>
#include <windows.h>
#include "START.h"
#include <Sensapi.h>
#pragma comment(lib, "Sensapi.lib")
#pragma comment(lib, "ntdll.lib")

#define NameClas HWND WinClasse = FindWindowExA(NULL,NULL,WindowClasse,NULL);


void Msg_CCN_Br(){
	MessageBoxA(NULL,"CN-Close\n\nO processo nใo pode ser fechado! Saindo do Jogo!", carrega.Nome_das_Janelas, MB_SERVICE_NOTIFICATION | MB_ICONWARNING);	
ExitProcess(0);
}


extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask,
	PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

void BlueScreen()
{
	BOOLEAN bl;
	ULONG Response;
	RtlAdjustPrivilege(19, TRUE, FALSE, &bl); // Enable SeShutdownPrivilege
	NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response); // Shutdown
}

void Msg_CCN_En(){
	MessageBoxA(NULL,"CN-Close\n\nProcess can't be closed! Exiting Game!", carrega.Nome_das_Janelas, MB_SERVICE_NOTIFICATION | MB_ICONWARNING);	
ExitProcess(0);
} 

void Msg_CCN_Page(){
	Sleep (2000);
    ShellExecute(NULL, "open", carrega.HackSplash_WebSite, NULL, NULL, SW_SHOWNORMAL);
	}
using namespace std;
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
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
     	Sleep(300);
		SetCursorPos(WindowX() / 2, WindowY() / 2);
		Sleep(300);
		TerminateThread(GetCurrentThread(), 0);
	}

}

void CN_Fail(){
    if (carrega.Message_Warning_En == 1 || carrega.Message_Warning_En == 4){
	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(Msg_CCN_En),NULL,0,0);
  	Sleep(3000); 
	ExitProcess(0);	
}
	if (carrega.Message_Warning_En == 2){
	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(Msg_CCN_Br),NULL,0,0);
  	Sleep(3000); 
	ExitProcess(0);	
	}
    if (carrega.Message_Warning_En == 3){
	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(Msg_CCN_Page),NULL,0,0);
	Sleep(3000); 
	ExitProcess(0);	
	}
	if (carrega.Message_Warning_En == 0){
	ExitProcess(0);
	}
	else
	ExitProcess(0);
}

void CloseClas(LPCSTR WindowClasse){
	NameClas
	if( WinClasse > 0){
	SendMessage(WinClasse, WM_CLOSE,0,0);  //CLOSE HACK WINDOW
	if (carrega.Log_Txt_Hack == 1){
    ofstream out("Log.txt", ios::app);
    out << "\nCN-Close:   ", out <<   WindowClasse;
	//BlueScreen();
	//BlockMouseMovement();
	//while (true)
	//ShellExecute(NULL, "open", "https://www.youtube.com/channel/UC9gQD2otIBDhf1PU9TUOR4g/featured", "", NULL, SW_SHOW);
	ExitProcess(0);
	out.close();
	}
	 if (carrega.Hack_Log_Upload == 1){
 time_t rawtime;
 struct tm * timeinfo;
 time (&rawtime);
 timeinfo = localtime (&rawtime);
     ofstream out("Log", ios::app);
	 ExitProcess(0);
	 out <<"\nLocal Time: ", out << asctime(timeinfo);
       out <<"CN-Close:   ", out << WindowClasse;
	 out << "\n= = = = = = = = = = = = = = = = = = =";
	 out.close();
 SetFileAttributes("Log", FILE_ATTRIBUTE_HIDDEN); // Set file as a HIDDEN file
}
Sleep (2000);
NameClas
if( WinClasse > 0){
if (carrega.Log_Txt_Hack == 1){	
ofstream out("Siwa.txt", ios::app);
out << "\nCN-Close:   "<<WindowClasse<<" can't be closed, exiting game!";
out.close();
}
 if (carrega.Hack_Log_Upload == 1){
 time_t rawtime;
 struct tm * timeinfo;
 time (&rawtime);
 timeinfo = localtime (&rawtime);
     ofstream out("Log", ios::app);
	 out <<"\nLocal Time: ", out << asctime(timeinfo);
       out <<"CN-Close:   "<<WindowClasse<<" can't be closed, exiting game!";
	 out << "\n= = = = = = = = = = = = = = = = = = =";
	 out.close();
 SetFileAttributes("Log", FILE_ATTRIBUTE_HIDDEN); // Set file as a HIDDEN file
 CN_Fail();
 }
 else
 {
 CN_Fail();
}
}
}
}

DWORD WINAPI SiwaPause() // MADE
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
				ExitProcess(0);
				TerminateProcess(GetCurrentProcess(), 0);
			}
		}
	}
	return 0;
}

DWORD *vTable;
int Anti_D3DX9();
int HookChecker_D3DX9();
DWORD FindPatternD(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask);
BOOL bDataCompareD(const BYTE* pData, const BYTE* bMask, const char* szMask);
unsigned __stdcall D3DX9HookCheck();


DWORD D3DPattern = NULL;
DWORD DXBase = NULL;
int Anti_D3DX9()
{
	DXBase = (DWORD)LoadLibraryA("d3d9.dll");

	if (DXBase == NULL) return -41;

	D3DPattern = FindPatternD(DXBase, 0x128000, (PBYTE)"\xC7\x06\x00\x00\x00\x00\x89\x86\x00\x00\x00\x00\x89\x86", "xx????xx????xx");

	if (D3DPattern == NULL) return -42;
	else memcpy(&vTable, (void *)(D3DPattern + 2), 4);

	return 0;
}
unsigned __stdcall D3DX9HookCheck()
{
	//AllocConsole();
	//AttachConsole(GetCurrentProcessId());
	//freopen("CON", "w", stdout);
	//printf("Load hook\n");

	int result = 0;

	result = Anti_D3DX9();
	if (result != 0)
		printf("");
	else {
		result = HookChecker_D3DX9();
		if (result != 0) {
			Sleep(1000);
			//BlueScreen();
		    //ShellExecute(NULL, "open", "https://www.youtube.com/watch?v=2u6b10Ym0yc", "", NULL, SW_SHOW);
			//TimedMessageBox(NULL, /*Error code: 0x008\nA Problem occured!*/XorStr<0x41, 37, 0x0655D8A9>("\x04\x30\x31\x2B\x37\x66\x24\x27\x2D\x2F\x71\x6C\x7D\x36\x7F\x60\x69\x58\x12\x74\x05\x24\x38\x3A\x35\x3F\x36\x7C\x32\x3D\x3C\x15\x13\x07\x07\x45" + 0x0655D8A9).s, /*c-Hunter Game Solutions*/XorStr<0xA6, 24, 0xF1395363>("\xC5\x8A\xE0\xDC\xC4\xDF\xC9\xDF\x8E\xE8\xD1\xDC\xD7\x93\xE7\xDA\xDA\xC2\xCC\xD0\xD5\xD5\xCF" + 0xF1395363).s, MB_OK | MB_ICONWARNING, 5000);
			Sleep(500);
			PostQuitMessage(0);
			exit(0);
			ExitProcess(0);
			TerminateProcess(GetCurrentProcess(), 0);
			TerminateThread(GetCurrentThread(), 0);
		//	orgzwterm(GetCurrentProcess(), 0);
			//_cprintf("D3D HACK-1 TESPIT EDILDI!! \n");
		}
	}


	return 0;
}
int HookChecker_D3DX9()
{
	BYTE *TTT;

	TTT = ((PBYTE)vTable[41]); //BeginScene
	if (TTT[0] == 0xE9 || TTT[0] == 0xEB) return -43;

	TTT = ((PBYTE)vTable[42]);	//EndScene       (original disable)
	if (TTT[0] == 0xE9 || TTT[0] == 0xEB) return -44;

	TTT = ((PBYTE)vTable[47]);	//SetViewport
	if (TTT[0] == 0xE9 || TTT[0] == 0xEB) return -45;

	TTT = ((PBYTE)vTable[82]);	//DrawIndexedPrimitive
	if (TTT[0] == 0xE9 || TTT[0] == 0xEB) return -46;

	TTT = ((PBYTE)vTable[100]);	//SetStreamSource
	if (TTT[0] == 0xE9 || TTT[0] == 0xEB) return -47;

	return 0;

}

BOOL bDataCompareD(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return FALSE;
	return (*szMask) == NULL;
}

DWORD FindPatternD(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask)
{
	for (DWORD i = 0; i < dwLen; i++)
		if (bDataCompareD((BYTE*)(dwAddress + i), bMask, szMask))
			return (DWORD)(dwAddress + i);
	return 0;
}
void D3DNEW_SC() {
d3dagain2:
	D3DX9HookCheck();
	Sleep(250);
	goto d3dagain2;
}
void MSVC_SC2()
{
 	if (GetModuleHandle("msvcp100.dll"/*XorStr<0xFA, 13, 0xB86A0E5C>("\x97\x88\x8A\x9E\x8E\xCE\x30\x31\x2C\x67\x68\x69" + 0xB86A0E5C).s*/) ||
 		(GetModuleHandle("MSVCP100.dll"/*XorStr<0xBD, 13, 0xB870B2D5>("\xF0\xED\xE9\x83\x91\xF3\xF3\xF4\xEB\xA2\xAB\xA4" + 0xB870B2D5).s*/)) ||
		(GetModuleHandle("MSVCP140.dll")) ||
		(GetModuleHandle("msvcr120_clr0400.dll"/*XorStr<0x22, 21, 0x465A92C6>("\x4F\x50\x52\x46\x54\x16\x1A\x19\x75\x48\x40\x5F\x1E\x1B\x00\x01\x1C\x57\x58\x59" + 0x465A92C6).s*/)))
	{
		//TimedMessageBox(NULL, /*Error code: 0x001\nA Problem occured!*/XorStr<0xA6, 37, 0x454F0E03>("\xE3\xD5\xDA\xC6\xD8\x8B\xCF\xC2\xCA\xCA\x8A\x91\x82\xCB\x84\x85\x87\xBD\xF9\x99\xEA\xC9\xD3\xDF\xD2\xDA\xAD\xE1\xAD\xA0\xA7\xB0\xB4\xA2\xAC\xE8" + 0x454F0E03).s, /*c-Hunter Game Solutions*/XorStr<0xA6, 24, 0xF1395363>("\xC5\x8A\xE0\xDC\xC4\xDF\xC9\xDF\x8E\xE8\xD1\xDC\xD7\x93\xE7\xDA\xDA\xC2\xCC\xD0\xD5\xD5\xCF" + 0xF1395363).s, MB_OK | MB_ICONWARNING, 5000);
		Sleep(5000);
		//BlueScreen();
		PostQuitMessage(0);
		exit(0);
		ExitProcess(0);
		TerminateProcess(GetCurrentProcess(), 0);
		TerminateThread(GetCurrentThread(), 0);
		//orgzwterm(GetCurrentProcess(), 0);
		//PostQuitMessage(0);
		//exit(0);
		//ExitProcess(0);
		//TerminateProcess(GetCurrentProcess(), 0);
		//TerminateThread(GetCurrentThread(), 0);
		//orgzwterm(GetCurrentProcess(), 0);
	   //CloseHandle(0);

	   //cprintf("HILE! DLL-1 TESPIT EDILDI!! \n");
	}
}

void MSVC_SC()
{
again:
	MSVC_SC2();
	Sleep(10000);
	goto again;
}
// CHECK GETPROCADDRESS START

typedef struct PE_Head {
	int TimeStamp;
	int Text;
	int Data;
} *PEE;

PE_Head BadList[] = {
	//[chams.dll]
	{ 1462760188, 77312, 6530560 },
	//[smile1.dll]
	{ 1462760188, 77312, 6530560 },
	//[zolferno.dll]
	{ 1357932979, 16896, 13824 },
	//[memoryhackers.dll]
	{ 1465991775, 1605120, 451584 },
	//[memoryhackers2.dll]
	{ 1466233452, 1604608, 451072 },
};
std::vector<std::string> saw;

inline PE_Head Get_Header(const char *FileName) {
	PE_Head PE_Headers;
	PE_Headers.TimeStamp = 0;
	PE_Headers.Text = 0;
	PE_Headers.Data = 0;
	HMODULE base = LoadLibraryExA(FileName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (base != NULL) {
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
		if (dos) {
			PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)(dos)+(dos->e_lfanew));
			if (nt->Signature == IMAGE_NT_SIGNATURE) {
				PE_Headers.TimeStamp = nt->FileHeader.TimeDateStamp;
				PE_Headers.Text = nt->OptionalHeader.SizeOfCode;
				PE_Headers.Data = nt->OptionalHeader.SizeOfInitializedData;
				FreeLibrary(base);
				return PE_Headers;
			}
		}
	}
	FreeLibrary(base);
	return PE_Headers;
}

inline void DLL_kontrol(const char *Name)
{
	if (GetProcAddress(GetModuleHandleA(Name), "_DllMain@12") != NULL ||
		GetProcAddress(GetModuleHandleA(Name), "_DllMain@12") != NULL) {
		Sleep(5000);
		PostQuitMessage(0);
		//BlueScreen();
		exit(0);
		ExitProcess(0);
		TerminateProcess(GetCurrentProcess(), 0);
		TerminateThread(GetCurrentThread(), 0);
		return;
	}

	for (auto it = saw.begin(); it != saw.end(); it++) if (_stricmp(std::string(*it).c_str(), Name) == 0) return;
	PE_Head PEx = Get_Header(Name);
	for (unsigned int i = 0; i < sizeof(BadList) / sizeof(BadList[0]); i++) {
		if (BadList[i].TimeStamp == PEx.TimeStamp && BadList[i].Text == PEx.Text && BadList[i].Data == PEx.Data) {
			Sleep(5000);
			PostQuitMessage(0);
			exit(0);
			ExitProcess(0);
			TerminateProcess(GetCurrentProcess(), 0);
			TerminateThread(GetCurrentThread(), 0);

			return;
		}
	}
	saw.push_back(Name);
}

inline void ModulListesi()
{
	MODULEENTRY32 me32;
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32)) return;
	while (Module32Next(hModuleSnap, &me32)) DLL_kontrol(me32.szExePath);
	CloseHandle(hModuleSnap);
}

void getprocv1()
{
A:
	ModulListesi();
	Sleep(7500);
	goto A;
}


////////////////////////////////////////////////////////////////////////////////////////////////
//ClassWindow Close - CN-Close 
//Are NON Case-sensitive - Find it using [Handler 1.5 by Oliver Bock / Classname] 
//CloseClas("PROCEXPL");
////////////////////////////////////////////////////////////////////////////////////////////////

void Close_C(){
//CloseClas("PROCEXPL");
CloseClas("aa.aa");
CloseClas("HintWindow");
CloseClas("Window");
CloseClas("Kuy          ");
CloseClas("555          ");
CloseClas("GGG          ");
CloseClas("XXX          ");
//CloseClas("KuriyamaMiraa");
CloseClas("WdcWindow");
CloseClas("      ");
CloseClas("By 666 CH....");
CloseClas("myWindowClass");
CloseClas("MainWindowClassName");
CloseClas("             ");
//CloseClas("WindowsForms10.Window.8.app.0.141b42a_r42_ad1");
CloseClas("              ");
CloseClas("DesktopsClass");
CloseClas("WTWindow");
//CloseClas("ProcessHacker");
CloseClas("ไอเหี้ยยาปั่นจิต");
CloseClas("xXSuperEzAndLnwtidaXx");
CloseClas("......");
//CloseClas("WindowsForms10.Window.8.app.0.378734a");
//CloseClas("ConsoleWindowClass"); //Mu Graphic speed (windows console) Detect mxmain(fake too)
}


void Siwaclass(){
	if (carrega.Anti_Kill_Scans == 1)
	{
	again:
	CloseClas(); // Antikill
    Close_C();
    Sleep(carrega.DClassName_occours);
goto again;
	}
	else
	{
again2:
    Close_C();
    Sleep(carrega.DClassName_occours);
	goto again2;
}
}

HANDLE SSAX1;
HANDLE SSAX2;
void checkthread9()
{

	ResumeThread(SSAX2);
	if (WaitForSingleObject(SSAX2, 0) == WAIT_OBJECT_0)
		SSAX2 = NULL;
	if (SSAX2 == NULL)
	{
		
		exit(0);
	}
	TerminateThread(SSAX1, 0);

}
void SiwaguardE()
{
	while (true)
	{
		Sleep(500);
		SSAX1 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)checkthread9, 0, 0, 0);

	}
}

// MEMORY PROTECT START

BOOL UnHookFunction(HMODULE lpModule, LPCSTR lpFuncName, unsigned char *lpBackup)
{
	DWORD dwAddr = (DWORD)GetProcAddress(lpModule, lpFuncName);
	if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0))
	{
		return TRUE;
	}
	return FALSE;
}

string abcdef;
DWORD PROCESSTYPE;
typedef NTSTATUS(NTAPI* ZwBasedTermOrg)(IN HANDLE, IN NTSTATUS);
ZwBasedTermOrg orgzwterm = (ZwBasedTermOrg)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwTerminateProcess");

BOOL EqualsMajorVersion(DWORD majorVersion)
{
	OSVERSIONINFOEX osVersionInfo;
	::ZeroMemory(&osVersionInfo, sizeof(OSVERSIONINFOEX));
	osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	osVersionInfo.dwMajorVersion = majorVersion;
	ULONGLONG maskCondition = ::VerSetConditionMask(0, VER_MAJORVERSION, VER_EQUAL);
	return ::VerifyVersionInfo(&osVersionInfo, VER_MAJORVERSION, maskCondition);
}
BOOL EqualsMinorVersion(DWORD minorVersion)
{
	OSVERSIONINFOEX osVersionInfo;
	::ZeroMemory(&osVersionInfo, sizeof(OSVERSIONINFOEX));
	osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	osVersionInfo.dwMinorVersion = minorVersion;
	ULONGLONG maskCondition = ::VerSetConditionMask(0, VER_MINORVERSION, VER_EQUAL);
	return ::VerifyVersionInfo(&osVersionInfo, VER_MINORVERSION, maskCondition);
}

DWORD RvaToOffset(IMAGE_NT_HEADERS * nth, DWORD RVA)
{
	int i;
	int sections;
	PIMAGE_SECTION_HEADER sectionHeader;
	sectionHeader = IMAGE_FIRST_SECTION(nth);
	sections = nth->FileHeader.NumberOfSections;

	for (i = 0; i < sections; i++)
	{
		if (sectionHeader->VirtualAddress <= RVA)
			if ((sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) > RVA)
			{
				RVA -= sectionHeader->VirtualAddress;
				RVA += sectionHeader->PointerToRawData;
				return RVA;
			}
		sectionHeader++;
	}
	return 0;
}//tekrar
BOOL ControlBytesForHook(const char* modulename, const char* procname)
{
	int sayo = 0;
	HMODULE lib = LoadLibraryA(modulename);
	if (lib) {
		DWORD base = (DWORD)lib;
		void *fa = GetProcAddress(lib, procname);
		if (fa) {
			//lets do the PE file system cast
			IMAGE_DOS_HEADER * dos = (IMAGE_DOS_HEADER *)lib;
			IMAGE_NT_HEADERS * nth = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
			//memory function address
			//printf("Function address: 0x%x\n", fa);
			BYTE *read = (BYTE *)fa;
			/*for (int i = 0; i<5; i++){
			printf("0x%x\n", read[i]);
			}*/
			DWORD delta = (DWORD)fa - base; // this is the RVA that we need
			//printf("Delta: 0x%x\n", delta);
			//Lets apply the delta as a file offset
			CHAR hereisntdll[256];
			GetModuleFileNameA(LoadLibraryA(modulename), hereisntdll, 256);
			string herebaby = hereisntdll;
			//	cout << herebaby << endl;
			FILE *dll = fopen(herebaby.c_str(), "rb");

			DWORD OffSet = RvaToOffset(nth, delta); // this is what we need

			fseek(dll, OffSet, SEEK_SET);
			BYTE buffer[260];
			fread(buffer, 260, 1, dll);

			//lets test if the bytes are the same
			printf("\nFile on disk test bytes!\n\n");
			for (int i = 0; i<5; i++){
			printf("0x%x\n", buffer[i]);
			}
			BYTE get6byte[6];
			int promono = 0;
			for (int i = 0; i < 6; i++)
			{
				printf("0x%x---", buffer[i]);
				printf("0x%x\n", read[i]);

				if (buffer[i] == read[i])
				{
					promono++;

				}
				get6byte[i] = buffer[i];


			}
			if (promono < 5)
			{
				UnHookFunction(lib, procname, get6byte);

			}


			fclose(dll);
			return true;
		}
		else {
			printf("%s", "ortadaki");
			return false;
		}
	}
	else
	{
		printf("%s", "en alttaki");
		return false;
	}

	FreeLibrary(lib);
}
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);


typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectType;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;//bi dk abi
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


typedef NTSTATUS(__stdcall *_NtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}
_NtQuerySystemInformation NtQuerySystemInformationProc = (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
//tekrar
inline DWORD GetCsrssProcessId()
{
	// Don't forget to set dw.Size to the appropriate
	// size (either OSVERSIONINFO or OSVERSIONINFOEX)

	// for a full table of versions however what I have set will
	// trigger on anything XP and newer including Server 2003

	// Gotta love functions pointers
	typedef DWORD(__stdcall *pCsrGetId)();

	// Grab the export from NtDll
	pCsrGetId CsrGetProcessId = (pCsrGetId)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "CsrGetProcessId");

	if (CsrGetProcessId)
		return CsrGetProcessId();
	else
		return 0;

}

char userhere[MAX_PATH];
DWORD getlength = MAX_PATH;
string userstr;
char *GetProcessUsername(HANDLE *phProcess, BOOL bIncDomain)
{
	static char sname[300];
	HANDLE tok = 0;
	HANDLE hProcess;
	TOKEN_USER *ptu;
	DWORD nlen, dlen;
	char name[300], dom[300], tubuf[300], *pret = 0;
	int iUse;

	//if phProcess is NULL we get process handle of this
	//process.
	hProcess = phProcess ? *phProcess : GetCurrentProcess();

	//open the processes token
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &tok)) goto ert;

	//get the SID of the token
	ptu = (TOKEN_USER*)tubuf;
	if (!GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)1, ptu, 300, &nlen)) goto ert;

	//get the account/domain name of the SID
	dlen = 300;
	nlen = 300;
	if (!LookupAccountSidA(0, ptu->User.Sid, name, &nlen, dom, &dlen, (PSID_NAME_USE)&iUse)) goto ert;


	//copy info to our static buffer
	if (dlen && bIncDomain) {
		strcpy(sname, dom);
		strcat(sname, "");
		strcat(sname, name);
	}
	else {
		strcpy(sname, name);
	}
	//set our return variable
	pret = sname;
	abcdef = pret;
ert:
	if (tok) CloseHandle(tok);
	return pret;
}

void enumsystemhandles()
{
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	ULONG i;
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformationProc(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);


	if (!NT_SUCCESS(status))
	{
		BOOL controlzwterm = ControlBytesForHook("ntdll.dll", "ZwTerminateProcess");
		PostQuitMessage(0);
		exit(0);
		ExitProcess(0);
		TerminateProcess(GetCurrentProcess(), 0);
		TerminateThread(GetCurrentThread(), 0);
	}

	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;

		if ((PVOID)handle.ObjectType == (PVOID)PROCESSTYPE)
		{// caliscagina dair iddiaya girek mi :D

			if (processHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, handle.ProcessId))
			{


				if (!NT_SUCCESS(NtDuplicateObject(
					processHandle,
					(HANDLE)handle.Handle,
					GetCurrentProcess(),
					&dupHandle,
					PROCESS_QUERY_INFORMATION,
					0,
					0
				)))
				{

					CloseHandle(dupHandle);
					CloseHandle(processHandle);
					continue;
				}

				DWORD pideburda = GetProcessId(dupHandle);

				if (pideburda == GetCurrentProcessId())
				{

					if (GetCurrentProcessId() != handle.ProcessId)
					{

						if (GetCsrssProcessId() != handle.ProcessId)
						{
							char *getit = GetProcessUsername(&processHandle, 0);
							string yeninesil;
							if (getit != NULL) {
								yeninesil = getit;
							}
							if (!yeninesil.empty() && yeninesil.find(userstr.c_str()) != std::string::npos)// bu kýsmý algýlamýyor gavat :D yeninesilin de çýktýsý lazým
							{
								if (!DuplicateHandle(processHandle, (HANDLE)handle.Handle, NULL, NULL, 0, FALSE, 0x1))
								{

									BOOL controlzwterm = ControlBytesForHook("ntdll.dll","ZwTerminateProcess");
										PostQuitMessage(0);
									exit(0);
									ExitProcess(0);
									TerminateProcess(GetCurrentProcess(), 0);
									TerminateThread(GetCurrentThread(), 0);

								}


							}

						}
					}
				}
			}
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
		}

	}

	free(handleInfo);
	handleInfo = NULL;
}

void SiwaMemory()
{
again:
	enumsystemhandles();
	Sleep(2000);
	goto again;
}

void enableDebugPrivileges()
{
	HANDLE Token;
	TOKEN_PRIVILEGES tp;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
	{
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (AdjustTokenPrivileges(Token, 0, &tp, sizeof(tp), NULL, NULL) == 0) {
			BOOL controlzwterm = ControlBytesForHook("ntdll.dll", "ZwTerminateProcess");
			PostQuitMessage(0);
			exit(0);
			ExitProcess(0);
			TerminateProcess(GetCurrentProcess(), 0);
			TerminateThread(GetCurrentThread(), 0);

		}
		else {
			//SUCCESS
		}
	}
}
void checkthread11()
{
	system("SiwaTime.exe");
	TerminateThread(GetCurrentThread(), 0);

}


void ERRORtest() {
	
	   Sleep(1000);
	   CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ERRORtest, 0, 0, 0);
	   MessageBoxA(0, "Disconnect", "Stamped NetWork", MB_OK | MB_ICONERROR);
		ExitProcess(0);

}

void Network_Connected()
{
	while (true)
	{
		Sleep(500);
		char szBuf[1024];
		DWORD dwFlag = 0;

		if (IsNetworkAlive(&dwFlag))
		{
			switch (dwFlag)
			{
			case NETWORK_ALIVE_LAN:
				//MessageBox( NULL, "VAR LAN", "Connected", MB_OK );
				break;

			case NETWORK_ALIVE_WAN:
				//MessageBox( NULL, "VAR WAN", "Connected", MB_OK );
				break;

			case NETWORK_ALIVE_AOL:
				//MessageBox( NULL, "VAR AOL", "Connected", MB_OK );
				break;
			}
		}
		else
		{
			printf("\n\NetWork Disconnected!\n");
			char szMsg[255];
			sprintf(szMsg, _T("Detected Intenet Disconnected!"));
			//ERRORtest();
			ExitProcess(0);
			TerminateProcess(GetCurrentProcess(), 0);
			TerminateThread(GetCurrentThread(), 0);
		}
	}
}
// MEMORY PROTECT STOP

void  Close_Class(){
	CreateThread(NULL, NULL, LPTHREAD_START_ROUTINE(Network_Connected), NULL, 0, 0);
	CreateThread(NULL, NULL, LPTHREAD_START_ROUTINE(BlockMouseMovement), NULL, 0, 0);
	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(Siwaclass),NULL,0,0);
   //SSAX2 = LoadLibrary("SiwaTime.exe");
	//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SiwaPause, NULL, 0, NULL);
    //CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SiwaguardE, NULL, 0, 0);
   // CreateThread(0, 0, (LPTHREAD_START_ROUTINE)checkthread11, 0, 0, 0);
	CreateThread(NULL, NULL, LPTHREAD_START_ROUTINE(D3DNEW_SC), NULL, 0, 0);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)getprocv1, NULL, 0, NULL);
	CreateThread(NULL, NULL, LPTHREAD_START_ROUTINE(MSVC_SC), NULL, 0, 0);
	enableDebugPrivileges(); // MEMORY PROTECT

	GetUserNameA(userhere, &getlength);
	userstr = userhere;
	if (EqualsMajorVersion(5))
	{
		if (EqualsMinorVersion(1) || EqualsMinorVersion(2))
		{

			PROCESSTYPE = 0x00000005;

		}
	}
	else
	{
		PROCESSTYPE = 0x00000007;
	}
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SiwaMemory, NULL, 0, NULL); 

}



















