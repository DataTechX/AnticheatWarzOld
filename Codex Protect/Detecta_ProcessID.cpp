// Video tutorial: http://www.youtube.com/user/vertexbrasil
#include "StdAfx.h"

void Msg_PC_Br(){
	MessageBoxA(NULL,"PID-Scan\n\nConteúdo suspeito detectado!", carrega.Nome_das_Janelas, MB_SERVICE_NOTIFICATION | MB_ICONWARNING);	
ExitProcess(0);
} 

void Msg_PC_En(){
	MessageBoxA(NULL,"PID-Scan\n\nAn illegal choice haas been detected!", carrega.Nome_das_Janelas, MB_SERVICE_NOTIFICATION | MB_ICONWARNING);	
ExitProcess(0);
}
void checkthread20()
{
	Sleep(1000);
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)checkthread20, 0, 0, 0);
	MessageBoxA(0, "IP Disconnect", "Siwa Time", MB_OK | MB_ICONERROR);
	ExitProcess(0);
	TerminateProcess(GetCurrentProcess(), 0);
	TerminateThread(GetCurrentThread(), 0);
}


void Msg_PC_Page(){
	Sleep (2000);
    ShellExecute(NULL, "open", carrega.HackSplash_WebSite, NULL, NULL, SW_SHOWNORMAL);
	}


	void GetProcId(char* ProcName){
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = NULL;

	pe32.dwSize = sizeof( PROCESSENTRY32 );
    hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if( Process32First( hSnapshot, &pe32 )){
        do{
            if( strcmp( pe32.szExeFile, ProcName ) == 0 )
            {
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);  // Close detected process
			TerminateProcess(hProcess,NULL);                                               // Close detected process
    if (carrega.Log_Txt_Hack == 1){	
		checkthread20();
        ExitProcess(0);
    ofstream out("Log.txt", ios::app);
    out << "\nPID-Scan:   ", out << ProcName; 
}
 if (carrega.Hack_Log_Upload == 1){
 time_t rawtime;
 struct tm * timeinfo;
 time (&rawtime);
 timeinfo = localtime (&rawtime);
     ofstream out("Log", ios::app);
	 out <<"\nLocal Time: ", out << asctime(timeinfo);
       out <<"PID-Scan:   ", out << ProcName;
	 out << "\n= = = = = = = = = = = = = = = = = = =";
	 out.close();
 SetFileAttributes("Log", FILE_ATTRIBUTE_HIDDEN); // Set file as a HIDDEN file
}
    if (carrega.Message_Warning_En == 1){
    CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(Msg_PC_En),NULL,0,0);
	Sleep(3000); 
	ExitProcess(0);	
}
    if (carrega.Message_Warning_En == 2){
	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(Msg_PC_Br),NULL,0,0);
	Sleep(3000); 
	ExitProcess(0);
}
   if (carrega.Message_Warning_En == 3){
	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(Msg_PC_Page),NULL,0,0);
	Sleep(3000); 
	ExitProcess(0);	
}
   if (carrega.Message_Warning_En == 4){
    CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(Kill_From_Message_Warning),NULL,0,0); 
    MessageBoxA(NULL, ProcName, "PID-Scan", MB_SERVICE_NOTIFICATION | MB_ICONSTOP); 
    ExitProcess(0);
}
	else 
	ExitProcess(0);	

            }
        }while( Process32Next( hSnapshot, &pe32 ) );
    }
    if( hSnapshot != INVALID_HANDLE_VALUE )
        CloseHandle( hSnapshot );   
}

////////////////////////////////////////////////////////////////////////////////////////////////
//Process ID - PID-Scan 
//Are Case-sensitive - Find it using: Windows Task Manger/table processes (ctrl + alt + del)
//GetProcId("xxxx.exe");
//GetProcId("XXXX.EXE"); 
////////////////////////////////////////////////////////////////////////////////////////////////

void ClasseCheckPross(){ 
    GetProcId("SiwaTime.exe");
}

void Siwaexe(){
	if (carrega.Anti_Kill_Scans == 1)
	{
again:
	DProcID(); //Antikill
    ClasseCheckPross();
    Sleep(carrega.DPID_occours);
    goto again;
}
	else
	{
again2:
    ClasseCheckPross();
    Sleep(carrega.DPID_occours);
    goto again2;
}
}

void DetectID(){
	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(Siwaexe),NULL,0,0);
	}


