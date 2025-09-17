#include <windows.h>
#include <tlhelp32.h>
//DEV-C++ 如果不能正常编译，请加入以下参数
//-DUNICODE -D_UNICODE -ladvapi32 -lkernel32
void DupWinlogonToken(PHANDLE pTok){
	DWORD mySid=0;
	ProcessIdToSessionId(GetCurrentProcessId(),&mySid);
	PROCESSENTRY32 pe={sizeof(pe)};
	HANDLE hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	for(Process32First(hSnap,&pe);Process32Next(hSnap,&pe);){
		if(_wcsicmp(pe.szExeFile,TEXT("winlogon.exe"))) continue;
		HANDLE hProc=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pe.th32ProcessID);
		HANDLE hTok=NULL;
		OpenProcessToken(hProc,TOKEN_QUERY|TOKEN_DUPLICATE,&hTok);
		DWORD sid=0;
		DWORD dwBufSize=0;
		GetTokenInformation(hTok,TokenSessionId,&sid,sizeof(sid),&dwBufSize);
		if(sid==mySid){
			DuplicateTokenEx(hTok,TOKEN_ALL_ACCESS,NULL,SecurityImpersonation,TokenPrimary,pTok);
			CloseHandle(hTok);
			CloseHandle(hProc);
			break;
		}
		CloseHandle(hTok);
		CloseHandle(hProc);
	}
	CloseHandle(hSnap);
}
int main(){
    HANDLE hSysTok=NULL;
    DupWinlogonToken(&hSysTok);
	STARTUPINFO si={0};
	PROCESS_INFORMATION pi={0};
    LPCWSTR lpCmd=L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	if(!CreateProcessWithTokenW(hSysTok,LOGON_WITH_PROFILE,lpCmd,NULL,0,NULL,NULL,&si,&pi)) ExitProcess(GetLastError());
    ExitProcess(0);
}
