#include <stdio.h>
#include <sddl.h>

#include "uthash.h"

#include "param.h"
#include "ProcessMonitor.h"
#include "log.h"
#include "hash.h"


BOOL WINAPI ConvertSidToStringSidA(
	_In_  PSID     Sid,
	_Outptr_ LPSTR  *StringSid
);

CRITICAL_SECTION gCleanProcessMonitorCS;
HANDLE hCleanProcessMonitorThread = 0;

char ProcessTempLogPath[256];

HANDLE hDevice, hEventProcess, hEventImage, hThreadProcess, hThreadProcessQueue, hThreadImage, hThreadImageQueue;

ProcessInfo *FirstEventProcess, *LastEventProcess;

typedef struct {
	char hash[33];
	ULONGLONG time;
	UT_hash_handle hh;
} image_t;

image_t *Image = NULL;

DWORD WINAPI ProcessMonitorQueueThread(LPVOID);
DWORD WINAPI ProcessMonitorThread(LPVOID);
DWORD WINAPI CleanProcessMonitorThread(LPVOID);

void ProcessEvent(ProcessInfo *);
void ImageEvent(ProcessInfo *);

extern char *CurrentLog;
extern unsigned NumTransactionsCurrent;

/**********************************************************************************/

void LoadProcessMonitorDriver(void) {

	SC_HANDLE scmHandle, serviceHandle;
	BOOL ret;
	char path[1024], str[1024];

	if (GetParameter("SOFTWARE_PATH", 0) == NULL) return;

	scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (NULL == scmHandle)
	{
		sprintf_s(str, 1024, "ERROR LoadProcessMonitorDriver OpenSCManager failed (%d)", GetLastError());
		LogError(str);
		return;
	}

	serviceHandle = OpenServiceA(scmHandle, PROCESS_MONITOR_NAME, SC_MANAGER_ALL_ACCESS);
	if (serviceHandle)	// Ja està creat
	{
		ret = StartService(serviceHandle, 0, NULL);
		if (ret == 0)  {
			if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
				sprintf_s(str, 1024, "ProcessMonitorDriver StartService failed (%d)", GetLastError());
				LogError(str);
			}
		}
		//else printf("ProcessMonitorDriver.sys iniciat OK\n");

		CloseServiceHandle(serviceHandle);
		CloseServiceHandle(scmHandle);

		return;
	}

	//printf("LoadDriver: abans CreateService\n");
	//printf("SOFTWARE_PATH=%s\n", GetParameter("SOFTWARE_PATH", 0));
	sprintf_s(path, 1024, "%sProcessMonitorDriver.sys", GetParameter("SOFTWARE_PATH", 0));
	//sprintf(path, "system32\\drivers\\ProcessMonitorDriver.sys");
	printf("LoadProcessMonitorDriver <%s>\n", path);

	serviceHandle = CreateServiceA(
		scmHandle,
		PROCESS_MONITOR_NAME,
		PROCESS_MONITOR_NAME,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_AUTO_START,
		SERVICE_ERROR_IGNORE,
		path,
		NULL,
		NULL,
		NULL,
		NULL,
		"");
	if (!serviceHandle) {
		sprintf_s(str, 1024, "LoadProcessMonitorDriver CreateService failed (%d)", GetLastError());
		LogError(str);
		CloseServiceHandle(scmHandle);
		return;
	}

	if (!StartService(serviceHandle, 0, NULL)) {
		sprintf_s(str, 1024, "LoadProcessMonitorDriver StartService failed (%d)", GetLastError());
		LogError(str);
		CloseServiceHandle(scmHandle);
		return;
	}

	CloseServiceHandle(scmHandle);

	LogError("ProcessMonitorDriver.sys creat OK");
}

/**********************************************************************************/

void InitializeProcessMonitor(void)
{
	//DWORD dwReturn;
	//BOOL status;
	char str[1024];

	FirstEventProcess = NULL;
	LastEventProcess = NULL;

	LoadProcessMonitorDriver();

	hDevice = NULL;
	hEventProcess = NULL;
	hEventImage = NULL;

	hDevice = CreateFileA(PROCESS_MONITOR_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
		//OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		sprintf_s(str, 1024, "InitializeProcessMonitor ERROR: InitializeProcessMonitor - CreateFile %i", GetLastError());
		LogError(str);
		return;
	}
	// else printf("InitializeProcessMonitor - CreateFile OK\n");

	hEventProcess = OpenEvent(SYNCHRONIZE, FALSE, L"Global\\CaptureProcDrvProcessEvent");

	hThreadProcess = CreateThread(NULL, 0, ProcessMonitorThread, NULL, 0, NULL);
	if (hThreadProcess == NULL) {
		LogError("InitializeProcessMonitor ERROR: InitializeProcessMonitor - CreateThread ProcessMonitorThread");
		return;
	}

	hThreadProcessQueue = CreateThread(NULL, 0, ProcessMonitorQueueThread, NULL, 0, NULL);
	if (hThreadProcessQueue == NULL) {
		LogError("InitializeProcessMonitor ERROR: InitializeProcessMonitor - CreateThread ProcessMonitorQueueThread");
		return;
	}

	hCleanProcessMonitorThread = CreateThread(NULL, 0, CleanProcessMonitorThread, NULL, 0, NULL);
	if (hCleanProcessMonitorThread == NULL) {
		LogError("InitializeNetworkMonitor ERROR: InitializeProcessMonitor - CreateThread CleanProcessMonitorThread");
		return;
	}

	// printf("InitializeProcessMonitor - CreateThread OK\n");
}

/**********************************************************************************/

DWORD WINAPI ProcessMonitorThread(LPVOID lpdwThreadParam) {

	BOOL stat;
	char outbuf[1024];
	DWORD dwReturn;
	ProcessInfo *p;

	lpdwThreadParam;

	while (1) {

		//ResetEvent(hEventProcess);

	    //printf("IOCTL_CAPTURE_GET_PROCINFO=%lu\n", (ULONG)IOCTL_CAPTURE_GET_PROCINFO);

		WaitForSingleObject(hEventProcess, INFINITE);

		p = malloc(sizeof(ProcessInfo));
		if (p == NULL) LogError("ProcessMonitorThread malloc event");

		stat = DeviceIoControl(hDevice,
			IOCTL_CAPTURE_GET_PROCINFO,
			NULL,
			0,
			p,
			sizeof(ProcessInfo),
			&dwReturn,
			NULL);
		if (dwReturn==0)
		{
			sprintf_s(outbuf, 1024, "ProcessMonitorThread - DeviceIoControl %d", GetLastError());
			LogError(outbuf);
			return 0;
		}

		//if (p->processPathLength>0)
		//  wprintf(L"Captured %02d:%02d:%02d parentId=%ld ProcessId=%ld processPath=<%ls>\n",
		//	p->time.Hour, p->time.Minute, p->time.Second,
		//	p->ParentId, p->ProcessId, p->processPath);
		//printf("ProcessMonitorThread <%s> strlen=%d\n", outbuf, strlen(outbuf));
		//printf("ProcessMonitorThread <%s>\n", outbuf);

		p->next = NULL;
		//e->buffer = malloc(strlen(outbuf) + 1);
		//if (e->buffer == NULL) LogError("ProcessMonitorThread malloc buffer");
		//strcpy(e->buffer, outbuf);

		if (FirstEventProcess == NULL) FirstEventProcess = p;
		if (LastEventProcess != NULL) LastEventProcess->next = p;
		LastEventProcess = p;
	}

	//CloseHandle(hDevice);
}

/**********************************************************************************/

DWORD WINAPI ProcessMonitorQueueThread(LPVOID lpdwThreadParam) {

	ProcessInfo *p;

	lpdwThreadParam;

	while (1) {

		if (FirstEventProcess == NULL) {

			Sleep(10);
			continue;
		}

		p = FirstEventProcess;

		if (p->bCreate<2) {
			//wprintf(L"Create=%i parentId=%ld ProcessId=%ld processPath=<%ls>\n", p->bCreate, p->ParentId, p->ProcessId, p->processPath);
			ProcessEvent(p);
		}
		else {
			ImageEvent(p);
		}

		FirstEventProcess = p->next;
		if (p == LastEventProcess) LastEventProcess = NULL;

		if (p!= NULL) free(p);
	}
}

/**********************************************************************************/

void ImageEvent(ProcessInfo *ie) {

	char str[1024], Path[1024], Path2[1024], hash[33];
	image_t *p;
	char hash_sha256[128], CreationTime3[32], LastWriteTime3[32];
	DWORD dWFileSize, dwFileType;
	FILETIME CreationTime, LastWriteTime;
	SYSTEMTIME CreationTime2, LastWriteTime2;
	size_t i;

	if (ie->processPath == NULL) return;

	wcstombs_s(&i, Path, 1024, ie->processPath, 1024);

	//printf("\nPath=<%s>\n", Path);

	// \SystemRoot\System32\ntdll.dll
	// \SystemRoot\SysWOW64\ntdll.dll

	if (strncmp(Path, "\\SystemRoot\\", 12) == 0) {
		strcpy_s(Path2, 1024, "\\Windows");
		strcat_s(Path2, 1024, &Path[11]);
		strcpy_s(Path, 1024, Path2);
	}

	if (strncmp(Path, "\\Device\\", 8) == 0) {
		for (i = 8; ((i < strlen(Path)) && (Path[i] != '\\')); i++);
		strcpy_s(Path2, 1024, &Path[i]);
		strcpy_s(Path, 1024, Path2);
	}

	calc_hash_string(CALG_MD5, Path, hash);
	// printf("<%s> hash=<%s>\n", &outbuf[20], hash);

	HASH_FIND(hh, Image, &hash, 32, p);

	//printf("%p Path=<%s>\n", p, Path);

	memset(hash_sha256, 0, sizeof(hash_sha256));
	dWFileSize = 0;
	dwFileType = 0;
	memset(&CreationTime, 0, sizeof(CreationTime));
	memset(&LastWriteTime, 0, sizeof(LastWriteTime));

	if (p) {  // Aquest hash està a la taula de hashos

		//printf("%s hash=<%s> p->time=%lli Tick=%lli p->time+OFFSET=%lli\n", ProcessName, hash, p->time, GetTickCount64(), p->time + LOG_IMAGE_TIMEOUT_MS);

		if (p->time + LOG_IMAGE_TIMEOUT_MS < GetTickCount64()) {	// ms

			//printf("calc_hash ImageEvent OLD Path=<%s>\n", Path);

			calc_hash(CALG_SHA_256, Path, hash_sha256, &dWFileSize, &dwFileType, &CreationTime, &LastWriteTime);

			FileTimeToSystemTime(&CreationTime, &CreationTime2);	// SystemTime en UTC
			FileTimeToSystemTime(&LastWriteTime, &LastWriteTime2);	// SystemTime en UTC

			sprintf_s(CreationTime3, 32, "%04d%02d%02dT%02d%02d%02d",
				CreationTime2.wYear, CreationTime2.wMonth, CreationTime2.wDay, CreationTime2.wHour, CreationTime2.wMinute, CreationTime2.wSecond);

			sprintf_s(LastWriteTime3, 32, "%04d%02d%02dT%02d%02d%02d",
				LastWriteTime2.wYear, LastWriteTime2.wMonth, LastWriteTime2.wDay, LastWriteTime2.wHour, LastWriteTime2.wMinute, LastWriteTime2.wSecond);

			sprintf_s(str, 1024, "L\t%llu\t%s\t%s\t%d\t%d\t%s\t%s",
				(long long unsigned)ie->ProcessId, Path, hash_sha256, dWFileSize, dwFileType, CreationTime3, LastWriteTime3);

			p->time = GetTickCount64();

			printf("%s\n", str);
			Logs(str);
		}
	}
	else {	// Aquest hash NO està a la taula de hashos

		//printf("calc_hash ImageEvent NEW Path=<%s>\n", Path);

		calc_hash(CALG_SHA_256, Path, hash_sha256, &dWFileSize, &dwFileType, &CreationTime, &LastWriteTime);

		FileTimeToSystemTime(&CreationTime, &CreationTime2);	// SystemTime en UTC
		FileTimeToSystemTime(&LastWriteTime, &LastWriteTime2);	// SystemTime en UTC

		sprintf_s(CreationTime3, 32, "%04d%02d%02dT%02d%02d%02d",
			CreationTime2.wYear, CreationTime2.wMonth, CreationTime2.wDay, CreationTime2.wHour, CreationTime2.wMinute, CreationTime2.wSecond);

		sprintf_s(LastWriteTime3, 32, "%04d%02d%02dT%02d%02d%02d",
			LastWriteTime2.wYear, LastWriteTime2.wMonth, LastWriteTime2.wDay, LastWriteTime2.wHour, LastWriteTime2.wMinute, LastWriteTime2.wSecond);

		sprintf_s(str, 1024, "L\t%llu\t%s\t%s\t%d\t%d\t%s\t%s",
			(long long unsigned)ie->ProcessId, Path, hash_sha256, dWFileSize, dwFileType, CreationTime3, LastWriteTime3);

		printf("%s\n", str);
		Logs(str);

		p = malloc(sizeof(image_t));
		memset(p, 0, sizeof(image_t));
		strcpy_s(p->hash, 33, hash);
		p->time = GetTickCount64();

		HASH_ADD(hh, Image, hash, 32, p);
	}
}

/**********************************************************************************/

void ProcessEvent(ProcessInfo *ie) {

	char str[1024], Path[1024], Path2[1024];
	char hash_sha256[128], CreationTime3[32], LastWriteTime3[32];
	DWORD dWFileSize, dwFileType;
	FILETIME CreationTime, LastWriteTime;
	SYSTEMTIME st, CreationTime2, LastWriteTime2;
	char strtime[32];
	size_t i;
	LPSTR process_sid=NULL, parent_sid=NULL;
	char ParentUserName[128], ParentDomainName[128];
	char ProcessUserName[128], ProcessDomainName[128];
	DWORD len1, len2;
	SID_NAME_USE Use;

	if (ie->processPath == NULL) return;

	FileTimeToSystemTime((FILETIME *)&(ie->time), &st);
	sprintf_s(strtime, 32, "%04d%02d%02dT%02d%02d%02d.%03d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

	if (ConvertSidToStringSidA(ie->ParentSID, &parent_sid) == 0)
		printf("ProcessEvent ConvertSidToStringSidA error=%i\n", GetLastError());
	len1 = 128; len2 = 128;
	LookupAccountSidA(NULL, ie->ParentSID, ParentUserName, &len1, ParentDomainName, &len2, &Use);

	if (ConvertSidToStringSidA(ie->ProcessSID, &process_sid) == 0)
		printf("ProcessEvent ConvertSidToStringSidA error=%i\n", GetLastError());
	len1 = 128; len2 = 128;
	LookupAccountSidA(NULL, ie->ProcessSID, ProcessUserName, &len1, ProcessDomainName, &len2, &Use);

	//printf("sid=<%s> ParentDomainName=<%s> ParentUserName=<%s>\n", parent_sid, ParentDomainName, ParentUserName);
	//printf("sid=<%s> ProcessDomainName=<%s> ProcessUserName=<%s>\n", process_sid, ProcessDomainName, ProcessUserName);

	wcstombs_s(&i, Path, 1024, ie->processPath, 1024);

	//printf("\nPath=<%s>\n", Path);

	if (ie->bCreate == 0) { // Terminate process

		sprintf_s(str, 1024, "T\t%s\t%llu\t%s\t%s\t%s\t%llu\t%s\t%s\t%s\t%s", 
			strtime, 
			(long long unsigned)ie->ParentId, parent_sid, ParentDomainName, ParentUserName,
			(long long unsigned)ie->ProcessId, process_sid, ProcessDomainName, ProcessUserName, 
			Path);
	}
	else { // Create process

		// \SystemRoot\System32\ntdll.dll
		// \SystemRoot\SysWOW64\ntdll.dll

		if (strncmp(Path, "\\SystemRoot\\", 12) == 0) {
			strcpy_s(Path2, 1024, "\\Windows");
			strcat_s(Path2, 1024, &Path[11]);
			strcpy_s(Path, 1024, Path2);
		}

		if (strncmp(Path, "\\Device\\", 8) == 0) {
			for (i = 8; ((i < strlen(Path)) && (Path[i] != '\\')); i++);
			strcpy_s(Path2, 1024, &Path[i]);
			strcpy_s(Path, 1024, Path2);
		}

		//printf("Path=<%s>\n", Path);

		memset(hash_sha256, 0, sizeof(hash_sha256));
		dWFileSize = 0;
		dwFileType = 0;
		memset(&CreationTime, 0, sizeof(CreationTime));
		memset(&LastWriteTime, 0, sizeof(LastWriteTime));

		calc_hash(CALG_SHA_256, Path, hash_sha256, &dWFileSize, &dwFileType, &CreationTime, &LastWriteTime);

		FileTimeToSystemTime(&CreationTime, &CreationTime2);	// SystemTime en UTC
		FileTimeToSystemTime(&LastWriteTime, &LastWriteTime2);	// SystemTime en UTC

		sprintf_s(CreationTime3, 32, "%04d%02d%02dT%02d%02d%02d",
			CreationTime2.wYear, CreationTime2.wMonth, CreationTime2.wDay, CreationTime2.wHour, CreationTime2.wMinute, CreationTime2.wSecond);

		sprintf_s(LastWriteTime3, 32, "%04d%02d%02dT%02d%02d%02d",
			LastWriteTime2.wYear, LastWriteTime2.wMonth, LastWriteTime2.wDay, LastWriteTime2.wHour, LastWriteTime2.wMinute, LastWriteTime2.wSecond);

		sprintf_s(str, 1024, "P\t%s\t%llu\t%s\t%s\t%s\t%llu\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s", 
			strtime, 
			(long long unsigned)ie->ParentId, parent_sid, ParentDomainName, ParentUserName,
			(long long unsigned)ie->ProcessId, process_sid, ProcessDomainName, ProcessUserName, 
			Path, hash_sha256, dWFileSize, dwFileType, CreationTime3, LastWriteTime3);
	}

	printf("%s\n", str);
	Logs(str);

	if (parent_sid) LocalFree(parent_sid);
	if (process_sid) LocalFree(process_sid);
}

/**********************************************************************************/

DWORD WINAPI CleanProcessMonitorThread(LPVOID lpParam) {

	image_t *i, *j;

	lpParam;

	while (1) {

		//EnterCriticalSection(&gCleanProcessMonitorCS);

		HASH_ITER(hh, Image, i, j) {

			//printf("Clean Test %i\n", GetTickCount64() - i->time);

			if (i->time + LOG_IMAGE_TTL_MS < GetTickCount64()) {	// ms

				HASH_DEL(Image, i); // Esborrar hash de la taula
				free(i);
			}
		}

		//LeaveCriticalSection(&gCleanProcessMonitorCS);

		Sleep(60000); /* 60000 ms = 1 min */
	}
}

/**********************************************************************************/
