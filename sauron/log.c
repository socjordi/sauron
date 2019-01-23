//#define _WIN32_WINNT_WIN7                   0x0601

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <aclapi.h>

#include "Param.h"
#include "https.h"
#include "log.h"
#include "network.h"
#include "miniz.c"	// zlib
#include "hash.h"
#include "event.h"

HANDLE hThread;
unsigned NumTransactionsCurrent;
unsigned MaxTransactions;
char *LogFolder, *CurrentLog;

DWORD WINAPI LogThread(LPVOID);

wchar_t *log_server_address;
int log_server_port;
wchar_t *log_server_method;
wchar_t *log_server_resource;

time_t t_last_log;
SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
PSID pSystemSid = NULL;
EXPLICIT_ACCESS ea;
PACL acl = NULL;
SECURITY_ATTRIBUTES system_sa, *psystem_sa;
PSECURITY_DESCRIPTOR sd;

void SendConfiguration(void);
void SendLog(char *, char *);
void CheckCurrentLogSize(void);
void InitializeSystem(void);
void ProcessResponse(int, char *);

/**********************************************************************************/

void UpdateParameter(char *str) {

	int i, i0, num;
	char nom[1024], valor[1024];

	i0 = 0;
	for (i = i0; ((i < (int)strlen(str)) && ((str[i] != ' ') && (str[i] != '\t'))); i++);

	if (i == strlen(str)) return;

	strncpy_s(nom, 1024, &str[i0], 1024); nom[i - i0] = 0;
	i0 = i + 1;
	for (i = i0; ((i < (int)strlen(str)) && ((str[i] != ' ') && (str[i] != '\t'))); i++);
	if (i == strlen(str)) return;

	strncpy_s(valor, 1024, &str[i0], 1024); valor[i - i0] = 0;
	num = atoi(valor);
	strncpy_s(valor, 1024, &str[i+1], 1024);

	if (valor[strlen(valor) - 1] == '\r') valor[strlen(valor) - 1] = 0;
	if (valor[strlen(valor) - 1] == '\n') valor[strlen(valor) - 1] = 0;

	printf("UpdateParameter %s %i = %s\n", nom, num, valor);
	SetParameter(nom, num, valor);
}

/**********************************************************************************/

void GetAgentId(void) {

	//char line[4096];
	char *ComputerName;
	//unsigned long mida;
	DWORD len;

	if ((GetParameter("ID_AGENT", 0) == NULL) || (strcmp(GetParameter("ID_AGENT", 0), "0") == 0)) {

		GetComputerNameExA(ComputerNameDnsHostname, NULL, &len);
		ComputerName = (char*)malloc(len);
		GetComputerNameExA(ComputerNameDnsHostname, ComputerName, &len);
		printf("ComputerName=<%s>\n", ComputerName);
		SetParameter("ID_AGENT", 0, ComputerName);
	}

	/*
	if (strcmp(GetParameter("ID_AGENT", 0), "0") == 0) {

		mida = 1024;
		line[0] = 0;
		if (send_https("?GetAgentId", &mida, line) == 0) {

			if (line[strlen(line) - 1] == '\r') line[strlen(line) - 1] = 0;
			if (line[strlen(line) - 1] == '\n') line[strlen(line) - 1] = 0;

			//printf("Received ID_AGENT=<%s>\n", line);
			//SetParameter("ID_AGENT", 0, line);

			ProcessResponse(mida, line);

			printf("WriteConfiguration getAgentId\n");
			WriteConfiguration();
			SendConfiguration();
		}
	}
	*/
}

/**********************************************************************************/

void InitializeLog(void) {

	char line[1024];
	HANDLE hFile;
	FILE *fp;
	size_t n, len;

	if (GetParameter("LOG_MAX_TRANSACTIONS", 0) == NULL) return;
	if (GetParameter("LOG_FOLDER", 0) == NULL) return;
	if (GetParameter("LOG_SERVER_ADDRESS", 0) == NULL) return;
	if (GetParameter("LOG_SERVER_PORT", 0) == NULL) return;
	if (GetParameter("LOG_SERVER_METHOD", 0) == NULL) return;
	if (GetParameter("LOG_SERVER_RESOURCE", 0) == NULL) return;

	InitializeSystem();

	NumTransactionsCurrent = 0;

	MaxTransactions = atoi(GetParameter("LOG_MAX_TRANSACTIONS", 0));

	len = strlen(GetParameter("LOG_FOLDER", 0)) + 1;
	LogFolder = malloc(len);
	strcpy_s(LogFolder, len, GetParameter("LOG_FOLDER", 0));

	// Mirem si existeix la carpeta de log, si no existeix la creem
	if (GetFileAttributesA(LogFolder) == INVALID_FILE_ATTRIBUTES) CreateDirectoryA(LogFolder, NULL);

	// Mirem si existeix el fitxer "current", si no existeix el creem
	len += 8;
	CurrentLog = malloc(len);
	sprintf_s(CurrentLog, len, "%s\\current", LogFolder);

	// printf("CurrentLog=<%s>\n", CurrentLog);

	if (GetFileAttributesA(CurrentLog) == INVALID_FILE_ATTRIBUTES) { // No existeix, el creem

		hFile=CreateFileA(CurrentLog,
			GENERIC_READ | GENERIC_WRITE,       // open for writing
			0,                                  // do not share
			psystem_sa,                         // security (NULL per defecte)
			CREATE_ALWAYS,                      // create new file only 
			FILE_ATTRIBUTE_NORMAL,              // normal file
			NULL);
		CloseHandle(hFile);
	}
	else { // Ja existeix, comptem quantes linies te

		if (fopen_s(&fp, CurrentLog, "r") == 0) {

			NumTransactionsCurrent = 0;
			while (fgets(line, 1024, fp) != NULL) NumTransactionsCurrent++;
			fclose(fp);
		}
	}

	len = strlen(GetParameter("LOG_SERVER_ADDRESS", 0)) + 1;
	log_server_address = malloc(len * sizeof(wchar_t));
	mbstowcs_s(&n, log_server_address, len, GetParameter("LOG_SERVER_ADDRESS", 0), _TRUNCATE);

	log_server_port = atoi(GetParameter("LOG_SERVER_PORT", 0));

	len = strlen(GetParameter("LOG_SERVER_METHOD", 0)) + 1;
	log_server_method = malloc(len * sizeof(wchar_t));
	mbstowcs_s(&n, log_server_method, len, GetParameter("LOG_SERVER_METHOD", 0), _TRUNCATE);

	len = strlen(GetParameter("LOG_SERVER_RESOURCE", 0)) + 1;
	log_server_resource = malloc(len * sizeof(wchar_t));
	mbstowcs_s(&n, log_server_resource, len, GetParameter("LOG_SERVER_RESOURCE", 0), _TRUNCATE);

	// GetAgentId();

	hThread = CreateThread(NULL, 0, LogThread, NULL, 0, NULL);
	if (hThread == NULL)
	{
		printf("ERROR: InitializeLog - CreateThread\n");
		return;
	}
}

/**********************************************************************************/

void LogError(char *data) {		// N=NetworkMonitor, F=FileMonitor. P=ProcessMonitor

  SYSTEMTIME st;
  char strtime[32], ArchiveLog[1024];
  FILE *fp;

  if (GetParameter("SOFTWARE_PATH", 0) == NULL) return;
  if (GetParameter("ID_AGENT", 0) == NULL) return;

  //printf("LogError <%s>\n", data);

  GetSystemTime(&st);	// Coordinated Universal Time (UTC)
  sprintf_s(strtime, 32, "%04d%02d%02dT%02d%02d%02d.%03d",
		    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

  sprintf_s(ArchiveLog, 1024, "%s\\general.log", GetParameter("SOFTWARE_PATH", 0));

  if (fopen_s(&fp, ArchiveLog, "a") == 0) {

	printf("%03i %s\t%s\n", NumTransactionsCurrent, strtime, data);

	fprintf(fp, "%s\t%s\t%s\n", strtime, GetParameter("ID_AGENT", 0), data);
	fclose(fp);
  }
}

/**********************************************************************************/

void CheckCurrentLogSize(void) {

	SYSTEMTIME st;
	char strtime[32], str[1024], ArchiveLog[1024];
	int ret, m;
	HANDLE hFile;
	time_t t_now, t;

	if (GetParameter("LOG_TIMEOUT", 0) == NULL) return;

	m = 0;

	if (t_last_log > 0) {

		time(&t_now);
		t = t_now - t_last_log;
		if (t > atoi(GetParameter("LOG_TIMEOUT", 0))) {
			m = 1;
			//printf("t_now=%llu t_last=%llu t=%llu m=%i\n", t_now, t_last_log, t, m);
			time(&t_last_log);
		}
	}

	if (NumTransactionsCurrent >= MaxTransactions) {
		m = 1;
		printf("NumTransactionsCurrent=%i MaxTransactions=%i m=%i\n", NumTransactionsCurrent, MaxTransactions, m);
	}

	if (m) {

		GetSystemTime(&st);	// Coordinated Universal Time (UTC)
		sprintf_s(strtime, 32, "%04d%02d%02dT%02d%02d%02d.%03d",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

		sprintf_s(ArchiveLog, 1024, "%s\\%s.log", LogFolder, strtime);

		ret = rename(CurrentLog, ArchiveLog);
		if (ret != 0) {
			sprintf_s(str, 1024, "CheckCurrentLogSize - Error rename <%s> <%s>", CurrentLog, ArchiveLog);
			printf("%s\n", str);
			//LogError(str);
		}
		else {
			sprintf_s(str, 1024, "CheckCurrentLogSize - Rename <%s> <%s>", CurrentLog, ArchiveLog);
			printf("%s\n", str);
		}

		hFile = CreateFileA(CurrentLog,
			GENERIC_READ | GENERIC_WRITE,       // open for writing
			0,                                  // do not share
			psystem_sa,                         // default security (NULL per defecte)	
			CREATE_ALWAYS,                      // create new file only 
			FILE_ATTRIBUTE_NORMAL,              // normal file
			NULL);

		CloseHandle(hFile);

		NumTransactionsCurrent = 0;
	}
}

/**********************************************************************************/

void Logs(char *data) {		// N=NetworkMonitor, F=FileMonitor, P=ProcessMonitor

  FILE *fp;
  SYSTEMTIME st;
  char strtime[32];

  //printf("Logs <%s>\n", data);

  GetAgentId();

  // Si el log "current té més de max_transactions, el renombrem a "YYYMMDD..." i creem un nou "current"
  CheckCurrentLogSize();

  if (GetParameter("ID_AGENT", 0) == NULL) return;

  if (fopen_s(&fp, CurrentLog, "a") == 0) {

	  GetSystemTime(&st);	// Coordinated Universal Time (UTC)
	  time(&t_last_log);
	  sprintf_s(strtime, 32, "%04d%02d%02dT%02d%02d%02d.%03d",
		        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

	  // AESEncryptDecrypt(buffer, &length, length, 0);
	  fprintf(fp, "%s\t%s\t%s\n", GetParameter("ID_AGENT", 0), strtime, data);
	  fclose(fp);
	  NumTransactionsCurrent++;
  }
}

/**********************************************************************************/

void SendConfiguration(void) {

	FILE *fh;
	unsigned long s;
	char *buffer, params[128], str[32], *send_ret;
	FILETIME filetime;
	ULONGLONG time;
	DWORD last, timeseconds, refresh;

	if (GetParameter("ID_AGENT", 0) == NULL) return;
	if (GetParameter("CONFIG_PATH", 0) == NULL) return;

	if (strlen(GetParameter("ID_AGENT", 0)) == 0) return;
	if (strcmp(GetParameter("ID_AGENT", 0), "0") == 0) return;

	if ((GetParameter("CONFIG_LAST_TIME", 0) == NULL) ||(GetParameter("CONFIG_LAST_TIME", 0) == NULL)) last = 0;
	else last = atoi(GetParameter("CONFIG_LAST_TIME", 0));

	if (GetParameter("CONFIG_REFRESH", 0) == NULL) refresh = 600;
	else refresh = atoi(GetParameter("CONFIG_REFRESH", 0));

	GetSystemTimeAsFileTime(&filetime);
	time = (((ULONGLONG)filetime.dwHighDateTime) << 32) + filetime.dwLowDateTime;
	timeseconds = (DWORD)(time / 10000000);

	if (timeseconds > last + refresh) {

		sprintf_s(str, 32, "%li", timeseconds);
		SetParameter("CONFIG_LAST_TIME", 0, str);
	}
	else return;

	printf("SendConfiguration\n");

	if (fopen_s(&fh, GetParameter("CONFIG_PATH", 0), "rb") != 0) {
		printf("ERROR SendConfiguration fopen\n");
		return;
	}

	fseek(fh, 0L, SEEK_END);
	s = ftell(fh);
	rewind(fh);

	buffer = calloc(s, 1);
	if (buffer == NULL) {
		printf("ERROR SendConfiguration malloc\n");
		return;
	}

	fread(buffer, s, 1, fh);
	fclose(fh);

	AESEncryptDecrypt(buffer, &s, s, 0);

	//printf("DECRYPTED=%s\n", buffer);

	sprintf_s(params, 128, "?AgentId=%s&Param=Config.par", GetParameter("ID_AGENT", 0));

	send_ret=send_https(params, &s, buffer);
	if (send_ret != NULL) {
		printf("send_ret=%p\n", send_ret);
		//ProcessResponse(s, send_ret);
		free(send_ret);
	}

	free(buffer);
}

/**********************************************************************************/

void ProcessResponse(int len, char *buffer) {
	
	int i, i0, n, nw;
	char str[1024];

	i = 0;
	n = 0;
	nw = 0;
	while (i < len) {

		for (i0 = i; ((i < len) && (buffer[i] != '\n')); i++);

		strncpy_s(str, 1024, &buffer[i0], i - i0);
		str[i - i0] = 0;

		printf("ProcessResponse <%s>\n", str);

		if (strcmp(str, "EXIT") == 0) exit(1);

		if (strcmp(str, "LOGOK") != 0) {

			UpdateParameter(str);
			n++;
			if (strncmp(str, "WHITE", 5) == 0) nw++;
		}

		i++;
	}

	if (n > 0) {
		printf("WriteConfiguration ProcessResponse\n");
		WriteConfiguration();
		SetParameter("CONFIG_LAST_TIME", 0, "0");
		SendConfiguration();
		if (nw>0) LoadHashes();
	}
}

/**********************************************************************************/

void SendLog(char *name, char *param) {

	char path[1024], params[128];
	char *buffer, *buffer2;
	FILE *fh;
	char *send_ret;
	BOOL ret;
	unsigned long s, s2;
	int i;

	if (GetParameter("ID_AGENT", 0)==NULL) return;
	if (strlen(GetParameter("ID_AGENT", 0)) == 0) return;
	if (strcmp(GetParameter("ID_AGENT", 0), "0") == 0) return;

	printf("SendLog name=<%s> param=<%s>\n", name, param);

	sprintf_s(path, 1024, "%s\\%s", LogFolder, name);

	if (fopen_s(&fh, path, "rb") == 0) {

		fseek(fh, 0L, SEEK_END);
		s = ftell(fh);
		rewind(fh);

		buffer = malloc(s);
		if (buffer != NULL)
		{
			fread(buffer, s, 1, fh);

			s2 = compressBound(s);
			buffer2 = malloc(s2);
			compress((unsigned char *)buffer2, (mz_ulong *)&s2, (unsigned char *)buffer, (mz_ulong)s);

			if (strlen(param)==0)
				sprintf_s(params, 128, "?AgentId=%s", GetParameter("ID_AGENT", 0));
			else
				sprintf_s(params, 128, "?AgentId=%s&Param=%s", GetParameter("ID_AGENT", 0), param);

			send_ret = send_https(params, &s2, buffer2);
			if (send_ret != NULL) {

				if (strncmp(send_ret, "LOGOK", 5) == 0) {
					if (fh != NULL) fclose(fh);
					fh = NULL;
					//printf("DeleteFile <%s>\n", path);
					for (i = 0; (i < 10); i++) {
						ret = DeleteFileA(path);
						if (ret != 0) break;
						//printf("SendLog DeleteFile <%s> ret=%i GetLastError=%i\n", path, ret, GetLastError());
						Sleep(500);
					}
				}
				
				ProcessResponse(s2, send_ret);

				free(send_ret);
			}

			free(buffer);
			free(buffer2);
		}

		if (fh != NULL) fclose(fh);
	}
}

/**********************************************************************************/

DWORD WINAPI LogThread(LPVOID lpParam)
{
	WIN32_FIND_DATAA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	char path[1024], min[32];
	//DWORD dwError = 0;
	int n;

	lpParam;

	t_last_log=0;
	
	while (1) {

		n = 0;

		sprintf_s(path, 1024, "%s\\*.log", LogFolder);
		//printf("path=<%s>\n", path);

		// Llegir els fitxers de la carpeta de logs, ordenar-los i processar el primer

		hFind = FindFirstFileA(path, &ffd);
		if (INVALID_HANDLE_VALUE != hFind) {

			strcpy_s(min, 32, "999999999999999.999.log");
			do if (strcmp(min, ffd.cFileName) > 0) strcpy_s(min, 32, ffd.cFileName);
			while (FindNextFileA(hFind, &ffd) != 0);

			SendLog(min, "");
			n++;

			FindClose(hFind);
		}

		sprintf_s(path, 1024, "%s\\*.par", LogFolder);
		//printf("path=<%s>\n", path);

		hFind = FindFirstFileA(path, &ffd);
		if (INVALID_HANDLE_VALUE != hFind)
		{
			do {
				SendLog(ffd.cFileName, ffd.cFileName);
				//t_last_log = 0;
				n++;
			}
			while (FindNextFileA(hFind, &ffd) != 0);
			FindClose(hFind);
		}

		CheckCurrentLogSize();

		if (n==0) Sleep(500); // ms
	}

	return 0;
}

/**********************************************************************************/

void InitializeSystem(void) {

	if (!AllocateAndInitializeSid(&SIDAuthNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid))
	printf("InitializeSystem AllocateAndInitializeSid Error %u\n", GetLastError());

	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = (LPWSTR)pSystemSid;

	SetEntriesInAcl(1, &ea, NULL, &acl);

	sd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE);

	system_sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	system_sa.lpSecurityDescriptor = sd;
	system_sa.bInheritHandle = FALSE;

	psystem_sa = &system_sa;
psystem_sa = NULL;

	return;
}

/**********************************************************************************/
