#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "uthash.h"

#define LOCALPASSWORD "MAgdPz;I6C@aA340iL*%Lfl"

#define WMI_REFRESH_DEFAULT "3600"
#define CONFIG_REFRESH_DEFAULT "600"

#include "log.h"
#include "Param.h"

typedef struct {
	char name[32];
	int n;
	char *value;
	UT_hash_handle hh; /* makes this structure hashable */
} parameter_t;

typedef struct {
	char name[32];
	int n;
} lookup_key_t;

parameter_t *Parameters = NULL;

/**********************************************************************************/

void SetParameter(char *key, int n, char *value) {

	parameter_t *p;
	lookup_key_t lookup_key;
	unsigned keylen;

	memset(&lookup_key.name, 0, sizeof(lookup_key.name));
	strcpy_s(lookup_key.name, sizeof(lookup_key.name), key);
	lookup_key.n = n;

	keylen = offsetof(parameter_t, n)		/* offset of last key field */
		   + sizeof(p->n)					/* size of last key field */
		   - offsetof(parameter_t, name);	/* offset of first key field */

	HASH_FIND(hh, Parameters, &lookup_key, keylen, p);
	
	// printf("<%s> p=%p\n", key, p);

	if (p) { // El parametre ja existeix

		if (p->value != NULL) free(p->value);
		p->value = malloc(strlen(value)+1);
		strcpy_s(p->value, strlen(value) + 1, value);
	}
	else { // El parametre no existeix

		p = malloc(sizeof(parameter_t));
		memset(p, 0, sizeof(parameter_t));

		memset(p->name, 0, sizeof(p->name));
		strcpy_s(p->name, sizeof(p->name), key);
		p->n = n;
		p->value = malloc(strlen(value) + 1);
		strcpy_s(p->value, strlen(value) + 1, value);

		HASH_ADD(hh, Parameters, name, keylen, p);
	}
}

/**********************************************************************************/

char* GetParameter(char *key, int n) {

	parameter_t *p;
	lookup_key_t lookup_key;
	unsigned keylen;

	keylen = offsetof(parameter_t, n)      /* offset of last key field */
		   + sizeof(p->n)				   /* size of last key field */
		   - offsetof(parameter_t, name);  /* offset of first key field */

	memset(&lookup_key.name, 0, sizeof(lookup_key.name));
	strcpy_s(lookup_key.name, 32, key);
	lookup_key.n = n;

	HASH_FIND(hh, Parameters, &lookup_key.name, keylen, p);
	if (p == NULL) return NULL;
	else return p->value;
}

/**********************************************************************************/

void InitializeParameters(void) {

	char SoftwarePath[1024], path[1024];
	DWORD size;
	long ret;

	Parameters = NULL;

	SetParameter("ID_AGENT", 0, "0");

	size = 1024;
	ret = RegGetValueA(HKEY_LOCAL_MACHINE,
		"SYSTEM\\CurrentControlSet\\services\\Sauron\\Parameters",
		"AppDirectory",
		RRF_RT_ANY,
		NULL,
		SoftwarePath,
		&size);
	if (ret==ERROR_SUCCESS) {
		SetParameter("SOFTWARE_PATH", 0, SoftwarePath);
	}
	else {
		printf("InitializeParameters - RegGetValue services\\Sauron\\Parameters\\AppDirectory ret=%i\n", ret);
		exit(1);
	}

	SetParameter("SOFTWARE_PATH", 0, SoftwarePath);

	sprintf_s(path, sizeof(path), "%sConfig", SoftwarePath);
	SetParameter("CONFIG_PATH", 0, path);
	SetParameter("CONFIG_REFRESH", 0, CONFIG_REFRESH_DEFAULT);				// In seconds
	SetParameter("CONFIG_LAST_TIME", 0, "0");

	SetParameter("UPDATE_SERVER_ADDRESS", 0, "10.125.17.3");
	SetParameter("UPDATE_SERVER_PORT", 0, "443");
	SetParameter("UPDATE_SERVER_METHOD", 0, "GET");

#if (_WIN64) 
	SetParameter("UPDATE_SERVER_RESOURCE", 0, "/files/x64/");
#else
	SetParameter("UPDATE_SERVER_RESOURCE", 0, "/files/x86/");
#endif

	SetParameter("WHITE_SERVER_ADDRESS", 0, "10.125.17.3");
	SetParameter("WHITE_SERVER_PORT", 0, "443");
	SetParameter("WHITE_SERVER_METHOD", 0, "GET");
	SetParameter("WHITE_SERVER_RESOURCE", 0, "/white/windows7");

	sprintf_s(path, 1024, "%sWhite", SoftwarePath);
	SetParameter("WHITE_PATH", 0, path);

	SetParameter("LOG_SERVER_ADDRESS", 0, "10.125.17.3");
	SetParameter("LOG_SERVER_PORT", 0, "443");
	SetParameter("LOG_SERVER_METHOD", 0, "POST");
	SetParameter("LOG_SERVER_RESOURCE", 0, "/");

	SetParameter("LOG_MAX_TRANSACTIONS", 0, "250");
	SetParameter("LOG_TIMEOUT", 0, "60"); // en segons
	sprintf_s(path, 1024, "%sLog", SoftwarePath);
	SetParameter("LOG_FOLDER", 0, path);

	/*
	SetParameter("MONITOR_PROCESS_CREATE", 0, "S");		// D=disable L=LocalFile S=Server
	SetParameter("MONITOR_PROCESS_TERMINATE", 0, "S");	// D=disable L=LocalFile S=Server
	SetParameter("MONITOR_THREAD_CREATE", 0, "D");		// D=disable L=LocalFile S=Server
	SetParameter("MONITOR_THREAD_TERMINATE", 0, "D");	// D=disable L=LocalFile S=Server
	
	SetParameter("MONITOR_FILE", 0, "D");				// D=disable L=LocalFile S=Server
	*/

	SetParameter("MONITOR_NETWORK_PACKETS", 0, "1000");

	// MONITOR_NETWORK - NumRule - NumDevice IPSrc IPDst PortSrc PortDst Log IncludeData
	SetParameter("MONITOR_NETWORK", 0, "1 * * 53 * S 1");	// DNS
	SetParameter("MONITOR_NETWORK", 1, "1 * * * 53 S 1");	// DNS
	//SetParameter("MONITOR_NETWORK", 2, "1 * * 80 * L 1");	// HTTP
	//SetParameter("MONITOR_NETWORK", 3, "1 * * * 80 L 0");	// HTTP

	SetParameter("EVENT_LOG_REFRESH", 0, "10000");			// En ms

	SetParameter("EVENT_LOG_NAME", 0, "Application");
	SetParameter("EVENT_LOG_LOG", 0, "S");					// D=disable L=LocalFile S=Server
	SetParameter("EVENT_LOG_LAST_RECORD_NUMBER", 0, "0");

	SetParameter("EVENT_LOG_NAME", 1, "Security");
	SetParameter("EVENT_LOG_LOG", 1, "S");					// D=disable L=LocalFile S=Server
	SetParameter("EVENT_LOG_LAST_RECORD_NUMBER", 1, "0");

	SetParameter("EVENT_LOG_NAME", 2, "System");
	SetParameter("EVENT_LOG_LOG", 2, "S");					// D=disable L=LocalFile S=Server
	SetParameter("EVENT_LOG_LAST_RECORD_NUMBER", 2, "0");

	//SetParameter("EVENT_LOG_NAME", 3, "Microsoft-Windows-Sysmon/Operational");
	//SetParameter("EVENT_LOG_LOG", 3, "S");					// D=disable L=LocalFile S=Server
	//SetParameter("EVENT_LOG_LAST_RECORD_NUMBER", 3, "0");

	//SetParameter("EVENT_LOG_NAME", 0, "Windows PowerShell");
	//SetParameter("EVENT_LOG_LAST_TIME", 0, "0");

	/*
	SetParameter("WMI_NAME", 0, "Win32_OperatingSystem");	// Operating System
	SetParameter("WMI_LOG", 0, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 0, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 0, "0");

	SetParameter("WMI_NAME", 1, "Win32_PhysicalMedia");		// Physical Media
	SetParameter("WMI_LOG", 1, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 1, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 1, "0");

	SetParameter("WMI_NAME", 2, "Win32_NetworkAdapterConfiguration");	// Network Configuration
	SetParameter("WMI_LOG", 2, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 2, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 2, "0");

	SetParameter("WMI_NAME", 3, "Win32_IP4RouteTable");		// Routing Table
	SetParameter("WMI_LOG", 3, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 3, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 3, "0");

	SetParameter("WMI_NAME", 4, "Win32_IP4PersistedRouteTable");	// Persisted Routing Table
	SetParameter("WMI_LOG", 4, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 4, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 4, "0");

	SetParameter("WMI_NAME", 5, "Win32_UserAccount");		// Usuaris
	SetParameter("WMI_LOG", 5, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 5, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 5, "0");

	SetParameter("WMI_NAME", 6, "Win32_Group");				// Grups
	SetParameter("WMI_LOG", 6, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 6, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 6, "0");

	SetParameter("WMI_NAME", 7, "Win32_LogicalDisk");		// Local storage devices
	SetParameter("WMI_LOG", 7, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 7, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 7, "0");

	SetParameter("WMI_NAME", 8, "Win32_Share");				// Shares
	SetParameter("WMI_LOG", 8, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 8, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 8, "0");

	SetParameter("WMI_NAME", 9, "Win32_Printer");			// Printers
	SetParameter("WMI_LOG", 9, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 9, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 9, "0");

	SetParameter("WMI_NAME", 10, "Win32_Product");			// Installed software
	SetParameter("WMI_LOG", 10, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 10, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 10, "0");

	SetParameter("WMI_NAME", 11, "Win32_LoggedOnUser");		// Logged On User
	SetParameter("WMI_LOG", 11, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 11, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 11, "0");

	SetParameter("WMI_NAME", 12, "Win32_Service");			// Services
	SetParameter("WMI_LOG", 12, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 12, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 12, "0");

	SetParameter("WMI_NAME", 13, "Win32_Process");			// Running processes
	SetParameter("WMI_LOG", 13, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 13, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 13, "0");

	SetParameter("WMI_NAME", 14, "Win32_QuickFixEngineering");		// QFE (Quick-Fix Engineering) updates
	SetParameter("WMI_LOG", 14, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 14, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 14, "0");

	SetParameter("WMI_NAME", 15, "Win32_LogonSession");		// Logon sessions
	SetParameter("WMI_LOG", 15, "S");						// D=disable L=LocalFile S=Server
	SetParameter("WMI_REFRESH", 15, WMI_REFRESH_DEFAULT);	// In seconds
	SetParameter("WMI_LAST_TIME", 15, "0");
	*/
}

/**********************************************************************************/

void WriteConfiguration(void) {

	FILE *fp;
	char *buffer, str[4096];
	DWORD num, length, length_buf;
	parameter_t *p;
	errno_t err;
	int i;

	length = 0;
	num = 0;
	for (p = Parameters; (p != NULL); p = p->hh.next) {
		// printf("<%s> <%s> len=%i\n", p->name, p->value, strlen(p->value));
		sprintf_s(str, 4096, "%s\t%i\t%s\n", p->name, p->n, p->value);
		length += (int)strlen(str);
		num++;
	}
	sprintf_s(str, 4096, "%i\n", num);
	length += (int)strlen(str);

	// printf("\nlength=%i\n", length);

	length_buf = length;
	AESEncryptDecrypt(NULL, &length_buf, length, 1);

	buffer = calloc(length_buf, 1);
	if (buffer == 0) {
		printf("WriteConfiguration: erroc calloc\n");
		exit(1);
	}

	length = 0;
	sprintf_s(buffer, length_buf, "%i\n", num);
	for (p = Parameters; (p != NULL); p = p->hh.next) {
		sprintf_s(str, 4096, "%s\t%i\t%s\n", p->name, p->n, p->value);
		strcat_s(buffer, length_buf, str);
	}

	length = (int)strlen(buffer);
	// printf("\nlength=%i length_buf=%i\n", length, length_buf);

	AESEncryptDecrypt(buffer, &length, length_buf, 1);

	for (i = 0; (i < 60); i++) {
		printf("Writing <%s>\n", GetParameter("CONFIG_PATH", 0));
		err = fopen_s(&fp, GetParameter("CONFIG_PATH", 0), "wb");
		if (err == 0) break;
		printf("Write Configuration - fopen %s (errno=%i)\n", GetParameter("CONFIG_PATH", 0), err);
		Sleep(1000); // 1 s
	}

	if (i >= 60) {
		printf("ERROR Write Configuration - fopen %s\n", GetParameter("CONFIG_PATH", 0));
		exit(1);
	}

	fwrite(buffer, length, 1, fp);
	fclose(fp);

	free(buffer);
}

/**********************************************************************************/

void ReadConfiguration(void) {

	FILE *fp;
	char *buffer, name[32], value[128], nn[8];
	DWORD i, length;
	int i0, j, j0, n, num;

	printf("CONFIG_PATH=<%s>\n", GetParameter("CONFIG_PATH", 0));

	if (fopen_s(&fp, GetParameter("CONFIG_PATH", 0), "rb") != 0) {
		WriteConfiguration();
		printf("Generant fitxer config\n");
		return;
	}
	fseek(fp, 0L, SEEK_END);
	length = ftell(fp);

	buffer = calloc(length, 1);

	fseek(fp, 0L, SEEK_SET);
	fread(buffer, length, 1, fp);
	fclose(fp);

	if (AESEncryptDecrypt(buffer, &length, length, 0)) {
		WriteConfiguration();
		printf("Regenerant fitxer config\n");
	}

	//printf("DECRYPTED=%s\n", buffer);

	i0 = 0;
	for (i = i0; ((i < length)&&(buffer[i]!='\n')); i++);
	buffer[i] = 0;
	num = atoi(buffer);
	
	// printf("num=%i\n", num);

	for (n = 0; (n < num); n++) {

		i0 = i + 1;
		for (i = i0; ((i < length) && (buffer[i] != '\n')); i++);
		buffer[i] = 0;

		//printf("%2i <%s>\n", n, &buffer[i0]);

		j0 = i0;
		for (j = j0; (buffer[j] != '\t'); j++);
		buffer[j] = 0;
		// printf("\t<%s>\n", &buffer[j0]);
		strcpy_s(name, 32, &buffer[j0]);

		j0 = j + 1;
		for (j = j0; (buffer[j] != '\t'); j++);
		buffer[j] = 0;
		// printf("\t<%s>\n", &buffer[j0]);
		strcpy_s(nn, 8, &buffer[j0]);

		j0 = j + 1;
		// printf("\t<%s>\n", &buffer[j0]);
		strcpy_s(value, 128, &buffer[j0]);

		//printf("SetParameter <%s>\n", name);
		SetParameter(name, atoi(nn), value);
	}

	free(buffer);
}

/**********************************************************************************/

void PrintConfiguration() {

	parameter_t *p;

	for (p = Parameters; (p != NULL); p = p->hh.next)
		printf("%s\t%i\t%s\n", p->name, p->n, p->value);
}

/**********************************************************************************/

int AESEncryptDecrypt(char *buffer, DWORD *length_data, DWORD length_buffer, int enc) {

	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HCRYPTHASH hHash;
	DWORD dwLength, dwValLen, dwKeyLen;
	char szLocalPassword[] = LOCALPASSWORD;

	//if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
			printf("AESEncryptDecrypt CryptAcquireContext ERROR 0x%.8X\n", GetLastError());
		exit(1);
	}

	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
		printf("AESEncryptDecrypt CryptCreateHash ERROR 0x%.8X\n", GetLastError());
		exit(1);
	}

	dwLength = (int)strlen(szLocalPassword);
	if (!CryptHashData(hHash, (BYTE *)szLocalPassword, dwLength, 0)) {
		printf("AESEncryptDecrypt CryptHashData ERROR 0x%.8X\n", GetLastError());
		exit(1);
	}

	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &hKey)) {
		printf("AESEncryptDecrypt CryptDeriveKey ERROR 0x%.8X\n", GetLastError());
		exit(1);
	}

	/*
	dwPadding = PKCS5_PADDING;
	CryptSetKeyParam(hKey, KP_PADDING, &dwPadding, 0);

	dwMode=CRYPT_MODE_CBC;
	CryptSetKeyParam(hKey, KP_MODE, &dwMode, 0);

	dwValLen = sizeof(DWORD);
	if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (LPBYTE)&dwBlockLen, &dwValLen, 0)) {
		printf("ReadConfiguration CryptGetKeyParam failed with error 0x%.8X\n", GetLastError());
		exit(1);
	}

	dwBlockLen /= 8;
	iv = calloc(dwBlockLen, 1);

	CryptSetKeyParam(hKey, KP_IV, iv, 0);

	free(iv);
	*/

	dwValLen = sizeof(DWORD);
	if (!CryptGetKeyParam(hKey, KP_KEYLEN, (LPBYTE)&dwKeyLen, &dwValLen, 0)) {
		printf("AESEncryptDecrypt CryptGetKeyParam failed with error 0x%.8X\n", GetLastError());
		exit(1);
	}

	// printf("dwValLen=%i enc=%i length_data=%i length_buffer=%i\n", dwValLen, enc, *length_data, length_buffer);

	if (enc == 1) {
		if (!CryptEncrypt(hKey, (HCRYPTHASH) NULL, TRUE, 0, (BYTE *)buffer, length_data, length_buffer)) { // length_buffer=total size buffer
			printf("AESEncryptDecrypt CryptEncrypt failed with error 0x%.8X\n", GetLastError());
			return 1;
		}
	} 
	else {
		if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, TRUE, 0, (BYTE *)buffer, length_data)) {
			printf("AESEncryptDecrypt CryptEncrypt failed with error 0x%.8X\n", GetLastError());
			return 1;
		}
	}

	if (!CryptDestroyKey(hKey)) {
		printf("AESEncryptDecrypt CryptDestroyKey failed with error 0x%.8X\n", GetLastError());
		exit(1);
	}

	if (!CryptDestroyHash(hHash)) {
		printf("AESEncryptDecrypt CrypteDestroyHash failed with error 0x%.8X\n", GetLastError());
		exit(1);
	}

	if (!CryptReleaseContext(hProv, 0)) {
		printf("AESEncryptDecrypt CryptReleaseContext failed with error 0x%.8X\n", GetLastError());
		exit(1);
	}

	return 0;
}

/**********************************************************************************/

void decrypt_file(char *filein, char *fileout) {

	FILE *fp;
	DWORD length;
	char *buffer;

	if (fopen_s(&fp, filein, "rb") != 0) { printf("encrypt_file fopen error\n");  exit(1); }

	fseek(fp, 0L, SEEK_END);
	length = ftell(fp);

	buffer = calloc(length, 1);

	fseek(fp, 0L, SEEK_SET);
	fread(buffer, length, 1, fp);
	fclose(fp);

	AESEncryptDecrypt(buffer, &length, length, 0);

	if (fopen_s(&fp, fileout, "wb") != 0) { printf("encrypt_file fopen error\n");  exit(1); }
	fwrite(buffer, length, 1, fp);
	fclose(fp);

	return;
}

/**********************************************************************************/

void encrypt_file(char *filein, char *fileout) {

	FILE *fp;
	DWORD length, length_buf;
	char *buffer, *buffer2;

	if (fopen_s(&fp, filein, "rb")!=0) { printf("encrypt_file fopen error\n");  exit(1); }
	fseek(fp, 0L, SEEK_END);
	length = ftell(fp);

	buffer = calloc(length, 1);

	fseek(fp, 0L, SEEK_SET);
	fread(buffer, length, 1, fp);
	fclose(fp);

	length_buf = length;
	AESEncryptDecrypt(NULL, &length_buf, length, 1);
	printf("length=%i length_buf=%i\n", length, length_buf);

	buffer2 = calloc(length_buf, 1);
	if (buffer2 == 0) {
		printf("decrypt_file: erroc calloc\n");
		exit(1);
	}
	memcpy(buffer2, buffer, length);
	free(buffer);

	length = (int)strlen(buffer2);

	AESEncryptDecrypt(buffer2, &length, length_buf, 1);

	if (fopen_s(&fp, fileout, "wb") != 0) { printf("encrypt_file fopen error\n");  exit(1); }
	fwrite(buffer2, length, 1, fp);
	fclose(fp);

	free(buffer2);

	return;
}

/**********************************************************************************/
