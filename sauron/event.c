#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include <WinEvt.h>

#include "uthash.h"
#include "event.h"

#include "log.h"
#include "param.h"
#include "hash.h"
#include "https.h"

#define ARRAY_SIZE 10

HANDLE hEventMonitorThread = 0;

typedef struct {
	char hashtype;
	char hash[32];
	UT_hash_handle hh; /* makes this structure hashable */
} hash_t;

typedef struct {
	char hashtype;
	char hash[32];
} hash_lookup_key_t;

hash_t *Hashes = NULL;

void LoadHashes(void);
void AddHash(char hashtype, char *hash);
char CheckHash(char hashtype, char *hash);
DWORD WINAPI EventMonitorThread(LPVOID);

/**********************************************************************************/
/*
Per a testejar:

	eventcreate /T SUCCESS /ID 100 /L APPLICATION /D "Sauron Test"
	eventcreate /T ERROR /ID 100 /L APPLICATION /D "Sauron Test"
*/
/**********************************************************************************/

DWORD events(char *LogName, DWORD last)
{
	DWORD status = ERROR_SUCCESS, l, last2, dwReturned = 0, dwBufferSize = 0, dwBufferUsed = 0, dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
	wchar_t *pwsPath=NULL, pwsQuery[64], *pRenderedContent = NULL;
	int end, out, j, k, c;
	EVT_HANDLE hResults = NULL, hEvents[ARRAY_SIZE], hContext = NULL;
	size_t nameLength, convertedChars, len;
	char strbyte[4], *str=NULL, *str2=NULL, *strhashes=NULL, *strhash=NULL, hash[128], *s1=NULL, *s2=NULL, ret, hashtype;
	errno_t err;
	
	// printf("events <%s> last=%i\n", LogName, last);

	nameLength = strlen(LogName) + 1;
	pwsPath = (wchar_t*)malloc(nameLength*sizeof(wchar_t));
	convertedChars = 0;
	mbstowcs_s(&convertedChars, pwsPath, nameLength, LogName, _TRUNCATE);

	swprintf_s(pwsQuery, 64, L"Event/System[EventRecordID>%i]", last);
	// wprintf(L"last=%i pwsPath=<%s> pwsQuery=<%s>\n", last, pwsPath, pwsQuery);
	// wprintf(L">last=%i\n", last, pwsPath, pwsQuery);

	if (last == 0) end = 1; else end = 0;
	last2 = last;

	hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
	if (NULL == hContext)
	{
		wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
	}

	if (last==0)
		hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection);
	else
 		hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryForwardDirection);

	while (1)
	{
		if (EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
		{
          // printf("dwReturned=%i\n", dwReturned);

		  for (DWORD i = 0; i < dwReturned; i++)
		  {
			  dwBufferSize = 0;
			  dwBufferUsed = 0;
			  dwPropertyCount = 0;
			  pRenderedContent = NULL;

			  // Render Values
			  // printf("EvtRender VALUES %i\n", i);
			  if (!EvtRender(hContext, hEvents[i], 0, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
			  {
				  status = GetLastError();
				  if (status == ERROR_INSUFFICIENT_BUFFER) {

					  dwBufferSize = dwBufferUsed;
					  pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
					  if (pRenderedValues)
					  {
						  EvtRender(hContext, hEvents[i], 0, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);

						  l = pRenderedValues[EvtSystemEventRecordId].Int32Val;
						  if (l>last2) last2 = l;

						  // wprintf(L"%s Event Record Id: %i  last=%i last2=%i\n", pwsPath, l, last, last2);

						  free(pRenderedValues);
					  }
					  else printf("ERROR malloc pRenderedValues\n");
				  }
			  }
			  else {
				  wprintf(L"EvtRender VALUES pRenderedContent dwBufferUsed=%i dwPropertyCount=%i\n", dwBufferUsed, dwPropertyCount);
			  }

			  dwBufferSize = 0;
			  dwBufferUsed = 0;
			  dwPropertyCount = 0;
			  pRenderedContent = NULL;

			  // Render XML
			  // printf("EvtRender XML %i\n", i);
			  if (!EvtRender(NULL, hEvents[i], 1, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
			  {
				  status = GetLastError();
			      // printf("status=%i\n", status);
				  if (status==ERROR_INSUFFICIENT_BUFFER) {

					  dwBufferSize = dwBufferUsed;
					  pRenderedContent = (LPWSTR)malloc(dwBufferSize);
					  if (pRenderedContent)
					  {
						  EvtRender(NULL, hEvents[i], 1, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
						  // wprintf(L"wcslen=%i Rendered=<%s>\n", wcslen(pRenderedContent), pRenderedContent);

						  convertedChars = 0;
						  nameLength = (wcslen(pRenderedContent) + 1)*sizeof(wchar_t);
						  str2 = (char*) malloc(nameLength);
						  err=wcstombs_s(&convertedChars, str2, nameLength, pRenderedContent, _TRUNCATE);
						  // printf("err=%i str2=%p wcs=%i nameLength=%i convertedChars=%i str2=<%s>\n", err, str2, wcslen(pRenderedContent), nameLength, convertedChars, str2);

						  s1 = strstr(str2, "<Data Name='Hashes'>");

						  out = 1;

						  if (s1 != NULL) {

							  s1 += 20;
							  s2 = strstr(s1, "</Data>");

							  len = s2 - s1 + 1;
							  strhashes = malloc(len);
							  strncpy_s(strhashes, len, s1, s2 - s1);
							  strhashes[s2 - s1] = 0;

							  //printf("strhashes=<%s>\n", strhashes);

							  s1 = strhashes;

							  while (1) {

								  s2 = strstr(s1, ",");
								  if (s2 == NULL) {
									  len = strlen(s1) + 1;
									  strhash = malloc(len);
									  strcpy_s(strhash, len, s1);
								  }
								  else {
									  len = s2 - s1 + 1;
									  strhash = malloc(len);
									  strncpy_s(strhash, len, s1, s2 - s1);
									  strhash[s2 - s1] = 0;
								  }

								  len = (int) strlen(strhash);
								  
								  for (k = 0; ((k < (int)strlen(strhash)) && (strhash[k] != '=')); k++);
								  strhash[k++] = 0;

								  if      (strcmp(strhash, "MD5") == 0)     hashtype = SYSMON_HASH_MD5;
								  else if (strcmp(strhash, "SHA1") == 0)    hashtype = SYSMON_HASH_SHA1;
								  else if (strcmp(strhash, "SHA256") == 0)  hashtype = SYSMON_HASH_SHA256;
								  else if (strcmp(strhash, "IMPHASH") == 0) hashtype = SYSMON_HASH_IMPHASH;

								  for (j=0; (k < (int)len); k += 2) {

									  strncpy_s(strbyte, sizeof(strbyte), &strhash[k], 2);
									  strbyte[2] = 0;

									  sscanf_s(strbyte, "%02x", &c);
									  hash[j++] = (char)c;
								  }

								  ret = CheckHash(hashtype, hash);
								  if (ret == 1) out = 0;
								  
								  if (s2 == NULL) break;
								  s1 = s2 + 1;
							  }

							  if (strhashes) free(strhashes);
							  if (strhash) free(strhash);
						  }

						  if (out) {

							  for (j = 0; (j < (int) strlen(str2)); j++) if ((str2[j] == '\r') || (str2[j] == '\n') || (str2[j] == '\t')) str2[j] = ' ';

							  len = strlen(str2) + 3;
							  str = malloc(len);
							  sprintf_s(str, len, "E\t%s", str2);

							  Logs(str);

							  if (str) free(str);
						  }

						  if (str2) free(str2);

						  free(pRenderedContent);
						  pRenderedContent = NULL;
					  }
				  }
			  }
			  else {
				wprintf(L"EvtRender XML pRenderedContent dwBufferUsed=%i dwPropertyCount=%i\n", dwBufferUsed, dwPropertyCount);
			  }

			  if (end) break;
		  }
		}
		else {
			status = GetLastError();
			if (status == ERROR_NO_MORE_ITEMS) end = 1;
		}

		if (hEvents) EvtClose(hEvents);

		if (end) break;
	}

	if (hResults) EvtClose(hResults);
	if (hContext) EvtClose(hContext);
	if (pwsPath) free(pwsPath);

	return last2;
}

/**********************************************************************************/

DWORD WINAPI EventMonitorThread(LPVOID lpParam)
{
	long last, l, i;
	char str[32], writeconf;

	lpParam;

	printf("EventMonitorThread\n");

	while (1) {

		i = 0;
		writeconf = 0;
		while (1) {

			//printf("events i=%i\n", i);

			if (GetParameter("EVENT_LOG_NAME", i) == NULL) break;

			if ((GetParameter("EVENT_LOG_LAST_RECORD_NUMBER", i) == NULL)||
				(strcmp(GetParameter("EVENT_LOG_LAST_RECORD_NUMBER", i), "0") == 0))
				last = 0;
			else {
				//printf("i=%i <%s>\n", i, GetParameter("EVENT_LOG_LAST_RECORD_NUMBER", i));
				last = atoi(GetParameter("EVENT_LOG_LAST_RECORD_NUMBER", i));
			}

			if (last < 0) last = 0;
			
			l = events(GetParameter("EVENT_LOG_NAME", i), last);
			if ((l > 0)&&(last<l)) {
				printf("events <%s> %i %i\n", GetParameter("EVENT_LOG_NAME", i), last, l);
				last = l;
				sprintf_s(str, 32, "%li", l);
				//printf("SetParameter i=%i <%s>\n", i, str);
				SetParameter("EVENT_LOG_LAST_RECORD_NUMBER", i, str);
				writeconf = 1;
			}

			i++;
		}

		if (writeconf == 1) {
			printf("WriteConfiguration EventMonitorThread\n");
			WriteConfiguration();
		}

		if (GetParameter("EVENT_LOG_REFRESH", 0) == NULL) i = 10000;
		else i=atoi(GetParameter("EVENT_LOG_REFRESH", 0));

		Sleep(i);
	}
	
	return 0;
}

/**********************************************************************************/
	
void InitializeEventMonitor(void)
{
	if (hEventMonitorThread != 0) {

	  printf("InitializeEventMonitor TerminateThread %llu\n", (unsigned long long)hEventMonitorThread);

	  TerminateThread(hEventMonitorThread, 0);
	  hEventMonitorThread = 0;
	}

	LogError("InitializeEventMonitor");

	Hashes = NULL;
	LoadHashes();

	hEventMonitorThread = CreateThread(NULL, 0, EventMonitorThread, 0, 0, NULL);
	if (hEventMonitorThread == NULL)
	{
		LogError("ERROR InitializeEventMonitor - CreateThread");
		return;
	}

	//printf("InitializeEventMonitor CreateThread %llu OK\n", (unsigned long long)hEventMonitorThread);
}

/**********************************************************************************/

void LoadHashes(void) {

	FILE *fp;
	DWORD i, length;
	char *buffer=NULL, hash[128], *path=NULL;
	int j, numhashes, white_server_port;
	long size;
	wchar_t *white_server_address=NULL, *white_server_method=NULL, *white_server_resource=NULL;
	DWORD dwFileSize, dwFileType;
	FILETIME CreationTime, LastWriteTime;
	errno_t err;
	size_t n, len;

	if (GetParameter("WHITE_PATH", 0) == NULL) return;
	if (GetParameter("WHITE_SHA256", 0) == NULL) return;
	if (GetParameter("WHITE_SERVER_ADDRESS", 0) == NULL) return;
	if (GetParameter("WHITE_SERVER_PORT", 0) == NULL) return;
	if (GetParameter("WHITE_SERVER_METHOD", 0) == NULL) return;
	if (GetParameter("WHITE_SERVER_RESOURCE", 0) == NULL) return;

	buffer = NULL;

	// Llegeix el SHA256 local

	len = strlen(GetParameter("WHITE_PATH", 0)) + 8;
	path = malloc(len);
	sprintf_s(path, len, "%s.sha256", GetParameter("WHITE_PATH", 0));

	err = fopen_s(&fp, path, "rt");
	if (err==0) {

		fseek(fp, 0L, SEEK_END);
		length = ftell(fp);
		buffer = calloc(length+1, 1);
		fseek(fp, 0L, SEEK_SET);
		fread(buffer, length, 1, fp);
		fclose(fp);

		if (length>=64) buffer[64] = 0;

		// Compara hash local amb el del servidor (variable WHITE_SHA256)

		if (GetParameter("WHITE_SHA256", 0) == NULL) return;
		if (strcmp(buffer, GetParameter("WHITE_SHA256", 0)) == 0) return;

		// Llegeix el SHA256 del servidor

		len = strlen(GetParameter("WHITE_SERVER_ADDRESS", 0)) + 1;
		white_server_address = malloc(len * sizeof(wchar_t));
		mbstowcs_s(&n, white_server_address, len, GetParameter("WHITE_SERVER_ADDRESS", 0), _TRUNCATE);

		white_server_port = atoi(GetParameter("WHITE_SERVER_PORT", 0));

		len = strlen(GetParameter("WHITE_SERVER_METHOD", 0)) + 1;
		white_server_method = malloc(len * sizeof(wchar_t));
		mbstowcs_s(&n, white_server_method, len, GetParameter("WHITE_SERVER_METHOD", 0), _TRUNCATE);

		len = strlen(GetParameter("WHITE_SERVER_RESOURCE", 0)) + 8;
		white_server_resource = malloc(len * sizeof(wchar_t));
		mbstowcs_s(&n, white_server_resource, len, GetParameter("WHITE_SERVER_RESOURCE", 0), _TRUNCATE);
		wcscat_s(white_server_resource, len, L".sha256");
		
		size = 128;
		if (get_https(&size, white_server_address, white_server_port, white_server_method, white_server_resource, hash)) {
			if (white_server_address) free(white_server_address);
			if (white_server_method) free(white_server_method);
			if (white_server_resource) free(white_server_resource);
			if (path) free(path);
			if (buffer) free(buffer);
			return;
		}

		hash[64] = 0;

		// Compara els hashos, si no coincideixen baixar el fitxer de hashos

		if (strcmp(buffer, hash) == 0) {
			if (white_server_address) free(white_server_address);
			if (white_server_method) free(white_server_method);
			if (white_server_resource) free(white_server_resource);
			if (path) free(path);
			if (buffer) free(buffer);
			return;
		}

		if (white_server_address) free(white_server_address);
		if (white_server_method) free(white_server_method);
		if (white_server_resource) free(white_server_resource);
		if (buffer) free(buffer);
		buffer = NULL;
	}

    // Llegir els hashos

	if (GetParameter("WHITE_SERVER_ADDRESS", 0) == NULL) return;

	len =strlen(GetParameter("WHITE_SERVER_ADDRESS", 0)) + 1;
	white_server_address = malloc(len * sizeof(wchar_t));
	mbstowcs_s(&n, white_server_address, len, GetParameter("WHITE_SERVER_ADDRESS", 0), _TRUNCATE);

	if (GetParameter("WHITE_SERVER_PORT", 0) == NULL) return;

	white_server_port = atoi(GetParameter("WHITE_SERVER_PORT", 0));

	if (GetParameter("WHITE_SERVER_METHOD", 0) == NULL) return;

	len = strlen(GetParameter("WHITE_SERVER_METHOD", 0)) + 1;
	white_server_method = malloc(len * sizeof(wchar_t));
	mbstowcs_s(&n, white_server_method, len, GetParameter("WHITE_SERVER_METHOD", 0), _TRUNCATE);

	if (GetParameter("WHITE_SERVER_RESOURCE", 0) == NULL) return;

	len = strlen(GetParameter("WHITE_SERVER_RESOURCE", 0)) + 1;
	white_server_resource = malloc(len * sizeof(wchar_t));
	mbstowcs_s(&n, white_server_resource, len, GetParameter("WHITE_SERVER_RESOURCE", 0), _TRUNCATE);

	if (get_https_to_file(white_server_address, white_server_port, white_server_method, white_server_resource, GetParameter("WHITE_PATH", 0)))
		return;

	// Calcular el SHA256

	calc_hash(CALG_SHA_256, GetParameter("WHITE_PATH", 0), hash, &dwFileSize, &dwFileType, &CreationTime, &LastWriteTime);

	// Escriure el SHA256 en local
	err = fopen_s(&fp, path, "wt");
	if (err==0) {
		fwrite(hash, strlen(hash), 1, fp);
		fclose(fp);
	}

	// Carregar els hashos en memòria

	if (GetParameter("WHITE_PATH", 0) == NULL) return;

	err = fopen_s(&fp, GetParameter("WHITE_PATH", 0), "rb");
	if (err != 0) return;
	fseek(fp, 0L, SEEK_END);
	length = ftell(fp);

	buffer = calloc(length, 1);

	fseek(fp, 0L, SEEK_SET);
	fread(buffer, length, 1, fp);
	fclose(fp);

	i = 0;
	numhashes = 0;
	while (i<length) {

		if (buffer[i] == SYSMON_HASH_SHA256) {
			i++;
			for (j = 0; (j < 32); j++) hash[j] = buffer[i++];
			AddHash(SYSMON_HASH_SHA256, hash);
			numhashes++;
		}
		else break;
	}

	printf("numhashes=%i\n", numhashes);

	if (white_server_address) free(white_server_address);
	if (white_server_method) free(white_server_method);
	if (white_server_resource) free(white_server_resource);
	if (path) free(path);
	if (buffer) free(buffer);
}

/**********************************************************************************/

void AddHash(char hashtype, char *hash) {

	hash_t *p;
	hash_lookup_key_t lookup_key;
	unsigned keylen, hashlen;

	if      (hashtype == SYSMON_HASH_MD5)    hashlen = 16;
	else if (hashtype == SYSMON_HASH_SHA1)   hashlen = 20;
	else if (hashtype == SYSMON_HASH_SHA256) hashlen = 32;
	else return;

	memset(&lookup_key.hash, 0, sizeof(lookup_key.hash));
	strncpy_s(lookup_key.hash, 32, hash, hashlen);
	lookup_key.hashtype = hashtype;

	keylen = offsetof(hash_t, hash)		/* offset of last key field */
		+ sizeof(p->hashtype)			/* size of last key field */
		- offsetof(hash_t, hashtype);	/* offset of first key field */

	HASH_FIND(hh, Hashes, &lookup_key, keylen, p);

	// printf("<%s> p=%p\n", key, p);

	if (p) return;
	
	// El parametre no existeix

	p = malloc(sizeof(hash_t));
	memset(p, 0, sizeof(hash_t));

	memset(p->hash, 0, sizeof(p->hash));
	strncpy_s(p->hash, 32, hash, hashlen);
	p->hashtype = hashtype;

	HASH_ADD(hh, Hashes, hash, keylen, p);

	return;
}

/**********************************************************************************/

char CheckHash(char hashtype, char *hash) {

	hash_t *p;
	hash_lookup_key_t lookup_key;
	unsigned keylen, hashlen;

	if      (hashtype == SYSMON_HASH_MD5)    hashlen = 16;
	else if (hashtype == SYSMON_HASH_SHA1)   hashlen = 20;
	else if (hashtype == SYSMON_HASH_SHA256) hashlen = 32;
	else return 0;

	keylen = offsetof(hash_t, hash)		/* offset of last key field */
		+ sizeof(p->hashtype)			/* size of last key field */
		- offsetof(hash_t, hashtype);	/* offset of first key field */

	memset(&lookup_key.hash, 0, sizeof(lookup_key.hash));
	memcpy_s(lookup_key.hash, 32, hash, hashlen);
	lookup_key.hashtype = hashtype;

	HASH_FIND(hh, Hashes, &lookup_key.hash, keylen, p);

	if (p != NULL) printf("CheckHash 1\n");

	if (p == NULL) return 0;
	else return 1;
}

/**********************************************************************************/
