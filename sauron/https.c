#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "https.h"

extern wchar_t *log_server_address;
extern int log_server_port;
extern wchar_t *log_server_method;
extern wchar_t *log_server_resource;

#define BUFFERSIZE 2048

/**********************************************************************************/

DWORD get_https(long *size, wchar_t *address, int port, wchar_t *method, wchar_t *resource, char *data)
{
	DWORD dwSize = 0, total, dwStatusCode = 0, dwDownloaded = 0;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;
	DWORD dwFlags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
					SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
					SECURITY_FLAG_IGNORE_UNKNOWN_CA;
	DWORD ret;
	char *pdata;

	wprintf(L"get_https address=\"%s\" port=%i method=\"%s\" resource=\"%s\"\n", address, (INTERNET_PORT)port, method, resource);

	hSession = WinHttpOpen(L"Sauron",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession) hConnect = WinHttpConnect(hSession, address, (INTERNET_PORT)port, 0);

	if (hConnect) {

		hRequest = WinHttpOpenRequest(hConnect, method, resource,
			NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE);

		bResults = WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(DWORD));

		if (hRequest) {

			// printf("WinHttpSendRequest %i\n", *size);
			bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, (DWORD_PTR)0);
			if (!bResults) {
				ret = GetLastError();
				printf("send_https - WinHttpSendRequest: Error %d\n", ret);
				if (hRequest) WinHttpCloseHandle(hRequest);
				if (hConnect) WinHttpCloseHandle(hConnect);
				if (hSession) WinHttpCloseHandle(hSession);
				return ret;
			}
		}
		else
			printf("ERROR WinHttpOpenRequest GetLastError=%d\n", GetLastError());

		if (!WinHttpReceiveResponse(hRequest, NULL))
		{
			printf("send_https - WinHttpReceiveResponse\n");
			return 4;
		}
		else {
			
			dwSize = sizeof(dwStatusCode);
			dwStatusCode = 0;

			WinHttpQueryHeaders(hRequest,
				WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				WINHTTP_HEADER_NAME_BY_INDEX,
				&dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

			if (dwStatusCode != 200) {
				if (hRequest) WinHttpCloseHandle(hRequest);
				if (hConnect) WinHttpCloseHandle(hConnect);
				if (hSession) WinHttpCloseHandle(hSession);
				return 1;
			}

			//printf("size=%i\n", *size);

			ZeroMemory(data, *size);
			*size = 0;

			total = 0;
			pdata = data;
			do {
				dwSize = 0;
				if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
					printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
					if (hRequest) WinHttpCloseHandle(hRequest);
					if (hConnect) WinHttpCloseHandle(hConnect);
					if (hSession) WinHttpCloseHandle(hSession);
					return 1;
				}

				//printf("WinHttpQueryDataAvailable dwSize=%i\n", dwSize);

				if (dwSize == 0) break;

				if (!WinHttpReadData(hRequest, (LPVOID)pdata, dwSize, &dwDownloaded)) {
					printf("Error %u in WinHttpReadData.\n", GetLastError());
					if (hRequest) WinHttpCloseHandle(hRequest);
					if (hConnect) WinHttpCloseHandle(hConnect);
					if (hSession) WinHttpCloseHandle(hSession);
					return 1;
				}

				//printf("dwSize=%i dwDownloaded=%i\n", dwSize, dwDownloaded);

				if ((long)(total + dwDownloaded) > *size) dwDownloaded = *size - total;

				pdata += dwDownloaded;
				total += dwDownloaded;

			} while (dwSize > 0);

			*size = total;
		}

		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
	}

	return 0;
}

/**********************************************************************************/

DWORD get_https_to_file(wchar_t *address, int port, wchar_t *method, wchar_t *resource, char *filename)
{
	DWORD dwSize = 0, dwStatusCode=0;
	//DWORD dwDownloaded = 0;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;
	DWORD dwFlags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
		SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
		SECURITY_FLAG_IGNORE_UNKNOWN_CA;
	DWORD ret;

	wprintf(L"get_https_to_file address=\"%s\" port=%i method=\"%s\" resource=\"%s\"\n", address, port, method, resource);

	hSession = WinHttpOpen(L"Sauron",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession) hConnect = WinHttpConnect(hSession, address, (INTERNET_PORT)port, 0);

	if (hConnect) {

		hRequest = WinHttpOpenRequest(hConnect, method, resource,
			NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE);

		bResults = WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(DWORD));

		if (hRequest) {

			// printf("WinHttpSendRequest %i\n", *size);
			bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, (DWORD_PTR)0);
			if (!bResults) {
				ret = GetLastError();
				printf("send_https - WinHttpSendRequest: Error %d\n", ret);
				if (hRequest) WinHttpCloseHandle(hRequest);
				if (hConnect) WinHttpCloseHandle(hConnect);
				if (hSession) WinHttpCloseHandle(hSession);
				return ret;
			}
		}
		else
			printf("send_https - WinHttpOpenRequest GetLastError=%d\n", GetLastError());

		if (!WinHttpReceiveResponse(hRequest, NULL))
		{
			printf("send_https - WinHttpReceiveResponse\n");
			return 4;
		}
		else {

			dwSize = sizeof(dwStatusCode);
			dwStatusCode = 0;

			WinHttpQueryHeaders(hRequest,
				WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				WINHTTP_HEADER_NAME_BY_INDEX,
				&dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

			if (dwStatusCode != 200) {
				if (hRequest) WinHttpCloseHandle(hRequest);
				if (hConnect) WinHttpCloseHandle(hConnect);
				if (hSession) WinHttpCloseHandle(hSession);
				return 1;
			}

			printf("Es crea <%s>\n", filename);

			HANDLE hTempFile = CreateFileA(
				filename, 
				GENERIC_WRITE, 
				0, 
				NULL, 
				CREATE_ALWAYS, 
				FILE_ATTRIBUTE_TEMPORARY, 
				NULL);
			if (hTempFile == INVALID_HANDLE_VALUE)
			{
				printf("send_https - Unable to open temporary file\n");
				return 5;
			}

			char pBuffer[BUFFERSIZE];
			DWORD dwAvailable = 0;
			while (WinHttpQueryDataAvailable(hRequest, &dwAvailable) && dwAvailable)
			{
				if (dwAvailable > BUFFERSIZE) dwAvailable = BUFFERSIZE;

				DWORD dwRead = 0;
				if (!WinHttpReadData(hRequest, pBuffer, dwAvailable, &dwRead))
				{
					printf("send_https - WinHttpReadData\n");
					return 6;
				}

				DWORD dwWritten = 0;
				WriteFile(hTempFile, pBuffer, dwRead, &dwWritten, NULL);
				if (dwWritten != dwRead)
				{
					printf("send_https - Error while writing to temporary file");
					return 5;
				}
			}

			CloseHandle(hTempFile);
		}

		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
	}

	return 0;
}

/**********************************************************************************/

char* send_https(char *params, DWORD *size, char *data) {

	DWORD dwSize = 0, t0, t1;
	DWORD dwDownloaded = 0;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;
	DWORD dwFlags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
		SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
		SECURITY_FLAG_IGNORE_UNKNOWN_CA;
	DWORD ret;
	wchar_t *wparams=NULL, *log_server_resource2=NULL;
	size_t n, len;
	char *dataout;

	//printf("send_https size=%i\n", *size);

	LPCWSTR additionalHeaders = L"Content-Type: text/plain\r\n";

	hSession = WinHttpOpen(L"Sauron",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (hSession == NULL) {
		printf("ERROR WinHttpOpen %i\n", GetLastError());
		return NULL;
	}

	// wprintf(L"log_server_address=<%s> log_server_port=%i\n", log_server_address, log_server_port);

	//if (!WinHttpSetTimeouts(hSession, 500, 500, 1000, 5000))
	//	printf("Error send_https WinHttpSetTimeouts %u.\n", GetLastError());

	hConnect = WinHttpConnect(hSession, log_server_address, (INTERNET_PORT)log_server_port, 0);
	if (hConnect == NULL) {
		printf("ERROR WinHttpConnect %i\n", GetLastError());
		if (hSession) WinHttpCloseHandle(hSession);
		return NULL;
	}

	len = strlen(params) + 1;
	wparams = (wchar_t*) malloc(len*sizeof(wchar_t));
	n = 0;
	mbstowcs_s(&n, wparams, len, params, _TRUNCATE);

	wprintf(L"send_https %s address=\"%s\" port=%i method=\"%s\" resource=\"%s\"\n", wparams, log_server_address, log_server_port, log_server_method, log_server_resource);

	len = wcslen(log_server_resource) + wcslen(wparams) + 2;
	log_server_resource2 = malloc(sizeof(wchar_t) * len);
	swprintf_s(log_server_resource2, len, L"%s%s", log_server_resource, wparams);

    //wprintf(L"log_server_method=<%s> log_server_resource=<%s> log_server_resource2=<%s>\n", log_server_method, log_server_resource, log_server_resource2);

	hRequest = WinHttpOpenRequest(hConnect, log_server_method, log_server_resource2,
			NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE);
	if (hRequest == NULL) {
		printf("ERROR WinHttpOpenRequest %i\n", GetLastError());
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
		return NULL;
	}

	bResults = WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(DWORD));
	if (!bResults) {
		printf("ERROR WinHttpSetOption %i\n", GetLastError());
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
		return NULL;
	}

	//printf("send_https %i\n", *size);

	t0=GetTickCount();
	bResults = WinHttpSendRequest(hRequest, additionalHeaders, (DWORD)-1L, (LPVOID)data, *size, *size, 0);
	t1 = GetTickCount();
	//printf("WinHttpSendRequest bResults=%i %i elapsed\n", bResults, t1 - t0);  // ms
	if (!bResults) {
		ret = GetLastError();
		printf("send_https - WinHttpSendRequest: Error %d\n", ret);
		if (log_server_resource2) free(log_server_resource2);
		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
		return NULL;
	}

	t0 = GetTickCount();
	bResults = WinHttpReceiveResponse(hRequest, NULL);
	t1 = GetTickCount();
	//printf("WinHttpReceiveResponse bResults=%i %i elapsed\n", bResults, t1 - t0);  // ms
	if (!bResults) {
		ret = GetLastError();
		printf("send_https - WinHttpReceiveResponse: Error %d\n", ret);
		if (log_server_resource2) free(log_server_resource2);
		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
		return NULL;
	}

	//ZeroMemory(data, *size);

	dwSize = 0;
	if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
	  printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
	  if (hRequest) WinHttpCloseHandle(hRequest);
	  if (hConnect) WinHttpCloseHandle(hConnect);
	  if (hSession) WinHttpCloseHandle(hSession);
	  return NULL;
	}

	dataout = calloc(dwSize, 1);
	if (dataout == NULL) {
		printf("ERROR send_https malloc\n");
		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
		return NULL;
	}

	if (!WinHttpReadData(hRequest, (LPVOID)dataout, dwSize, &dwDownloaded))
	  printf("Error %u in WinHttpReadData.\n", GetLastError());

	//printf("dwSize=%i dwDownloaded=%i\n", dwSize, dwDownloaded);

	*size = dwDownloaded;

	if (wparams) free(wparams);

	if (log_server_resource2) free(log_server_resource2);

	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return dataout;
}

/**********************************************************************************/
