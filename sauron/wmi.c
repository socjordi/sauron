#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <tchar.h>
#include <windows.h>
#include <wbemidl.h>
#include <inttypes.h>

#include "log.h"
#include "param.h"

HANDLE hWMIThread = 0;

extern SECURITY_ATTRIBUTES *psystem_sa;

/*
CIM_ILLEGAL = 4095, // 0xFFF
CIM_EMPTY = 0,    // 0x0
CIM_SINT8 = 16,   // 0x10
CIM_UINT8 = 17,   // 0x11
CIM_SINT16 = 2,    // 0x2
CIM_UINT16 = 18,   // 0x12
CIM_SINT32 = 3,    // 0x3
CIM_UINT32 = 19,   // 0x13
CIM_SINT64 = 20,   // 0x14
CIM_UINT64 = 21,   // 0x15
CIM_REAL32 = 4,    // 0x4
CIM_REAL64 = 5,    // 0x5
CIM_BOOLEAN = 11,   // 0xB
CIM_STRING = 8,    // 0x8
CIM_DATETIME = 101,  // 0x65
CIM_REFERENCE = 102,  // 0x66
CIM_CHAR16 = 103,  // 0x67
CIM_OBJECT = 13,   // 0xD
CIM_FLAG_ARRAY = 8192 // 0x2000
*/

/*
CHAR cVal;			1 byte= 8 bits
BYTE bVal;

SHORT iVal;			2 bytes=16 bits
USHORT uiVal;

INT intVal;			2 bytes=16 bits
UINT uintVal;

LONG lVal;			4 bytes=32 bits
ULONG ulVal;

LONGLONG llVal;		8 bytes=64 bits
ULONGLONG ullVal;

FLOAT fltVal;		4 bytes=32 bits

DOUBLE dblVal;		8 bytes=64 bits
*/

/*
LONGLONG llVal;
LONG lVal;
BYTE bVal;
SHORT iVal;
FLOAT fltVal;
DOUBLE dblVal;
VARIANT_BOOL boolVal;
_VARIANT_BOOL bool;
SCODE scode;
CY cyVal;
DATE date;
BSTR bstrVal;
IUnknown *punkVal;
IDispatch *pdispVal;
SAFEARRAY *parray;
BYTE *pbVal;
SHORT *piVal;
LONG *plVal;
LONGLONG *pllVal;
FLOAT *pfltVal;
DOUBLE *pdblVal;
VARIANT_BOOL *pboolVal;
_VARIANT_BOOL *pbool;
SCODE *pscode;
CY *pcyVal;
DATE *pdate;
BSTR *pbstrVal;
IUnknown **ppunkVal;
IDispatch **ppdispVal;
SAFEARRAY **pparray;
VARIANT *pvarVal;
PVOID byref;
CHAR cVal;
USHORT uiVal;
ULONG ulVal;
ULONGLONG ullVal;
INT intVal;
UINT uintVal;
DECIMAL *pdecVal;
CHAR *pcVal;
USHORT *puiVal;
ULONG *pulVal;
ULONGLONG *pullVal;
INT *pintVal;
UINT *puintVal;
*/

/**********************************************************************************/

/*
BSTR str2bstr(LPCSTR lpStr)
{
	//get the length of the string
	//the length excludes a null terminator
	UINT iLen = strlen(lpStr);
	//get the length of the string including a null terminator
	iLen++;
	LPWSTR wstr = (LPWSTR)malloc(sizeof(wchar_t)*iLen);
	wstr[0] = NULL;
	MultiByteToWideChar(CP_ACP, 0, lpStr, -1, wstr, iLen);
	BSTR bstr = SysAllocString(wstr);
	free(wstr);
	return bstr;
	//remember to SysFreeString the BSTR in the caller function.
}
*/

BSTR str2bstr(const char *str) {

	int wslen = MultiByteToWideChar(CP_ACP, 0, str, (int)strlen(str), 0, 0);
	BSTR bstr = SysAllocStringLen(0, wslen);
	MultiByteToWideChar(CP_ACP, 0, str, (int)strlen(str), bstr, wslen);
	// Use bstr here
	//SysFreeString(bstr);
	return bstr;
}

/**********************************************************************************/

void PrintVariant(VARIANT value, int size, WCHAR *str) {

	/*
	if ((int)type == CIM_STRING) {			// OK
		if (SUCCEEDED(hr) && (V_VT(&value) == VT_BSTR)) {
			//WideCharToMultiByte(CP_ACP, 0, V_VT(&value), -1, str, 256, NULL, NULL);
			wprintf(L"%s\n", V_BSTR(&value));
		}
	}
	else if ((int)type == CIM_SINT8)
		wprintf_s(L"%hhi\n", value.cVal);
	else if ((int)type == CIM_UINT8)
		wprintf_s(L"%hhu\n", value.bVal);
	else if ((int)type == CIM_SINT16)
		wprintf_s(L"%hi\n", value.iVal);
	else if ((int)type == CIM_UINT16)		// OK 18
		wprintf_s(L"%hu\n", value.uiVal);
	else if ((int)type == CIM_SINT32)
		wprintf_s(L"%I32i\n", value.lVal);
	else if ((int)type == CIM_UINT32)		// OK 19
		wprintf_s(L"%I32u\n", value.ulVal);
	else if ((int)type == CIM_SINT64)
		wprintf_s(L"%s\n", value.llVal);
	else if ((int)type == CIM_UINT64)		// OK 21
		wprintf_s(L"%s\n", value.ullVal);
	else if ((int)type == CIM_REAL32)
		wprintf_s(L"%f\n", value.fltVal);
	else if ((int)type == CIM_REAL64)
		wprintf_s(L"%lf\n", value.dblVal);
	else if ((int)type == CIM_BOOLEAN)		// OK 11
		wprintf_s(L"%hhi\n", value.bVal);
	else if ((int)type == CIM_DATETIME)		// OK 101
		wprintf_s(L"%s\n", value.date);
	else
		printf("type=%i %s\n", type);

	*/
	
	switch (V_VT(&value)) {
	case VT_NULL:	wsprintf(str, L""); break;
	case VT_I1:		wsprintf(str, L"%hi", value.cVal); break;
	case VT_UI1:	wsprintf(str, L"%hu", value.cVal); break;
	case VT_I2:		wsprintf(str, L"%hi", value.iVal); break;
	case VT_UI2:	wsprintf(str, L"%hu", value.uiVal); break;
	case VT_I4:		wsprintf(str, L"%I32u", value.lVal); break;
	case VT_UI4:	wsprintf(str, L"%I32u", value.ulVal); break;
	case VT_I8:		wsprintf(str, L"%s", value.llVal); break;
	case VT_UI8:	wsprintf(str, L"%s", value.ullVal); break;
	case VT_R4:		wsprintf(str, L"%f", value.fltVal); break;
	case VT_R8:		wsprintf(str, L"%lf", value.dblVal); break;
	case VT_DATE:	wsprintf(str, L"%s", value.date); break;
	case VT_BOOL:	wsprintf(str, L"%hi", value.bVal); break;
	case VT_BSTR:	{
		if (wcslen(V_BSTR(&value)) < (size_t)size) wsprintf(str, L"%s", V_BSTR(&value));
		else wsprintf(str, L"");
		break;
	}
	default:		wsprintf(str, L"???"); break;
	}
}

/**********************************************************************************/

void wmi(char *resource, char *str, char *where)
{
	HRESULT hr = 0;
	IWbemLocator         *locator = NULL;
	IWbemServices        *services = NULL;
	IEnumWbemClassObject *results = NULL;
	IWbemClassObject     *result = NULL;
	//IWbemClassObject	 *wmi_class = NULL;
	CIMTYPE type;
	ULONG returnedCount = 0;
	SAFEARRAY *psaNames = NULL;
	long lLower, lUpper, lLower2, lUpper2;
	WCHAR svalue[2048], wstr[1024];
	size_t num, wnum;
	char outbuf[1024];
	char path[1024], path2[1024], str2[1024];
	FILE *fp;
	HANDLE hFile;
	BSTR wresource, wlanguage, wstr2;

	if (GetParameter("LOG_FOLDER", 0) == NULL) return;

	//printf("wmi ");
	//if (resource != NULL) printf(" resource=\"%s\"", resource);
	//printf(" \"%s\"", str);
	//if (where != NULL) printf(" where=\"%s\"", where);
	//printf("\n");

	//sprintf(outbuf, "wmi <%s>", str);
	//printf("%s\n", str);
	//LogError(outbuf);

	sprintf_s(path, sizeof(path), "%s\\%s.par", GetParameter("LOG_FOLDER", 0), str);
	strcpy_s(path2, sizeof(path2), path);
	strcat_s(path2, sizeof(path2), ".tmp");

	hFile = CreateFileA(path2,
		GENERIC_READ | GENERIC_WRITE,       // open for writing
		0,                                  // do not share
		psystem_sa,                         // default security (NULL per defecte)
		CREATE_ALWAYS,                      // create new file only 
		FILE_ATTRIBUTE_NORMAL,              // normal file
		NULL);
	CloseHandle(hFile);

	if (fopen_s(&fp, path2, "w")!=0) {
		sprintf_s(outbuf, 1024, "wmi Error fopen %i\n", errno);
		LogError(outbuf);
		return;
	}

	// BSTR strings we'll use (http://msdn.microsoft.com/en-us/library/ms221069.aspx)

	if (resource == NULL)
		wresource = SysAllocString(L"ROOT\\CIMV2");
	else {
		wnum = 0;
		mbstowcs_s((size_t *)&wnum, wstr, 1024, resource, 1024);
		wresource = SysAllocString(wstr);
	}

	wlanguage = SysAllocString(L"WQL");

	sprintf_s(str2, sizeof(str2), "SELECT * FROM %s", str);

	if (where!=NULL) {
		strcat_s(str2, 1024, " ");
		strcat_s(str2, 1024, where);
		//if (strcmp(str, "Win32_UserAccount") == 0) strcat_s(str2, 128, " WHERE LocalAccount = True");
		//if (strcmp(str, "Win32_Group") == 0) strcat_s(str2, 128, " WHERE LocalAccount = True");
	}

	wstr2 = str2bstr(str2);
	BSTR query = SysAllocString(wstr2);

	wnum = 0;
	mbstowcs_s((size_t *)&wnum, wstr, 1024, str, 1024);

	hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);


	hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *)&locator);
	hr = locator->lpVtbl->ConnectServer(locator, wresource, NULL, NULL, NULL, 0, NULL, NULL, &services);


	IWbemClassObject* pClass = NULL;
	hr = services->lpVtbl->GetObjectW(services, wstr, 0, NULL, &pClass, NULL);

	if (pClass == NULL) {

		printf("ERROR wmi - IWbemServices GetObjectW\n");

		services->lpVtbl->Release(services);
		locator->lpVtbl->Release(locator);

		CoUninitialize();

		return;
	}

	hr = pClass->lpVtbl->GetNames(pClass, NULL, WBEM_FLAG_ALWAYS | WBEM_FLAG_NONSYSTEM_ONLY, NULL, &psaNames);
	
	SafeArrayGetLBound(psaNames, 1, &lLower);
	SafeArrayGetUBound(psaNames, 1, &lUpper);

	hr = services->lpVtbl->ExecQuery(services, wlanguage, query, WBEM_FLAG_BIDIRECTIONAL, NULL, &results);
	if (results != NULL) {

		num = 0;
		while ((hr = results->lpVtbl->Next(results, WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) {

			for (LONG i = lLower; (i < lUpper); i++) {

				VARIANT value;
				BSTR name;

				hr = SafeArrayGetElement(psaNames, &i, &name);
				hr = result->lpVtbl->Get(result, name, 0, &value, &type, 0);

				if (V_VT(&value) == 1) {
			      SysFreeString(name);
				  VariantClear(&value);
				  continue;
				}

				//wprintf_s(L"\tname=<%s>\ttype=%i %i\t", name, type, V_VT(&value));

				if (type == 8200) { // Array
					
					SAFEARRAY* pSafeArray = NULL;
					pSafeArray = V_ARRAY(&value);

					SafeArrayGetLBound(pSafeArray, 1, &lLower2);
					SafeArrayGetUBound(pSafeArray, 1, &lUpper2);

					for (LONG i2 = lLower2; (i2 <= lUpper2); i2++)
					{
						BSTR svalue2;

						SafeArrayGetElement(pSafeArray, &i2, (void*)&svalue2);
						fwprintf(fp, L"%i\t%s\t%s\n", (int)num, name, svalue2);
						SysFreeString(svalue2);
					}
				}
				else {
					
					PrintVariant(value, 2048, svalue);
					fwprintf(fp, L"%i\t%s\t%s\n", (int)num, name, svalue);
					
				}

				SysFreeString(name);
				VariantClear(&value);
			}

			result->lpVtbl->Release(result);
			num++;
		}

		results->lpVtbl->Release(results);
	}

	SafeArrayDestroy(psaNames);

	pClass->lpVtbl->Release(pClass);

	services->lpVtbl->Release(services);
	locator->lpVtbl->Release(locator);

	CoUninitialize();

	SysFreeString(query);

	SysFreeString(wstr2);
	SysFreeString(wlanguage);
	SysFreeString(wresource);

	if (fclose(fp) != 0) printf("ERROR fclose <%s>\n", path2);

	DeleteFileA(path);	

	//printf("rename <%s> <%s>\n", path2, path);
	rename(path2, path);

	//sprintf_s(outbuf, sizeof(outbuf), "wmi <%s> (END)", str);
	//LogError(outbuf);
}

/**********************************************************************************/

DWORD WINAPI WMIThread(LPVOID lpParam) {

	DWORD i, last, timeseconds, refresh;
	FILETIME filetime;
	ULONGLONG time;
	char str[128];

	lpParam;

	while (1) {

		i = 0;
		while (1) {

			if (GetParameter("WMI_NAME", i) == NULL) break;

			if (GetParameter("WMI_LAST_TIME", i) == NULL) last = 0;
			else last = atoi(GetParameter("WMI_LAST_TIME", i));

			if (GetParameter("WMI_REFRESH", i) == NULL) refresh = 3600;
			else refresh = atoi(GetParameter("WMI_REFRESH", i));

			GetSystemTimeAsFileTime(&filetime);
			time = (((ULONGLONG)filetime.dwHighDateTime) << 32) + filetime.dwLowDateTime;
			timeseconds = (DWORD)(time / 10000000L);

			if (timeseconds > last + refresh) {

				// GetParameter("WMI_LOG", i); // D=disable L=LocalFile S=Server

				if ((GetParameter("WMI_RESOURCE", i) != NULL) && (GetParameter("WMI_NAME", i) != NULL) && (GetParameter("WMI_WHERE", i) != NULL)) {

				  wmi(GetParameter("WMI_RESOURCE", i), GetParameter("WMI_NAME", i), GetParameter("WMI_WHERE", i));
				  sprintf_s(str, sizeof(str), "%li", timeseconds);
				  SetParameter("WMI_LAST_TIME", i, str);
				  printf("SetParameter %s\n", str);
				  printf("WriteConfiguration WMIThread\n");
				  WriteConfiguration();
				  SendConfiguration();
				}
			}

			i++;
		}

		Sleep(1000);
	}

	return 0;
}

/**********************************************************************************/

void InitializeWMI(void){

	if (hWMIThread != 0) {

		printf("InitializeWMI TerminateThread %llu\n", (unsigned long long)hWMIThread);

		TerminateThread(hWMIThread, 0);
		hWMIThread = 0;
	}

	LogError("InitializeWMI");

	hWMIThread = CreateThread(NULL, 0, WMIThread, 0, 0, NULL);
	if (hWMIThread == NULL)
	{
		LogError("ERROR InitializeWMI - CreateThread");
		return;
	}

	printf("InitializeWMI CreateThread %llu OK\n", (unsigned long long)hWMIThread);
}

/**********************************************************************************/
