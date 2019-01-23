#include <windows.h>
#include <conio.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>

#include "Param.h"
#include "https.h"
#include "hash.h"

wchar_t *log_server_address;
int log_server_port;
wchar_t *log_server_method;
wchar_t *log_server_resource;

/**********************************************************************************/

void Logs(char *data) {

	char strlog[1024], strtime[32];
	SYSTEMTIME st;
	FILE *fp;

	if (GetParameter("SOFTWARE_PATH", 0) == NULL) return;

	sprintf_s(strlog, 1024, "%s\\watch.log", GetParameter("SOFTWARE_PATH", 0));

	GetSystemTime(&st);
	sprintf_s(strtime, 32, "%04d%02d%02dT%02d%02d%02d.%03d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

	if (fopen_s(&fp, strlog, "a")==0) {

		printf("%s\t%s\n", strtime, data);
		fprintf(fp, "%s\t%s\n", strtime, data);
		fclose(fp);
	}
}

/**********************************************************************************/

int process(char *filename, long size, char *hash) {

	int download;
	char path[1024], chash[128], str[1024];
	DWORD dwFileSize, dwFileType;
	FILETIME CreationTime, LastWriteTime;
	char resource[256];
	wchar_t wresource[256];
	size_t wnum;

	if (GetParameter("SOFTWARE_PATH", 0) == NULL) return 0;
	if (GetParameter("UPDATE_SERVER_RESOURCE", 0) == NULL) return 0;

	printf("process <%s> size=%i hash=<%s>\n", filename, size, hash);

	sprintf_s(path, 1024, "%s\\%s", GetParameter("SOFTWARE_PATH", 0), filename);
	//printf("path=<%s>\n", path);

	download = 0;

	// Si no el tenim baixat, baixar-lo
	if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
		//printf("El fitxer <%s> no existeix.\n", path);
		download = 1;
	}
	else {

		// printf("size=%i csize=%i\n", size, csize);

		// Si el tenim i el hash es diferent, baixar-lo
		calc_hash(CALG_SHA_256, path, chash, &dwFileSize, &dwFileType, &CreationTime, &LastWriteTime);
		if (strcmp(hash, chash) != 0) {
			//printf("Els hashos <%s> i <%s> no coincideixen.\n", hash, chash);
			download = 1;
		}
	}

	if (download) {
		// Baixar el fitxer
		sprintf_s(resource, 128, "%sfiles/%s", GetParameter("UPDATE_SERVER_RESOURCE", 0), filename);
		mbstowcs_s(&wnum, wresource, 256, resource, 256);
		get_https_to_file(log_server_address, log_server_port, log_server_method, wresource, path);

		sprintf_s(str, 1024, "Actualitzat %s (mida=%i, hash=%s)", filename, size, hash);
		Logs(str);
	}

	return download;
}

/**********************************************************************************/

int main(int argc, char *argv[])
{
	int i, iname, isize, ihash;
	long size;
	char buffer[1024], ServiceName[32];
	SERVICE_STATUS ServiceStatus;
	SC_HANDLE schSCManager, schService;
	DWORD error;
	size_t n, n2, len;

	InitializeParameters();

	ReadConfiguration();

	/*
	printf("LOG_SERVER_ADDRESS=<%s>\n", GetParameter("LOG_SERVER_ADDRESS", 0));
	printf("UPDATE_SERVER_ADDRESS=<%s>\n", GetParameter("UPDATE_SERVER_ADDRESS", 0));

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
	*/

	schSCManager = OpenSCManager(
		NULL,                    // local machine
		NULL,                    // SERVICES_ACTIVE_DATABASE database is opened by default
		SC_MANAGER_ALL_ACCESS);  // full access rights
	if (schSCManager == NULL) {
		error = GetLastError();
		if (error != ERROR_SHUTDOWN_IN_PROGRESS) {
			sprintf_s(buffer, 1024, "OpenSCManager() failed - error: %d", error);
			Logs(buffer);
		}

		exit(1);
    } 

	sprintf_s(ServiceName, 32, "Sauron");
	schService = OpenServiceA(schSCManager, ServiceName, SERVICE_ALL_ACCESS);
	if (schService == NULL) {
      sprintf_s(buffer, 1024, "OpenService() failed - error: %d", GetLastError());
	  Logs(buffer);
	  exit(1);
	}

	/* Bucle infinit: comprova cada segon que el servei Sauron estigui en execució */

	while (1) {

		if (!QueryServiceStatus(schService, &ServiceStatus)) {
		  sprintf_s(buffer, 1024, "OpenSCManager() failed - error: %d", GetLastError());
          Logs(buffer);
		  Sleep(1000); // 1000 ms
		  continue;
	    }

		/* Si el servei Sauron està en execució, esperem 1 segon i repetim la comprovació */
		if (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
		  Sleep(1000); // 1000 ms
		  continue;
		}

		/* Si el servei no està en execució, l'aturem */
		ControlService(schService, SERVICE_CONTROL_STOP, &ServiceStatus);
		 
		/* Bucle infinit fins que el servei estigui aturat */
		while (1) {
			
			Sleep(100); // 100 ms

			if (!QueryServiceStatus(schService, &ServiceStatus)) {
				sprintf_s(buffer, 1024, "OpenSCManager() failed - error: %d", GetLastError());
				Logs(buffer);
				Sleep(1000); // 1000 ms
				continue;
			}

			printf("Status=%i\n", ServiceStatus.dwCurrentState);

			if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) break;
		}

		/* Llegir variables UPDATE_SERVER_ADDRESS, UPDATE_SERVER_PORT i UPDATE_SERVER_RESOURCE */

		printf("ReadConfiguration\n");
		ReadConfiguration();

		if (GetParameter("UPDATE_SERVER_ADDRESS", 0)==NULL) {
			Sleep(1000);  // 1000 ms
			continue;
		}

		len = strlen(GetParameter("UPDATE_SERVER_ADDRESS", 0)) + 1;
		log_server_address = malloc(len * sizeof(wchar_t));
		mbstowcs_s(&n2, log_server_address, len, GetParameter("UPDATE_SERVER_ADDRESS", 0), _TRUNCATE);

		if (GetParameter("UPDATE_SERVER_PORT", 0) == NULL) {
			Sleep(1000);  // 1000 ms
			continue;
		}

		log_server_port = atoi(GetParameter("UPDATE_SERVER_PORT", 0));

		if (GetParameter("UPDATE_SERVER_METHOD", 0) == NULL) {
			Sleep(1000);  // 1000 ms
			continue;
		}

		len = strlen(GetParameter("UPDATE_SERVER_METHOD", 0)) + 1;
		log_server_method = malloc(len * sizeof(wchar_t));
		mbstowcs_s(&n2, log_server_method, len, GetParameter("UPDATE_SERVER_METHOD", 0), _TRUNCATE);

		if (GetParameter("UPDATE_SERVER_RESOURCE", 0) == NULL) {
			Sleep(1000);  // 1000 ms
			continue;
		}

		len = strlen(GetParameter("UPDATE_SERVER_RESOURCE", 0)) + 1;
		log_server_resource = malloc(len * sizeof(wchar_t));
		mbstowcs_s(&n2, log_server_resource, len, GetParameter("UPDATE_SERVER_RESOURCE", 0), _TRUNCATE);

		// Si el proces Sauron s'esta executant, fer Sleep(1000) i continue

		// Baixar-se el fitxer /sauron/files/ (conté la llista de fitxers)

		//wprintf(L"log_server_address=<%s>\n", log_server_address);
		//wprintf(L"log_server_method=<%s>\n", log_server_method);
		//wprintf(L"log_server_resource=<%s>\n", log_server_resource);

		wprintf(L"%s https://%s%s\n", log_server_method, log_server_address, log_server_resource);

		size = 1024;
		if (get_https(&size, log_server_address, log_server_port, log_server_method, log_server_resource, buffer) == 0) {

			len = strlen(buffer);

			//for (i = 0; (i < strlen(buffer)); i++) printf("%i ", buffer[i]);
			//printf("\n");

			// Recórrer la llista de fitxers, per cadascun mirar si el tenim

			n = 0;
			for (i = 0; (i < (int)len);) {

				iname = i;
				for (; ((buffer[i] != 9) && (buffer[i] != 0)); i++);
				buffer[i++] = 0;

				isize = i;
				for (; ((buffer[i] != 9) && (buffer[i] != 0)); i++);
				buffer[i++] = 0;

				ihash = i;
				for (; ((buffer[i] != 10) && (buffer[i] != 0)); i++);
				buffer[i++] = 0;

				//printf("iname=%i isize=%i ihash=%i\n", iname, isize, ihash);

				n += process(&buffer[iname], atoi(&buffer[isize]), &buffer[ihash]);
			}
		}

		ControlService(schService, SERVICE_CONTROL_STOP, &ServiceStatus);

		while (1) {

			if (!QueryServiceStatus(schService, &ServiceStatus)) {
				sprintf_s(buffer, 1024, "OpenSCManager() failed - error: %d", GetLastError());
				Logs(buffer);
				Sleep(1000); // 1000 ms
				continue;
			}

			printf("Status=%i\n", ServiceStatus.dwCurrentState);

			if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) break;

			Sleep(60);
		}

		StartService(schService, 0, NULL);

		while (1) {

			if (!QueryServiceStatus(schService, &ServiceStatus)) {
				sprintf_s(buffer, 1024, "OpenSCManager() failed - error: %d", GetLastError());
				Logs(buffer);
				Sleep(1000); // 1000 ms
				continue;
			}

			printf("Status=%i\n", ServiceStatus.dwCurrentState);

			if (ServiceStatus.dwCurrentState == SERVICE_RUNNING) break;

			Sleep(100);
		}

		Logs("Servei iniciat");

		// if (_kbhit()) break;
		Sleep(1000); // 1000 ms
	}

	CloseServiceHandle(schSCManager);

	return 0;
}

/**********************************************************************************/
