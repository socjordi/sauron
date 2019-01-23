#include <windows.h>
#include <stdio.h>

#include "network.h"
#include "Param.h"
#include "https.h"
#include "wmi.h"
#include "event.h"
#include "log.h"
#include "usb.h"
#include "hash.h"
#include "ProcessMonitor.h"
#include "FileMonitor.h"

/**********************************************************************************/

void VersioAgent(void) {

	char hash[128], path[1024], strtime_c[32], strtime_m[32], str[1024], arq[16];
	FILETIME CreationTime, LastWriteTime;
	DWORD dwFileSize, dwFileType;
	SYSTEMTIME st;
	errno_t err;
	FILE *fp;

	if (GetParameter("SOFTWARE_PATH", 0) == NULL) return;
	if (GetParameter("LOG_FOLDER", 0) == NULL) return;

	sprintf_s(path, 1024, "%ssauron.exe", GetParameter("SOFTWARE_PATH", 0));
	calc_hash(CALG_SHA_256, path, hash, &dwFileSize, &dwFileType, &CreationTime, &LastWriteTime);

	FileTimeToSystemTime(&CreationTime, &st);

	sprintf_s(strtime_c, 32, "%04d%02d%02dT%02d%02d%02d.%03d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

	FileTimeToSystemTime(&LastWriteTime, &st);

	sprintf_s(strtime_m, 32, "%04d%02d%02dT%02d%02d%02d.%03d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

#if (_WIN64) 
	strcpy_s(arq, 16, "x64");
#else
	strcpy_s(arq, 16, "x86");
#endif

	sprintf_s(str, 1024, "I\tsauron.exe\t%s\t%s\t%s\tSHA256=%s", arq, strtime_c, strtime_m, hash);
	LogError(str);
	Logs(str);

	sprintf_s(path, sizeof(path), "%s\\AgentVersion.par", GetParameter("LOG_FOLDER", 0));

	err = fopen_s(&fp, path, "w");
	if (err != 0) {
		sprintf_s(str, sizeof(str), "VersioAgent Error fopen %i\n", errno);
		LogError(str);
		return;
	}

	sprintf_s(str, 1024, "0\tCreationTime\t%s\n0\tLastWriteTime\t%s\n0\tSHA256\t%s", strtime_c, strtime_m, hash);

	fprintf(fp, "%s\n", str);
	printf("%s\n", str);

	fclose(fp);
}

/**********************************************************************************/

int main(int argc, char *argv[])
{
	int par;

	InitializeParameters();

	InitializeLog();

	ReadConfiguration();
	SendConfiguration();

	/*
	int i;
	for (i = 0; (i < 100000); i++)
	{
		printf("%i ", i);
		wmi("ROOT\\CIMV2", "Win32_ComputerSystem", "");
		//wmi("ROOT\\CIMV2", "Win32_QuickFixEngineering", "");
	}
	exit(1);
	*/

	VersioAgent();

	par = 0;

	if (argc>1) {

		if      (strcmp(argv[1], "confp") == 0) {
			PrintConfiguration();
			exit(1);
		}
		else if (strcmp(argv[1], "enc") == 0) {
			encrypt_file(argv[2], argv[3]);
			exit(1);
		}
		else if (strcmp(argv[1], "dec") == 0) {
			decrypt_file(argv[2], argv[3]);
			exit(1);
		}
		else if (strcmp(argv[1], "init") == 0) {
			par=atoi(argv[2]);
		}

		if (par == 0) {
			printf("\n\tconfp\n");
			printf("\tenc <filein> <fileout>\n");
			printf("\tdec <filein> <fileout>\n\n");
			printf("\tinit <flags>\n");

			exit(1);
		}
	}

	//SetParameter("ID_AGENT", 0, "1");
	//WriteConfiguration();
	//exit(1);

	if ((par == 0) || ((par & 1) > 0)) {
		printf("InitializeNetworkMonitor\n");
		InitializeNetworkMonitor();
	}

	if ((par == 0) || ((par & 2) > 0)) {
		printf("InitializeProcessMonitor\n");
		InitializeProcessMonitor();
	}

	if ((par == 0) || ((par & 4) > 0)) {
		printf("InitializeFileMonitor\n");
		InitializeFileMonitor();
	}

	if ((par == 0) || ((par & 8) > 0)) {
		printf("InitializeEventMonitor\n");
		InitializeEventMonitor();
	}

	if ((par == 0) || ((par & 16) > 0)) {
		printf("InitializeUSBMonitor\n");
		InitializeUSBMonitor();
	}

	if ((par == 0) || ((par & 32) > 0)) {
		printf("InitializeWMI\n");
		InitializeWMI();
	}

	while (1) Sleep(60000); // 60000 ms = 1 min

	return 0;
}

/**********************************************************************************/
