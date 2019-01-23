#include <stdio.h>
#include <pcap.h>
#include <Ws2tcpip.h>

#include "uthash.h"

#include "log.h"
#include "https.h"
#include "param.h"

#define KEYSIZE 50

HANDLE hNetworkMonitorThread=0;
CRITICAL_SECTION gNetworkCS;

typedef struct {
	char key[KEYSIZE];
	long numpackets;
	long ipbytes;
	UT_hash_handle hh; /* makes this structure hashable */
} ipflow_t;

typedef struct {
	char key[KEYSIZE];
} ipflow_lookup_key_t;

ipflow_t *IPFlow = NULL;

long numpackets, numpacketsdump;

void InstallWinpcapDriver(void);

/**********************************************************************************/

void AddIPFlow(char *key, long v) {

	ipflow_t *p;
	ipflow_lookup_key_t lookup_key;

	EnterCriticalSection(&gNetworkCS);

	// printf("AddIPFlow <%s> %i\n", key, strlen(key));

	memset(&lookup_key.key, 0, KEYSIZE);
	strcpy_s(lookup_key.key, KEYSIZE, key);

	HASH_FIND(hh, IPFlow, &lookup_key, KEYSIZE, p);

	if (p) {	// El parametre ja existeix

		p->numpackets = p->numpackets + 1;
		p->ipbytes += v;
	}
	else {		// El parametre no existeix

		p = malloc(sizeof(ipflow_t));
		memset(p, 0, sizeof(ipflow_t));

		memset(p->key, 0, KEYSIZE);
		strcpy_s(p->key, KEYSIZE, key);
		p->numpackets = 1;
		p->ipbytes = v;

		HASH_ADD(hh, IPFlow, key, KEYSIZE, p);
	}

	LeaveCriticalSection(&gNetworkCS);
}

/**********************************************************************************/

void ListIPFlow() {

	ipflow_t *i, *j;
	char str[1024];

	if (GetParameter("MONITOR_NETWORK_PACKETS", 0) == NULL) return;

	EnterCriticalSection(&gNetworkCS);

	HASH_ITER(hh, IPFlow, i, j) {

		sprintf_s(str, 1024, "N\t%s\t%i\t%i", i->key, i->numpackets, i->ipbytes);
		printf("%s\n", str);
		Logs(str);

		HASH_DEL(IPFlow, i);
		free(i);
	}

	/*
	for (i = IPFlow; i != NULL; )
	{
		sprintf_s(str, 1024, "N\t%s\t%i\t%i", i->key, i->numpackets, i->ipbytes);
		printf("%s\n", str);
		Logs(str);

		j = i;
		i = i->hh.next;

		HASH_DEL(IPFlow, j);
		free(j);
	}
	*/

	IPFlow = NULL;
	numpackets = 0;
	numpacketsdump = atoi(GetParameter("MONITOR_NETWORK_PACKETS", 0));

	LeaveCriticalSection(&gNetworkCS);
}

/**********************************************************************************/
/*

Es manté una llista Protocol/IPOrigen/IPDesti/PortOrigen/PortDesti/NumBytes
Aquesta llista es va buidant al log cada minut

OPCIONAL

Es manté una llista blanca IP/PORT, es guarda al servidor /var/www/sauron/1/a1/config/NetworkMonitor.conf

Si fa match IP origen/port origen o IP destí/port destí, no fer log
Els ports poden ser *

En iniciar el servei i cada cert temps, es comprova si el del servidor coincideix amb el local (es comparen hashos), es fa manar el del servidor

*/
/**********************************************************************************/

unsigned short well_known_port(unsigned short port) {

	switch (port) {
	case  20:	return 1; break;	// FTP DATA
	case  22:	return 1; break;	// SSH
	case  23:	return 1; break;	// TELNET
	case  25:	return 1; break;	// SMTP
	case  53:	return 1; break;	// DNS
	case  80:	return 1; break;	// HTTP
	case 443:	return 1; break;	// HTTPS
	}

	return 0;
}

/**********************************************************************************/

void process_packet(u_char *parameters, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {

	unsigned char protocol, type, code;
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN], str[1024], str2[1024], *str3;
	unsigned short ethertype, srcport, dstport, length, total_length, wks, wkd;
	int len;

	packet_header;
	parameters;

	// printf("process_packet\n");

	numpackets++;

	// ETHERNET
	// 6 bytes MAC dest address
	// 6 bytes MAC src address
	// 2 bytes ethertype (0x0800=IP, 0x0806=ARP, 0x8035=RARP, 0x8100=802.1Q VLAN, 0x86dd=IPv6)

	// IP HEADER
	// 1 byte 0x45 (version 4 + header length 20 bytes)
	// 1 byte 0x00 (differentiated services field)
	// 2 bytes (total length)
	// 2 bytes (identification)
	// 2 bytes (flags)
	// 1 byte TTL
	// 1 byte protocol (1=ICMP, 6=TCP, 0x11=17=UDP)
	// 2 bytes (header checksum)
	// 4 bytes (src IP address)
	// 4 bytes (dst IP address)

	//for (int i = 14; (i < 40); i++) printf("%02x ", packet_data[i]);
	//printf("\n");

	// 0x0800=IP, 0x0806=ARP, 0x8035=RARP, 0x8100=802.1Q VLAN, 0x86dd=IPv6
	//((unsigned char *)&ethertype)[0] = packet_data[13];
	//((unsigned char *)&ethertype)[1] = packet_data[12];

	ethertype = (packet_data[12] << 8) | packet_data[13];
	if (ethertype != 0x0800) {
		//sprintf(str, "ethertype=%04x", ethertype);
		//Logs(str);
		return;
	}

	total_length = (packet_data[16] << 8) | packet_data[17];

	// 1=ICMP, 6=TCP, 0x11=17=UDP
	protocol=packet_data[23];
	//sprintf(str, "protocol=%02x", protocol);
	//Logs(str);

	inet_ntop(AF_INET, ((void *)(packet_data + 26)), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ((void *)(packet_data + 30)), dst, INET_ADDRSTRLEN);

	sprintf_s(str, 1024, "D\t%i\t%s\t%s", protocol, src, dst);

	if      (protocol == 0x01) { // ICMP

		type = packet_data[34];
		code = packet_data[35];

		sprintf_s(str2, 1024, "\t%i\t%i", type, code);
		strcat_s(str, 1024, str2);
	}
	else if (protocol == 0x06) { // TCP

		srcport = (packet_data[34] << 8) | packet_data[35];
		dstport = (packet_data[36] << 8) | packet_data[37];

		sprintf_s(str2, 1024, "\t%i\t%i", srcport, dstport);
		strcat_s(str, 1024, str2);
	}
	else if (protocol == 0x11) { // UDP

		// UDP header
		//for (int i = 34; (i < 50); i++) printf("%02x ", packet_data[i]);
		//printf("\n");

		// 34-35: src port
		// 36-37: dst port
		// 38-39: length
		// 40-41: checksum

		srcport = (packet_data[34] << 8) | packet_data[35];
		dstport = (packet_data[36] << 8) | packet_data[37];
		length  = (packet_data[38] << 8) | packet_data[39];

		sprintf_s(str2, 1024, "\t%i\t%i", srcport, dstport);
		strcat_s(str, 1024, str2);

		if ((srcport == 0x35)||(dstport == 0x35)) { // DNS

			// 42-43: transaction ID
			// 44-45: flags
			// 46-47: num questions
			// 48-49: num answer RRs
			// 50-51: num authority RRs
			// 52-53: num additional RRs
			// 54-  : queries

			//id = (packet_data[42] << 8) | packet_data[43];
			//flags = (packet_data[44] << 8) | packet_data[45];
			//num_questions = (packet_data[46] << 8) | packet_data[47];
			//num_answers = (packet_data[48] << 8) | packet_data[49];

			//sprintf(str2, "\tDNS\t%04x\t%04x\t%i\t%i\t%s", 
			//	   id, flags, num_questions, num_answers, packet_data+54);
			//strcat(str, str2);

			strcat_s(str, 1024, "\t");

			//printf("strlen(str)=%i length=%i\n", strlen(str), length);

			len = (int) strlen(str) + 2 * (length - 7) + 1;
			str3 = malloc(len);
			strcpy_s(str3, len, str);

			for (int i = 42; (i <= 42 + length - 8); i++) {
				sprintf_s(str2, 16, "%02x", packet_data[i]);
				// printf("strlen(str3)=%i len=%i strlen(str2)=%i\n", strlen(str3), len, strlen(str2));
				strcat_s(str3, len, str2);
			}

			Logs(str3);

			printf("%s\n", str3);

			free(str3);
		}
	}

	//printf("\n");
	//for (int i=26; (i<30); i++) printf("%02x ", packet_data[i]);
	//printf("\n");

	//Logs(str);

	wks = well_known_port(srcport);
	wkd = well_known_port(dstport);

	if (wks && wkd)
		sprintf_s(str, 1024, "%i\t%s\t%s\t%i\t%i", protocol, src, dst, srcport, dstport);
	else if (wks)
		sprintf_s(str, 1024, "%i\t%s\t%s\t%i\t%i", protocol, src, dst, srcport, 0);
	else if (wkd)
		sprintf_s(str, 1024, "%i\t%s\t%s\t%i\t%i", protocol, src, dst, 0, dstport);
	else
		sprintf_s(str, 1024, "%i\t%s\t%s\t%i\t%i", protocol, src, dst, srcport, dstport);

	// printf("AddIPFlow <%s> %i\n", str, total_length);

	AddIPFlow(str, length);

	// printf("numpackets=%i\n", numpackets);
	if (numpackets>=numpacketsdump) ListIPFlow();

	return;
}

/**********************************************************************************/

DWORD WINAPI NetworkMonitorThread(LPVOID lpParam) {

	char errbuf[PCAP_ERRBUF_SIZE];
	//u_int i = 0;
	//int res;
	//struct pcap_pkthdr *header;
	//const u_char *pkt_data;
	char *name;
	pcap_t *handle;

	name = (char*)lpParam;

	sprintf_s(errbuf, PCAP_ERRBUF_SIZE, "NetworkMonitorThread name=\"%s\"", name);
	printf("%s\n", errbuf);
	LogError(errbuf);

	if ((handle = pcap_open_live(name,	// name of the device
		65536,							// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,								// promiscuous mode (nonzero means promiscuous)
		1000,							// read timeout
		errbuf							// error buffer
		)) == NULL)
	{
		LogError("ERROR NetworkMonitorThread - pcap_open_live");
		return 1;
	}

	pcap_loop(handle, 0, process_packet, NULL);

	/*
	while (res = pcap_next_ex(fp, &header, &pkt_data)) {

		if (res == 0) continue; // Timeout
		
		if (res == 1) {
			printf("packet %s\n", name);
			process_packet(pkt_data);
		}
		else printf("pcap_next_ex %s res=%i\n", name, res);
	}
	*/

	return 0;
}

/**********************************************************************************/

void InitializeNetworkMonitor(void) {

	pcap_if_t *alldevs, *d;
	char errbuf[PCAP_ERRBUF_SIZE], *path=NULL;
	int num;
	FILE *fp;
	errno_t err;
	size_t len;

	if (GetParameter("MONITOR_NETWORK_PACKETS", 0) == NULL) return;
	if (GetParameter("LOG_FOLDER", 0) == NULL) return;

	InitializeCriticalSection(&gNetworkCS);

	InstallWinpcapDriver();

	IPFlow = NULL;
	numpackets = 0;
	numpacketsdump = atoi(GetParameter("MONITOR_NETWORK_PACKETS", 0));

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		sprintf_s(errbuf, PCAP_ERRBUF_SIZE, "ERROR NetworkMonitorDevices - pcap_findalldevs_ex: %s", errbuf);
		LogError(errbuf);
		return;
	}

	len = strlen(GetParameter("LOG_FOLDER", 0)) + 27;
	path = malloc(len);
	sprintf_s(path, len, "%s\\NetworkMonitorDevices.par", GetParameter("LOG_FOLDER", 0));

	err = fopen_s(&fp, path, "w");
	if (err != 0) {
		if (path) free(path);
		sprintf_s(errbuf, PCAP_ERRBUF_SIZE, "NetworkMonitorDevices Error fopen %i\n", errno);
		LogError(errbuf);
		return;
	}

	num = 0;
	for (d = alldevs; d; d = d->next)
	{
		num++;

		sprintf_s(errbuf, PCAP_ERRBUF_SIZE, "M\tNetworkDevice\t%d\t%s\t", num, d->name);
		if (d->description) strcat_s(errbuf, PCAP_ERRBUF_SIZE, d->description);
		//Logs(errbuf);
		fprintf(fp, "%s\n", errbuf);
		printf("%s\n", errbuf);

		/*
		if ((handle = pcap_open_live(d->name,		// name of the device
			65536,							// portion of the packet to capture. 
			// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
			)) == NULL)
		{
			LogError("ERROR NetworkMonitorThread - pcap_open_live");
			return;
		}

		pcap_loop(handle, 0, process_packet, NULL);
		*/

		hNetworkMonitorThread = CreateThread(NULL, 0, NetworkMonitorThread, d->name, 0, NULL);
		if (hNetworkMonitorThread == NULL)
		{
			if (path) free(path);
			LogError("ERROR InitializeNetworkMonitor - CreateThread");
			return;
		}

		printf("InitializeNetworkMonitor %s CreateThread %llu OK\n", d->name, (long long unsigned)hNetworkMonitorThread);
	}

	if (num == 0) {
		LogError("ERROR NetworkMonitorDevices - No interfaces found");
		//exit(1);
	}

	fclose(fp);

	if (path) free(path);

	/*
	if (hNetworkMonitorThread != 0) {

		printf("InitializeNetworkMonitor TerminateThread %i\n", (int)hNetworkMonitorThread);

		TerminateThread(hNetworkMonitorThread, 0);
		hNetworkMonitorThread = 0;

		pcap_close(fp);

		LogError("CloseNetworkMonitor");
	}

	sprintf_s(str, 1024, "InitializeNetworkMonitor numdevice=%i", *numdevice);
	LogError(str);

	hNetworkMonitorThread = CreateThread(NULL, 0, NetworkMonitorThread, numdevice, 0, NULL);
	if (hNetworkMonitorThread == NULL)
	{
		LogError("ERROR InitializeNetworkMonitor - CreateThread");
		return;
	}
	*/

	//pcap_freealldevs(alldevs);
}

/**********************************************************************************/

void InstallWinpcapDriver(void) {

	SC_HANDLE scmHandle, serviceHandle;
	SERVICE_STATUS ServiceStatus;
	char *pathsrc, str[1024];
	size_t len;

	if (GetParameter("SOFTWARE_PATH", 0) == NULL) return;

	// printf("InstallWinpcapDriver: abans d'OpenSCManager\n");

	scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (NULL == scmHandle) {
		sprintf_s(str, 1024, "ERROR InstallWinpcapDriver OpenSCManager failed (%d)", GetLastError());
		LogError(str);
		return;
	}

	serviceHandle = OpenServiceA(scmHandle, "NPF", SC_MANAGER_ALL_ACCESS);
	if (serviceHandle) {	// Ja està creat

		// Reiniciar

		if (!QueryServiceStatus(serviceHandle, &ServiceStatus)) {
			sprintf_s(str, 1024, "InstallWinpcapDriver - OpenSCManager() failed - error: %d", GetLastError());
			LogError(str);
			return;
		}

		if (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {

			if (!ControlService(serviceHandle, SERVICE_CONTROL_STOP, &ServiceStatus)) {
				sprintf_s(str, 1024, "InstallWinpcapDriver ControlService SERVICE_CONTROL_STOP failed (%d)", GetLastError());
				LogError(str);
				CloseServiceHandle(serviceHandle);
				CloseServiceHandle(scmHandle);
				return;
			}
		}

		if (!StartService(serviceHandle, 0, NULL)) {
			sprintf_s(str, 1024, "InstallWinpcapDriver StartService failed (%d)", GetLastError());
			LogError(str);
			CloseServiceHandle(serviceHandle);
			CloseServiceHandle(scmHandle);
			return;
		}

		CloseServiceHandle(serviceHandle);
		CloseServiceHandle(scmHandle);

		return;
	}

	len = strlen(GetParameter("SOFTWARE_PATH", 0)) + 9;
	pathsrc = malloc(len);
	sprintf_s(pathsrc, len, "%s\\npf.sys", GetParameter("SOFTWARE_PATH", 0));

	CopyFileA(pathsrc, "\\windows\\system32\\drivers\\npf.sys", FALSE);
	
	serviceHandle = CreateServiceA(
		scmHandle,
		"NPF",
		"NPF",
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_AUTO_START,
		SERVICE_ERROR_IGNORE,
		"system32\\drivers\\npf.sys",
		NULL,
		NULL,
		NULL,
		NULL,
		"");
	if (!serviceHandle) {
		sprintf_s(str, 1024, "InstallWinpcapDriver CreateService failed (%d)", GetLastError());
		LogError(str);
		CloseServiceHandle(scmHandle);
		return;
	}

	if (!StartService(serviceHandle, 0, NULL)) {
		sprintf_s(str, 1024, "InstallWinpcapDriver StartService failed (%d)", GetLastError());
		LogError(str);
		CloseServiceHandle(scmHandle);
		return;
	}

	CloseServiceHandle(scmHandle);

	LogError("npf.sys instal.lat OK");
}

/**********************************************************************************/
