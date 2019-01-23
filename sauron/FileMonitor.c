#include <stdio.h>
#include <windows.h>
#include <psapi.h>		// GetProcessImageFileName
#include "uthash.h"

#include "FileMonitor.h"
#include "../FileMonitorDriver/minispy.h"
#include "../FileMonitorDriver/mspyLog.h"
#include "log.h"
#include "param.h"
#include "hash.h"

#define BUFFER_SIZE 4096
//#define POLL_INTERVAL 200	// ms
#define POLL_INTERVAL 20	// ms

HANDLE hDevice, hEvent, hThread;
LOG_CONTEXT context;

typedef struct {
	char hash[33];
	ULONGLONG time;
	UT_hash_handle hh;
} path_t;

path_t *Paths = NULL;

/**********************************************************************************/

void LoadFileMonitorDriver(void) {

	SC_HANDLE scmHandle, serviceHandle;
	WCHAR sc_Data[64] = L"FileMonitorInst";
	WCHAR sc_Data1[32] = L"385000";
	LONG lResult;
	DWORD dFlags, dwBytesNeeded;
	//HKEY hKey;
	HKEY hKeyInstance, hKeyAltitude;
	SERVICE_STATUS_PROCESS ssp;
	char path[1024], str[1024];

	if (GetParameter("SOFTWARE_PATH", 0) == NULL) return;

	LogError("LoadFileMonitorDriver OpenSCManager");

	scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (NULL == scmHandle)
	{
		sprintf_s(str, 1024, "LoadFileMonitorDriver OpenSCManager failed (%d)", GetLastError());
		LogError(str);
		return;
	}

	serviceHandle = OpenServiceA(scmHandle, FILE_MONITOR_NAME,
		SERVICE_START | SERVICE_STOP |
		SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
	if (serviceHandle)	// Ja està creat
	{
		LogError("LoadFileMonitorDriver OpenService true");

		if (!QueryServiceStatusEx(
			serviceHandle,
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&ssp,
			sizeof(SERVICE_STATUS_PROCESS),
			&dwBytesNeeded))
		{
			sprintf_s(str, 1024, "LoadFileMonitorDriver QueryServiceStatusEx ERROR (%d)", GetLastError());
			LogError(str);
			return;
		}

		sprintf_s(str, 1024, "LoadFileMonitorDriver QueryServiceStatusEx dwCurrentState=%d", ssp.dwCurrentState);
		LogError(str);

		if (ssp.dwCurrentState == SERVICE_RUNNING) {

			LogError("LoadFileMonitorDriver ControlService STOP");
			if (!ControlService(serviceHandle, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
			{
				sprintf_s(str, 1024, "FileMonitorDriver ControlService SERVICE_CONTROL_STOP failed (%d)", GetLastError());
				LogError(str);
				return;
			}

			while (ssp.dwCurrentState != SERVICE_STOPPED) Sleep(1000);

			sprintf_s(str, 1024, "FileMonitorDriver ControlService dwCurrentState=%d", ssp.dwCurrentState);
			LogError(str);
		}

		if (!StartServiceA(serviceHandle, 0, NULL)) {
			//if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
			printf("LoadFileMonitor StartService failed (%d)", GetLastError());
			CloseServiceHandle(serviceHandle);
			CloseServiceHandle(scmHandle);
			return;
		}

		CloseServiceHandle(serviceHandle);
		CloseServiceHandle(scmHandle);

		LogError("FileMonitorDriver.sys iniciat OK");

		return;
	}

	// printf("LoadDriver: abans CreateService\n");
	sprintf_s(path, 1024, "%sFileMonitorDriver.sys", GetParameter("SOFTWARE_PATH", 0));

	sprintf_s(str, 1024, "LoadFileMonitorDriver CreateService %s", path);
	LogError(str);

	serviceHandle = CreateServiceA(
		scmHandle,
		FILE_MONITOR_NAME,
		FILE_MONITOR_NAME,
		SERVICE_ALL_ACCESS,
		SERVICE_FILE_SYSTEM_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		path,
		NULL,		// LoadOrderGroup
		NULL,		// TagId
		NULL,		// Dependencies
		NULL,		// ServiceStartName
		""
		);
	if (!serviceHandle) {
		sprintf_s(str, 1024, "FileMonitorDriver CreateService failed (%d)", GetLastError());
		LogError(str);
		CloseServiceHandle(scmHandle);
		return;
	}

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Services\\FileMonitor\\Instances", 0,
		KEY_READ, &hKeyInstance);
	if (lResult != ERROR_SUCCESS)
	{
		lResult = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
			L"SYSTEM\\CurrentControlSet\\Services\\FileMonitor\\Instances",
			0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKeyInstance, NULL);

		lResult = RegSetValueEx(hKeyInstance, L"DefaultInstance", 0, REG_SZ,
			(LPBYTE)sc_Data, lstrlen(sc_Data)*sizeof(TCHAR));

		lResult = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
			L"SYSTEM\\CurrentControlSet\\Services\\FileMonitor\\Instances\\FileMonitorInst",
			0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKeyAltitude, NULL);

		lResult = RegSetValueEx(hKeyAltitude, L"Altitude", 0, REG_SZ,
			(LPBYTE)sc_Data1, lstrlen(sc_Data1)*sizeof(TCHAR));

		dFlags = 1;
		lResult = RegSetValueEx(hKeyAltitude, L"Flags", 0, REG_DWORD, (LPBYTE)&dFlags, sizeof(DWORD));
	}
	RegCloseKey(hKeyInstance);

	if (!StartService(serviceHandle, 0, NULL)) {
		sprintf_s(str, 1024, "FileMonitorDriver StartService failed (%d)", GetLastError());
		LogError(str);
		CloseServiceHandle(scmHandle);
		return;
	}

	CloseServiceHandle(scmHandle);

	LogError("LoadFileMonitorDriver FileMonitorDriver.sys creat OK");
}

/**********************************************************************************/

void ListDevices(VOID)
{
	UCHAR buffer[1024];
	PFILTER_VOLUME_BASIC_INFORMATION volumeBuffer = (PFILTER_VOLUME_BASIC_INFORMATION)buffer;
	HANDLE volumeIterator = INVALID_HANDLE_VALUE;
	ULONG volumeBytesReturned;
	HRESULT hResult = S_OK;
	WCHAR driveLetter[15] = { 0 };
	WCHAR instanceName[INSTANCE_NAME_MAX_CHARS + 1];

	hResult = FilterVolumeFindFirst(FilterVolumeBasicInformation,
		volumeBuffer,
		sizeof(buffer) - sizeof(WCHAR),   //save space to null terminate name
		&volumeBytesReturned,
		&volumeIterator);
	if (IS_ERROR(hResult)) {
		printf("ListDevices ERROR FilterVolumeFindFirst\n");
		exit(1);
	}

	do {

		volumeBuffer->FilterVolumeName[volumeBuffer->FilterVolumeNameLength / sizeof(WCHAR)] = UNICODE_NULL;

		printf("ListDevices <%-14ws> <%-36ws>\n",
			(SUCCEEDED(FilterGetDosName(
			volumeBuffer->FilterVolumeName,
			driveLetter,
			sizeof(driveLetter) / sizeof(WCHAR))) ? driveLetter : L""),
			volumeBuffer->FilterVolumeName);

		if (wcslen(driveLetter) > 0) {

			printf("FilterAttach <%S>\n", driveLetter);

			hResult = FilterAttach(L"FileMonitor",
				driveLetter,
				NULL,
				sizeof(instanceName),
				instanceName);
			if (SUCCEEDED(hResult)) {
				printf("InitializeFileMonitor - Instance name: %S\n", instanceName);
			}
			else {
				printf("InitializeFileMonitor ERROR - Could not attach to device: 0x%08x\n", hResult);
				//exit(1);
			}
		}

	} while (SUCCEEDED(hResult = FilterVolumeFindNext(volumeIterator,
		FilterVolumeBasicInformation,
		volumeBuffer,
		sizeof(buffer) - sizeof(WCHAR),    //save space to null terminate name
		&volumeBytesReturned)));

	if (HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) == hResult) hResult = S_OK;

	if (INVALID_HANDLE_VALUE != volumeIterator) FilterVolumeFindClose(volumeIterator);

	if (IS_ERROR(hResult)) {
		if (HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) == hResult) printf("No volumes found.\n");
		else printf("Volume listing failed with error: 0x%08x\n", hResult);
	}
}

/**********************************************************************************/

void InitializeFileMonitor(void)
{
	//DWORD dwReturn;
	//BOOL status;
	HANDLE port = INVALID_HANDLE_VALUE;
	HRESULT hResult = S_OK;
	ULONG threadId;
	DWORD result;
	//WCHAR instanceName[INSTANCE_NAME_MAX_CHARS + 1];
	//CHAR buffer[BUFFER_SIZE], parm[32];

	LoadFileMonitorDriver();

	hResult = FilterConnectCommunicationPort(L"\\FileMonitor", 0, NULL, 0, NULL, &port);
	if (IS_ERROR(hResult)) {
		printf("InitializeFileMonitor ERROR: Could not connect to filter: 0x%08x\n", hResult);
		return;
	}

	//printf("InitializeFileMonitor port=%I64d\n", port);
	printf("InitializeFileMonitor\n");

	context.Port = port;
	context.ShutDown = CreateSemaphore(NULL, 0, 1, L"FileMonitor shut down");
	context.CleaningUp = FALSE;
	context.LogToFile = FALSE;
	context.LogToScreen = FALSE;        //don't start logging yet
	context.NextLogToScreen = TRUE;
	context.OutputFile = NULL;
	if (context.ShutDown == NULL) {
		result = GetLastError();
		printf("Could not create semaphore: %d\n", result);
		exit(1);
	}

	hThread = CreateThread(NULL, 0, FileMonitorThread, (LPVOID)&context, 0, &threadId);
	if (hThread == NULL)
	{
		printf("ERROR: InitializeFileMonitor - CreateThread\n");
		exit(1);
	}

	printf("InitializeFileMonitor - CreateThread id=%ld\n", threadId);

	ListDevices();

	/*
	strcpy_s(parm, 32, "c:");

	MultiByteToWideChar(CP_ACP,
		MB_ERR_INVALID_CHARS,
		parm,
		-1,
		(LPWSTR)buffer,
		BUFFER_SIZE / sizeof(WCHAR));

	hResult = FilterAttach(L"FileMonitor",
		(PWSTR)buffer,
		NULL,
		sizeof(instanceName),
		instanceName);
	if (SUCCEEDED(hResult)) {
		printf("InitializeFileMonitor - Instance name: %S\n", instanceName);
	}
	else {
		printf("InitializeFileMonitor ERROR - Could not attach to device: 0x%08x\n", hResult);
		exit(1);
	}
	*/
}

/**********************************************************************************/

ULONG
FormatSystemTime(
_In_ SYSTEMTIME *SystemTime,
_Out_writes_bytes_(BufferLength) CHAR *Buffer,
_In_ ULONG BufferLength
)
{
	ULONG returnLength = 0;

	if (BufferLength < TIME_BUFFER_LENGTH) return 0;

	returnLength = sprintf_s(Buffer,
		BufferLength,
		"%02d:%02d:%02d:%03d",
		SystemTime->wHour,
		SystemTime->wMinute,
		SystemTime->wSecond,
		SystemTime->wMilliseconds);

	return returnLength;
}

/**********************************************************************************/

VOID PrintIrpCode(_In_ UCHAR MajorCode, _In_ UCHAR MinorCode, char *OutputStr) {

	CHAR *irpMajorString, *irpMinorString = NULL;
	CHAR errorBuf[128];

	switch (MajorCode) {
	case IRP_MJ_CREATE:
		irpMajorString = IRP_MJ_CREATE_STRING;
		break;
	case IRP_MJ_CREATE_NAMED_PIPE:
		irpMajorString = IRP_MJ_CREATE_NAMED_PIPE_STRING;
		break;
	case IRP_MJ_CLOSE:
		irpMajorString = IRP_MJ_CLOSE_STRING;
		break;
	case IRP_MJ_READ:
		irpMajorString = IRP_MJ_READ_STRING;
		switch (MinorCode) {
		case IRP_MN_NORMAL:
			irpMinorString = IRP_MN_NORMAL_STRING;
			break;
		case IRP_MN_DPC:
			irpMinorString = IRP_MN_DPC_STRING;
			break;
		case IRP_MN_MDL:
			irpMinorString = IRP_MN_MDL_STRING;
			break;
		case IRP_MN_COMPLETE:
			irpMinorString = IRP_MN_COMPLETE_STRING;
			break;
		case IRP_MN_COMPRESSED:
			irpMinorString = IRP_MN_COMPRESSED_STRING;
			break;
		case IRP_MN_MDL_DPC:
			irpMinorString = IRP_MN_MDL_DPC_STRING;
			break;
		case IRP_MN_COMPLETE_MDL:
			irpMinorString = IRP_MN_COMPLETE_MDL_STRING;
			break;
		case IRP_MN_COMPLETE_MDL_DPC:
			irpMinorString = IRP_MN_COMPLETE_MDL_DPC_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_WRITE:
		irpMajorString = IRP_MJ_WRITE_STRING;
		switch (MinorCode) {
		case IRP_MN_NORMAL:
			irpMinorString = IRP_MN_NORMAL_STRING;
			break;
		case IRP_MN_DPC:
			irpMinorString = IRP_MN_DPC_STRING;
			break;
		case IRP_MN_MDL:
			irpMinorString = IRP_MN_MDL_STRING;
			break;
		case IRP_MN_COMPLETE:
			irpMinorString = IRP_MN_COMPLETE_STRING;
			break;
		case IRP_MN_COMPRESSED:
			irpMinorString = IRP_MN_COMPRESSED_STRING;
			break;
		case IRP_MN_MDL_DPC:
			irpMinorString = IRP_MN_MDL_DPC_STRING;
			break;
		case IRP_MN_COMPLETE_MDL:
			irpMinorString = IRP_MN_COMPLETE_MDL_STRING;
			break;
		case IRP_MN_COMPLETE_MDL_DPC:
			irpMinorString = IRP_MN_COMPLETE_MDL_DPC_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_QUERY_INFORMATION:
		irpMajorString = IRP_MJ_QUERY_INFORMATION_STRING;
		break;
	case IRP_MJ_SET_INFORMATION:
		irpMajorString = IRP_MJ_SET_INFORMATION_STRING;
		break;
	case IRP_MJ_QUERY_EA:
		irpMajorString = IRP_MJ_QUERY_EA_STRING;
		break;
	case IRP_MJ_SET_EA:
		irpMajorString = IRP_MJ_SET_EA_STRING;
		break;
	case IRP_MJ_FLUSH_BUFFERS:
		irpMajorString = IRP_MJ_FLUSH_BUFFERS_STRING;
		break;
	case IRP_MJ_QUERY_VOLUME_INFORMATION:
		irpMajorString = IRP_MJ_QUERY_VOLUME_INFORMATION_STRING;
		break;
	case IRP_MJ_SET_VOLUME_INFORMATION:
		irpMajorString = IRP_MJ_SET_VOLUME_INFORMATION_STRING;
		break;
	case IRP_MJ_DIRECTORY_CONTROL:
		irpMajorString = IRP_MJ_DIRECTORY_CONTROL_STRING;
		switch (MinorCode) {
		case IRP_MN_QUERY_DIRECTORY:
			irpMinorString = IRP_MN_QUERY_DIRECTORY_STRING;
			break;
		case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
			irpMinorString = IRP_MN_NOTIFY_CHANGE_DIRECTORY_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_FILE_SYSTEM_CONTROL:
		irpMajorString = IRP_MJ_FILE_SYSTEM_CONTROL_STRING;
		switch (MinorCode) {
		case IRP_MN_USER_FS_REQUEST:
			irpMinorString = IRP_MN_USER_FS_REQUEST_STRING;
			break;
		case IRP_MN_MOUNT_VOLUME:
			irpMinorString = IRP_MN_MOUNT_VOLUME_STRING;
			break;
		case IRP_MN_VERIFY_VOLUME:
			irpMinorString = IRP_MN_VERIFY_VOLUME_STRING;
			break;
		case IRP_MN_LOAD_FILE_SYSTEM:
			irpMinorString = IRP_MN_LOAD_FILE_SYSTEM_STRING;
			break;
		case IRP_MN_TRACK_LINK:
			irpMinorString = IRP_MN_TRACK_LINK_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_DEVICE_CONTROL:
		irpMajorString = IRP_MJ_DEVICE_CONTROL_STRING;
		switch (MinorCode) {
		case IRP_MN_SCSI_CLASS:
			irpMinorString = IRP_MN_SCSI_CLASS_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_INTERNAL_DEVICE_CONTROL:
		irpMajorString = IRP_MJ_INTERNAL_DEVICE_CONTROL_STRING;
		break;
	case IRP_MJ_SHUTDOWN:
		irpMajorString = IRP_MJ_SHUTDOWN_STRING;
		break;
	case IRP_MJ_LOCK_CONTROL:
		irpMajorString = IRP_MJ_LOCK_CONTROL_STRING;
		switch (MinorCode) {
		case IRP_MN_LOCK:
			irpMinorString = IRP_MN_LOCK_STRING;
			break;
		case IRP_MN_UNLOCK_SINGLE:
			irpMinorString = IRP_MN_UNLOCK_SINGLE_STRING;
			break;
		case IRP_MN_UNLOCK_ALL:
			irpMinorString = IRP_MN_UNLOCK_ALL_STRING;
			break;
		case IRP_MN_UNLOCK_ALL_BY_KEY:
			irpMinorString = IRP_MN_UNLOCK_ALL_BY_KEY_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_CLEANUP:
		irpMajorString = IRP_MJ_CLEANUP_STRING;
		break;
	case IRP_MJ_CREATE_MAILSLOT:
		irpMajorString = IRP_MJ_CREATE_MAILSLOT_STRING;
		break;
	case IRP_MJ_QUERY_SECURITY:
		irpMajorString = IRP_MJ_QUERY_SECURITY_STRING;
		break;
	case IRP_MJ_SET_SECURITY:
		irpMajorString = IRP_MJ_SET_SECURITY_STRING;
		break;
	case IRP_MJ_POWER:
		irpMajorString = IRP_MJ_POWER_STRING;
		switch (MinorCode) {
		case IRP_MN_WAIT_WAKE:
			irpMinorString = IRP_MN_WAIT_WAKE_STRING;
			break;
		case IRP_MN_POWER_SEQUENCE:
			irpMinorString = IRP_MN_POWER_SEQUENCE_STRING;
			break;
		case IRP_MN_SET_POWER:
			irpMinorString = IRP_MN_SET_POWER_STRING;
			break;
		case IRP_MN_QUERY_POWER:
			irpMinorString = IRP_MN_QUERY_POWER_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_SYSTEM_CONTROL:
		irpMajorString = IRP_MJ_SYSTEM_CONTROL_STRING;
		switch (MinorCode) {
		case IRP_MN_QUERY_ALL_DATA:
			irpMinorString = IRP_MN_QUERY_ALL_DATA_STRING;
			break;
		case IRP_MN_QUERY_SINGLE_INSTANCE:
			irpMinorString = IRP_MN_QUERY_SINGLE_INSTANCE_STRING;
			break;
		case IRP_MN_CHANGE_SINGLE_INSTANCE:
			irpMinorString = IRP_MN_CHANGE_SINGLE_INSTANCE_STRING;
			break;
		case IRP_MN_CHANGE_SINGLE_ITEM:
			irpMinorString = IRP_MN_CHANGE_SINGLE_ITEM_STRING;
			break;
		case IRP_MN_ENABLE_EVENTS:
			irpMinorString = IRP_MN_ENABLE_EVENTS_STRING;
			break;
		case IRP_MN_DISABLE_EVENTS:
			irpMinorString = IRP_MN_DISABLE_EVENTS_STRING;
			break;
		case IRP_MN_ENABLE_COLLECTION:
			irpMinorString = IRP_MN_ENABLE_COLLECTION_STRING;
			break;
		case IRP_MN_DISABLE_COLLECTION:
			irpMinorString = IRP_MN_DISABLE_COLLECTION_STRING;
			break;
		case IRP_MN_REGINFO:
			irpMinorString = IRP_MN_REGINFO_STRING;
			break;
		case IRP_MN_EXECUTE_METHOD:
			irpMinorString = IRP_MN_EXECUTE_METHOD_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_DEVICE_CHANGE:
		irpMajorString = IRP_MJ_DEVICE_CHANGE_STRING;
		break;
	case IRP_MJ_QUERY_QUOTA:
		irpMajorString = IRP_MJ_QUERY_QUOTA_STRING;
		break;
	case IRP_MJ_SET_QUOTA:
		irpMajorString = IRP_MJ_SET_QUOTA_STRING;
		break;
	case IRP_MJ_PNP:
		irpMajorString = IRP_MJ_PNP_STRING;
		switch (MinorCode) {
		case IRP_MN_START_DEVICE:
			irpMinorString = IRP_MN_START_DEVICE_STRING;
			break;
		case IRP_MN_QUERY_REMOVE_DEVICE:
			irpMinorString = IRP_MN_QUERY_REMOVE_DEVICE_STRING;
			break;
		case IRP_MN_REMOVE_DEVICE:
			irpMinorString = IRP_MN_REMOVE_DEVICE_STRING;
			break;
		case IRP_MN_CANCEL_REMOVE_DEVICE:
			irpMinorString = IRP_MN_CANCEL_REMOVE_DEVICE_STRING;
			break;
		case IRP_MN_STOP_DEVICE:
			irpMinorString = IRP_MN_STOP_DEVICE_STRING;
			break;
		case IRP_MN_QUERY_STOP_DEVICE:
			irpMinorString = IRP_MN_QUERY_STOP_DEVICE_STRING;
			break;
		case IRP_MN_CANCEL_STOP_DEVICE:
			irpMinorString = IRP_MN_CANCEL_STOP_DEVICE_STRING;
			break;
		case IRP_MN_QUERY_DEVICE_RELATIONS:
			irpMinorString = IRP_MN_QUERY_DEVICE_RELATIONS_STRING;
			break;
		case IRP_MN_QUERY_INTERFACE:
			irpMinorString = IRP_MN_QUERY_INTERFACE_STRING;
			break;
		case IRP_MN_QUERY_CAPABILITIES:
			irpMinorString = IRP_MN_QUERY_CAPABILITIES_STRING;
			break;
		case IRP_MN_QUERY_RESOURCES:
			irpMinorString = IRP_MN_QUERY_RESOURCES_STRING;
			break;
		case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
			irpMinorString = IRP_MN_QUERY_RESOURCE_REQUIREMENTS_STRING;
			break;
		case IRP_MN_QUERY_DEVICE_TEXT:
			irpMinorString = IRP_MN_QUERY_DEVICE_TEXT_STRING;
			break;
		case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
			irpMinorString = IRP_MN_FILTER_RESOURCE_REQUIREMENTS_STRING;
			break;
		case IRP_MN_READ_CONFIG:
			irpMinorString = IRP_MN_READ_CONFIG_STRING;
			break;
		case IRP_MN_WRITE_CONFIG:
			irpMinorString = IRP_MN_WRITE_CONFIG_STRING;
			break;
		case IRP_MN_EJECT:
			irpMinorString = IRP_MN_EJECT_STRING;
			break;
		case IRP_MN_SET_LOCK:
			irpMinorString = IRP_MN_SET_LOCK_STRING;
			break;
		case IRP_MN_QUERY_ID:
			irpMinorString = IRP_MN_QUERY_ID_STRING;
			break;
		case IRP_MN_QUERY_PNP_DEVICE_STATE:
			irpMinorString = IRP_MN_QUERY_PNP_DEVICE_STATE_STRING;
			break;
		case IRP_MN_QUERY_BUS_INFORMATION:
			irpMinorString = IRP_MN_QUERY_BUS_INFORMATION_STRING;
			break;
		case IRP_MN_DEVICE_USAGE_NOTIFICATION:
			irpMinorString = IRP_MN_DEVICE_USAGE_NOTIFICATION_STRING;
			break;
		case IRP_MN_SURPRISE_REMOVAL:
			irpMinorString = IRP_MN_SURPRISE_REMOVAL_STRING;
			break;
		case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
			irpMinorString = IRP_MN_QUERY_LEGACY_BUS_INFORMATION_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
		irpMajorString = IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION_STRING;
		break;

	case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
		irpMajorString = IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION_STRING;
		break;

	case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
		irpMajorString = IRP_MJ_ACQUIRE_FOR_MOD_WRITE_STRING;
		break;

	case IRP_MJ_RELEASE_FOR_MOD_WRITE:
		irpMajorString = IRP_MJ_RELEASE_FOR_MOD_WRITE_STRING;
		break;

	case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
		irpMajorString = IRP_MJ_ACQUIRE_FOR_CC_FLUSH_STRING;
		break;

	case IRP_MJ_RELEASE_FOR_CC_FLUSH:
		irpMajorString = IRP_MJ_RELEASE_FOR_CC_FLUSH_STRING;
		break;

	case IRP_MJ_NOTIFY_STREAM_FO_CREATION:
		irpMajorString = IRP_MJ_NOTIFY_STREAM_FO_CREATION_STRING;
		break;

	case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE:
		irpMajorString = IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE_STRING;
		break;

	case IRP_MJ_NETWORK_QUERY_OPEN:
		irpMajorString = IRP_MJ_NETWORK_QUERY_OPEN_STRING;
		break;

	case IRP_MJ_MDL_READ:
		irpMajorString = IRP_MJ_MDL_READ_STRING;
		break;

	case IRP_MJ_MDL_READ_COMPLETE:
		irpMajorString = IRP_MJ_MDL_READ_COMPLETE_STRING;
		break;

	case IRP_MJ_PREPARE_MDL_WRITE:
		irpMajorString = IRP_MJ_PREPARE_MDL_WRITE_STRING;
		break;

	case IRP_MJ_MDL_WRITE_COMPLETE:
		irpMajorString = IRP_MJ_MDL_WRITE_COMPLETE_STRING;
		break;

	case IRP_MJ_VOLUME_MOUNT:
		irpMajorString = IRP_MJ_VOLUME_MOUNT_STRING;
		break;

	case IRP_MJ_VOLUME_DISMOUNT:
		irpMajorString = IRP_MJ_VOLUME_DISMOUNT_STRING;
		break;

	case IRP_MJ_TRANSACTION_NOTIFY:
		irpMajorString = IRP_MJ_TRANSACTION_NOTIFY_STRING;
		switch (MinorCode) {
		case 0:
			irpMinorString = TRANSACTION_BEGIN;
			break;
		case TRANSACTION_NOTIFY_PREPREPARE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_PREPREPARE_STRING;
			break;
		case TRANSACTION_NOTIFY_PREPARE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_PREPARE_STRING;
			break;
		case TRANSACTION_NOTIFY_COMMIT_CODE:
			irpMinorString = TRANSACTION_NOTIFY_COMMIT_STRING;
			break;
		case TRANSACTION_NOTIFY_COMMIT_FINALIZE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_COMMIT_FINALIZE_STRING;
			break;
		case TRANSACTION_NOTIFY_ROLLBACK_CODE:
			irpMinorString = TRANSACTION_NOTIFY_ROLLBACK_STRING;
			break;
		case TRANSACTION_NOTIFY_PREPREPARE_COMPLETE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_PREPREPARE_COMPLETE_STRING;
			break;
		case TRANSACTION_NOTIFY_PREPARE_COMPLETE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_COMMIT_COMPLETE_STRING;
			break;
		case TRANSACTION_NOTIFY_ROLLBACK_COMPLETE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_ROLLBACK_COMPLETE_STRING;
			break;
		case TRANSACTION_NOTIFY_RECOVER_CODE:
			irpMinorString = TRANSACTION_NOTIFY_RECOVER_STRING;
			break;
		case TRANSACTION_NOTIFY_SINGLE_PHASE_COMMIT_CODE:
			irpMinorString = TRANSACTION_NOTIFY_SINGLE_PHASE_COMMIT_STRING;
			break;
		case TRANSACTION_NOTIFY_DELEGATE_COMMIT_CODE:
			irpMinorString = TRANSACTION_NOTIFY_DELEGATE_COMMIT_STRING;
			break;
		case TRANSACTION_NOTIFY_RECOVER_QUERY_CODE:
			irpMinorString = TRANSACTION_NOTIFY_RECOVER_QUERY_STRING;
			break;
		case TRANSACTION_NOTIFY_ENLIST_PREPREPARE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_ENLIST_PREPREPARE_STRING;
			break;
		case TRANSACTION_NOTIFY_LAST_RECOVER_CODE:
			irpMinorString = TRANSACTION_NOTIFY_LAST_RECOVER_STRING;
			break;
		case TRANSACTION_NOTIFY_INDOUBT_CODE:
			irpMinorString = TRANSACTION_NOTIFY_INDOUBT_STRING;
			break;
		case TRANSACTION_NOTIFY_PROPAGATE_PULL_CODE:
			irpMinorString = TRANSACTION_NOTIFY_PROPAGATE_PULL_STRING;
			break;
		case TRANSACTION_NOTIFY_PROPAGATE_PUSH_CODE:
			irpMinorString = TRANSACTION_NOTIFY_PROPAGATE_PUSH_STRING;
			break;
		case TRANSACTION_NOTIFY_MARSHAL_CODE:
			irpMinorString = TRANSACTION_NOTIFY_MARSHAL_STRING;
			break;
		case TRANSACTION_NOTIFY_ENLIST_MASK_CODE:
			irpMinorString = TRANSACTION_NOTIFY_ENLIST_MASK_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Transaction notication code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;


	default:
		sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp major function (%d)", MajorCode);
		irpMajorString = errorBuf;
		break;
	}

	/*
	if (OutputFile) {

		if (irpMinorString) fprintf(OutputFile, "\t%-35s\t%-35s", irpMajorString, irpMinorString);
		else fprintf(OutputFile, "\t%-35s\t                                   ", irpMajorString);
	}
	else {

		if (PrintMajorCode) printf("%-35s ", irpMajorString);
		else {
			if (irpMinorString) printf("                                                                     %-35s\n", irpMinorString);
		}
	}
	*/

	if (irpMinorString) {
	  sprintf_s(OutputStr, 1024, "\t%s\t%s", irpMajorString, irpMinorString);
	}
	else {
	  sprintf_s(OutputStr, 1024, "\t%s\t", irpMajorString);
	}

}

/**********************************************************************************/

VOID
ScreenDump(
_In_ ULONG SequenceNumber,
_In_ WCHAR CONST *Name,
_In_ PRECORD_DATA RecordData,
_In_ char *str
)
{
	FILETIME localTime;
	SYSTEMTIME systemTime;
	CHAR time[TIME_BUFFER_LENGTH];
	char str2[1024], FileName[1024];
	DWORD ret;

	SequenceNumber;

	strcpy_s(str, 1024, "F\t");

	// Is this an Irp or a FastIo?

	if      (RecordData->Flags & FLT_CALLBACK_DATA_IRP_OPERATION)
		strcat_s(str, 1024, "IRP");
	else if (RecordData->Flags & FLT_CALLBACK_DATA_FAST_IO_OPERATION)
		strcat_s(str, 1024, "FIO");
	else if (RecordData->Flags & FLT_CALLBACK_DATA_FS_FILTER_OPERATION)
		strcat_s(str, 1024, "FSF");
	else
		strcat_s(str, 1024, "ERR");

	// printf("%08X ", SequenceNumber);

	/*
	FileTimeToLocalFileTime((FILETIME *)&(RecordData->OriginatingTime), &localTime);
	FileTimeToSystemTime(&localTime, &systemTime);

	if (FormatSystemTime(&systemTime, time, TIME_BUFFER_LENGTH))
	printf("%-12s ", time);
	else
	printf("%-12s ", TIME_ERROR);
	*/

	FileTimeToLocalFileTime((FILETIME *)&(RecordData->CompletionTime), &localTime);
	FileTimeToSystemTime(&localTime, &systemTime);

	if (FormatSystemTime(&systemTime, time, TIME_BUFFER_LENGTH)) {
	  sprintf_s(str2, 1024, "\t%-12s", time);
	  strcat_s(str, 1024, str2);
	}
	else {
	  sprintf_s(str2, 1024, "\t%-12s", TIME_ERROR);
	  strcat_s(str, 1024, str2);
	}

	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)RecordData->ProcessId);
	if (!hProc) strcpy_s(FileName, 1024, "NN");
	else {
		ret = GetProcessImageFileNameA(hProc, FileName, 1024);
		CloseHandle(hProc);
	}

	//sprintf_s(str2, 1024, "\t%I64d\t%s\t%llu", RecordData->ProcessId, FileName, RecordData->ThreadId);
	sprintf_s(str2, 1024, "\t%llu\t%s\t%llu", (unsigned __int64)RecordData->ProcessId, FileName, (unsigned __int64)RecordData->ThreadId);

	strcat_s(str, 1024, str2);

	PrintIrpCode(RecordData->CallbackMajorId, RecordData->CallbackMinorId, str2);
	strcat_s(str, 1024, str2);

	/*
	sprintf(str2, "\t%08lx", RecordData->IrpFlags);
	strcat(str, str2);

	sprintf(str2, "\t%s", (RecordData->IrpFlags & IRP_NOCACHE) ? "N" : "-");
	strcat(str, str2);

	sprintf(str2, "%s", (RecordData->IrpFlags & IRP_PAGING_IO) ? "P" : "-");
	strcat(str, str2);

	sprintf(str2, "%s", (RecordData->IrpFlags & IRP_SYNCHRONOUS_API) ? "S" : "-");
	strcat(str, str2);

	sprintf(str2, "%s ", (RecordData->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ? "Y" : "-");
	strcat(str, str2);

	sprintf(str2, "%s", (RecordData->IrpFlags & IRP_CREATE_OPERATION) ? "C" : "-");
	strcat(str, str2);

	sprintf(str2, "%s", (RecordData->IrpFlags & IRP_READ_OPERATION) ? "R" : "-");
	strcat(str, str2);

	sprintf(str2, "%s ", (RecordData->IrpFlags & IRP_WRITE_OPERATION) ? "W" : "-");
	strcat(str, str2);

	sprintf(str2, "\t%08p", (PVOID)RecordData->DeviceObject);
	strcat(str, str2);

	sprintf(str2, "\t%08p", (PVOID)RecordData->FileObject);
	strcat(str, str2);

	sprintf(str2, "\t%08p", (PVOID)RecordData->Transaction);
	strcat(str, str2);
	*/

	//sprintf_s(str2, 1024, "\t%08lx:%p", RecordData->Status, (PVOID)RecordData->Information);
	sprintf_s(str2, 1024, "\t%lx\t%x", RecordData->Status, (int)RecordData->Information);
	strcat_s(str, 1024, str2);

	/*
	sprintf(str2, "\t%p %p %p %p %p %08I64x",
	  RecordData->Arg1,
	  RecordData->Arg2,
	  RecordData->Arg3,
	  RecordData->Arg4,
	  RecordData->Arg5,
	  RecordData->Arg6.QuadPart);
	strcat(str, str2);
	*/

	sprintf_s(str2, 1024, "\t%S", Name);
	strcat_s(str, 1024, str2);
}

/**********************************************************************************/

BOOLEAN
TranslateFileTag(
_In_ PLOG_RECORD logRecord
)
/*++

Routine Description:

If this is a mount point reparse point, move the given name string to the
correct position in the log record structure so it will be displayed
by the common routines.

Arguments:

logRecord - The log record to update

Return Value:

TRUE - if this is a mount point reparse point
FALSE - otherwise

--*/
{
	PFLT_TAG_DATA_BUFFER TagData;
	ULONG Length;

	//
	// The reparse data structure starts in the NAME field, point to it.
	//

	TagData = (PFLT_TAG_DATA_BUFFER)&logRecord->Name[0];

	//
	//  See if MOUNT POINT tag
	//

	if (TagData->FileTag == IO_REPARSE_TAG_MOUNT_POINT) {

		//
		//  calculate how much to copy
		//

		Length = min(MAX_NAME_SPACE - sizeof(UNICODE_NULL), TagData->MountPointReparseBuffer.SubstituteNameLength);

		//
		//  Position the reparse name at the proper position in the buffer.
		//  Note that we are doing an overlapped copy
		//

		MoveMemory(&logRecord->Name[0],
			TagData->MountPointReparseBuffer.PathBuffer,
			Length);

		logRecord->Name[Length / sizeof(WCHAR)] = UNICODE_NULL;
		return TRUE;
	}

	return FALSE;
}

/**********************************************************************************/

DWORD WINAPI FileMonitorThread(_In_ LPVOID lpParameter) {

	PLOG_CONTEXT ctxt = (PLOG_CONTEXT)lpParameter;
	DWORD bytesReturned = 0;
	DWORD used;
	PVOID alignedBuffer[BUFFER_SIZE / sizeof(PVOID)];
	PCHAR buffer = (PCHAR)alignedBuffer;
	HRESULT hResult;
	PLOG_RECORD pLogRecord;
	PRECORD_DATA pRecordData;
	COMMAND_MESSAGE commandMessage;
	char Path[1024], hash[33], str[1024];
	path_t *p;
	size_t NumCharsConverted;

	while (TRUE) {

		commandMessage.Command = GetMiniSpyLog;
		hResult = FilterSendMessage(ctxt->Port,
			&commandMessage,
			sizeof(COMMAND_MESSAGE),
			buffer,
			sizeof(alignedBuffer),
			&bytesReturned);
		if (IS_ERROR(hResult)) {
			if (HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) == hResult) {
				printf("The kernel component of FileMonitor has unloaded. Exiting\n");
				exit(1);
			}
			else {
				if (hResult != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
					printf("UNEXPECTED ERROR received: %x\n", hResult);
				Sleep(POLL_INTERVAL);
			}

			continue;
		}

		pLogRecord = (PLOG_RECORD)buffer;
		used = 0;

		for (;;) {

			if (used + FIELD_OFFSET(LOG_RECORD, Name) > bytesReturned) break;

			if (pLogRecord->Length < (sizeof(LOG_RECORD) + sizeof(WCHAR))) {
				printf("UNEXPECTED LOG_RECORD->Length: length=%lu expected>=%lu\n",
					pLogRecord->Length, (sizeof(LOG_RECORD) + sizeof(WCHAR)));
				break;
			}

			used += pLogRecord->Length;

			if (used > bytesReturned) {
				printf("UNEXPECTED LOG_RECORD size: used=%d bytesReturned=%d\n",
					used,
					bytesReturned);
				break;
			}

			pRecordData = &pLogRecord->Data;

			if (FlagOn(pLogRecord->RecordType, RECORD_TYPE_FILETAG)) {
				if (!TranslateFileTag(pLogRecord)){
					pLogRecord = (PLOG_RECORD)Add2Ptr(pLogRecord, pLogRecord->Length);
					continue;
				}
			}

			if (pRecordData->CallbackMajorId == IRP_MJ_CREATE) {

				//printf("M:  %08X\n", pLogRecord->SequenceNumber);
				//printf("MinorId=%i\n", pRecordData->CallbackMinorId);

				wcstombs_s(&NumCharsConverted, Path, 1024, pLogRecord->Name, 1024);

				int skip = 0;
				if ((strlen(Path)>15) && (strcmp((char *)Path + strlen(Path) - 15, "\\Program Files ") == 0)) skip = 1;
				if ((strlen(Path)>24) && (strcmp((char *)Path + strlen(Path) - 24, "\\Program Files\\sauron ") == 0)) skip = 1;
				if ((strlen(Path)>36) && (strcmp((char *)Path + strlen(Path) - 36, "\\Program Files\\sauron\\general.log ") == 0)) skip = 1;
				if ((strlen(Path)>36) && (strcmp((char *)Path + strlen(Path) - 36, "\\Program Files\\sauron\\Log\\current ") == 0)) skip = 1;

				//if (skip == 0) printf("strlen length=%i <%s>\n", strlen(Path), Path + strlen(Path) - 36);

				if ((int)pRecordData->Information < 2) skip = 1;

				if (skip==0) {

					calc_hash_string(CALG_MD5, Path, hash);
					HASH_FIND(hh, Paths, &hash, 32, p);
					if (p) {
						if (p->time + LOG_FILE_TIMEOUT_MS > GetTickCount64()) skip = 1;
						p->time = GetTickCount64();
					}
					else {
						p = malloc(sizeof(path_t));
						memset(p, 0, sizeof(path_t));
						strcpy_s(p->hash, 33, hash);
						p->time = GetTickCount64();

						HASH_ADD(hh, Paths, hash, 32, p);
					}

					if (skip == 0) {

						ScreenDump(pLogRecord->SequenceNumber, pLogRecord->Name, pRecordData, str);

						printf("%s\n", str);
						Logs(str);
					}
				}

				//printf("\n\n");
			}

			if      (FlagOn(pLogRecord->RecordType, RECORD_TYPE_FLAG_OUT_OF_MEMORY))
				printf("M:  %08X System Out of Memory\n", pLogRecord->SequenceNumber);
			else if (FlagOn(pLogRecord->RecordType, RECORD_TYPE_FLAG_EXCEED_MEMORY_ALLOWANCE))
				printf("M:  %08X Exceeded Maximum Allowed Memory Buffers\n", pLogRecord->SequenceNumber);

			pLogRecord = (PLOG_RECORD)Add2Ptr(pLogRecord, pLogRecord->Length);
		}

		if (bytesReturned == 0) Sleep(POLL_INTERVAL);
	}
}

/**********************************************************************************/
