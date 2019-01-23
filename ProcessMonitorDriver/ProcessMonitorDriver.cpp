//#define NTDDI_WINXPSP2                      0x05010200
//#define OSVERSION_MASK      0xFFFF0000
//#define SPVERSION_MASK      0x0000FF00
//#define SUBVERSION_MASK     0x000000FF

#include "ProcessMonitorDriver.h"

//
// macros to extract various version fields from the NTDDI version
//
#define OSVER(Version)  ((Version) & OSVERSION_MASK)
#define SPVER(Version)  (((Version) & SPVERSION_MASK) >> 8)
#define SUBVER(Version) (((Version) & SUBVERSION_MASK) )

//#define NTDDI_VERSION   NTDDI_WINXPSP2
//#include <sdkddkver.h>

#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>

#define FILE_DEVICE_UNKNOWN             0x00000022
#define IOCTL_UNKNOWN_BASE              FILE_DEVICE_UNKNOWN
#define IOCTL_CAPTURE_GET_PROCINFO      CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0802, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_CAPTURE_PROC_LIST         CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0807, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
#define PROCESS_POOL_TAG 'pPR'
#define USERSPACE_CONNECTION_TIMEOUT 10
#define PROCESS_HASH_SIZE 1024
#define PROCESS_HASH(ProcessId)			((UINT)(((UINT)ProcessId) % PROCESS_HASH_SIZE))

typedef unsigned int UINT;
typedef char * PCHAR;
typedef PVOID POBJECT;

typedef struct  _IMAGE_INFORMATION {
	ULONG kernelModeImage;
	WCHAR imagePath[1024];
} IMAGE_INFORMATION, *PIMAGE_INFORMATION;

/* Image packet */
typedef struct  _IMAGE_PACKET {
	LIST_ENTRY     Link;
	IMAGE_INFORMATION imageInformation;
} IMAGE_PACKET, *PIMAGE_PACKET;

/* Process event */
typedef struct  _PROCESS_INFORMATION {
	HANDLE processId;
	WCHAR processPath[1024];
	LIST_ENTRY lLoadedImageList;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION;

/* Storage for process information to be put into the process hash map */
typedef struct  _PROCESS_PACKET {
	LIST_ENTRY     Link;
	PROCESS_INFORMATION processInformation;
} PROCESS_PACKET, *PPROCESS_PACKET;

typedef struct _PROCESS_HASH_ENTRY
{
	LIST_ENTRY lProcess;
	KSPIN_LOCK  lProcessSpinLock;
} PROCESS_HASH_ENTRY, *PPROCESS_HASH_ENTRY;

/* Structure to be passed to the kernel driver using openevent */
typedef struct _PROCESS_EVENT
{
	//TIME_FIELDS time;
	LARGE_INTEGER time;
	HANDLE  hParentProcessId;
	HANDLE  hProcessId;
	BOOLEAN bCreated;
	UINT processPathLength;
	WCHAR processPath[1024];
	UCHAR ParentSID[SECURITY_MAX_SID_SIZE];
	UCHAR ProcessSID[SECURITY_MAX_SID_SIZE];
	_PROCESS_EVENT *next;
} PROCESS_EVENT, *PPROCESS_EVENT;

typedef struct _PROCESS_EVENT_PACKET
{
	LIST_ENTRY     Link;
	PROCESS_EVENT processEvent;
} PROCESS_EVENT_PACKET, *PPROCESS_EVENT_PACKET;

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

QUERY_INFO_PROCESS ZwQueryInformationProcess;

/* Context stuff */
typedef struct _CAPTURE_PROCESS_MANAGER
{
	PDEVICE_OBJECT pDeviceObject;
	BOOLEAN bReady;
	PKEVENT eNewProcessEvent;
	HANDLE  hNewProcessEvent;
	//PPROCESS_EVENT pCurrentProcessEvent;
	LIST_ENTRY lQueuedProcessEvents;
	KSPIN_LOCK lQueuedProcessEventsSpinLock;
	ULONG nQueuedProcessEvents;
	FAST_MUTEX mProcessWaitingSpinLock;
	ULONG lastContactTime;
} CAPTURE_PROCESS_MANAGER, *PCAPTURE_PROCESS_MANAGER;

/* Methods */
NTSTATUS KDispatchCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS KDispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

void UnloadDriver(PDRIVER_OBJECT DriverObject);

VOID ProcessCallback(IN HANDLE  hParentId, IN HANDLE  hProcessId, IN BOOLEAN bCreate);
VOID ProcessImageCallback(
	IN PUNICODE_STRING  FullImageName,
	IN HANDLE  ProcessId, // where image is mapped
	IN PIMAGE_INFO  ImageInfo
);

BOOLEAN InsertProcess(PROCESS_INFORMATION processInformation);
BOOLEAN RemoveProcess(HANDLE processId);
PLIST_ENTRY FindProcess(HANDLE processId);
PPROCESS_INFORMATION GetProcess(HANDLE processId);

VOID UpdateLastContactTime();
ULONG GetCurrentTime();
VOID QueueCurrentProcessEvent(PPROCESS_EVENT pProcessEvent);

/* Global process manager so our process callback can use the information*/
PDEVICE_OBJECT gpDeviceObject;

//#define FILELOGPROCESS L"\\SystemRoot\\Temp\\SauronProcessMonitor.log"

/***************************************************************************************************/

/*
void ProcessMonitorLog(char *str) {

	UNICODE_STRING FileName;
	NTSTATUS Status;
	HANDLE FileHandle;
	OBJECT_ATTRIBUTES ObjAttr;
	IO_STATUS_BLOCK IoStatus;
	char str2[128];

	RtlInitUnicodeString(&FileName, FILELOGPROCESS);

	InitializeObjectAttributes(&ObjAttr, &FileName,
		OBJ_CASE_INSENSITIVE, 0, NULL);

	Status = ZwCreateFile(&FileHandle,
		FILE_APPEND_DATA,
		&ObjAttr,
		&IoStatus, NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (Status == STATUS_SUCCESS)
	{
		sprintf(str2, "%s\n", str);

		Status = ZwWriteFile(FileHandle,
			0, NULL, NULL,
			&IoStatus,
			str2,
			(ULONG)strlen(str2),
			NULL, NULL);
	}

	ZwClose(FileHandle);
}
*/

/***************************************************************************************************/

NTSTATUS Unsupported(PDEVICE_OBJECT, PIRP) { return STATUS_NOT_SUPPORTED; }

/***************************************************************************************************/

/*	Main entry point into the driver, is called when the driver is loaded */
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING
)
{
	NTSTATUS        ntStatus;
	UNICODE_STRING  uszDriverString;
	UNICODE_STRING  uszDeviceString;
	UNICODE_STRING  uszProcessEventString;
	PDEVICE_OBJECT    pDeviceObject;
	PCAPTURE_PROCESS_MANAGER pProcessManager;

	/* Point uszDriverString at the driver name */
	RtlInitUnicodeString(&uszDriverString, DEVICE_NAME);

	/* Create and initialise Process Monitor device object */
	ntStatus = IoCreateDevice(
		DriverObject,
		sizeof(CAPTURE_PROCESS_MANAGER),
		&uszDriverString,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&pDeviceObject);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrint("ProcessMonitorDriver: ERROR IoCreateDevice ->  \\Device\\CaptureProcessMonitor - %08x\n", ntStatus);
		return ntStatus;
	}

	/* Point uszDeviceString at the device name */
	RtlInitUnicodeString(&uszDeviceString, DEVICE_LINK);

	/* Create symbolic link to the user-visible name */
	ntStatus = IoCreateSymbolicLink(&uszDeviceString, &uszDriverString);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ProcessMonitorDriver: ERROR IoCreateSymbolicLink ->  \\DosDevices\\CaptureProcessMonitor - %08x\n", ntStatus);
		IoDeleteDevice(pDeviceObject);
		return ntStatus;
	}

	/* Set global device object to newly created object */
	gpDeviceObject = pDeviceObject;

	/* Get the process manager from the extension of the device */
	pProcessManager = (PCAPTURE_PROCESS_MANAGER)gpDeviceObject->DeviceExtension;

	/* Assign global pointer to the device object for use by the callback functions */
	pProcessManager->pDeviceObject = pDeviceObject;
	ExInitializeFastMutex(&pProcessManager->mProcessWaitingSpinLock);
	KeInitializeSpinLock(&pProcessManager->lQueuedProcessEventsSpinLock);
	InitializeListHead(&pProcessManager->lQueuedProcessEvents);
	pProcessManager->nQueuedProcessEvents = 0;

	/* Create event for user-mode processes to monitor */
	RtlInitUnicodeString(&uszProcessEventString, L"\\BaseNamedObjects\\CaptureProcDrvProcessEvent");
	pProcessManager->eNewProcessEvent = IoCreateNotificationEvent(&uszProcessEventString, &pProcessManager->hNewProcessEvent);
	KeClearEvent(pProcessManager->eNewProcessEvent);

	for (int i=0; (i<IRP_MJ_MAXIMUM_FUNCTION); i++) DriverObject->MajorFunction[i] = Unsupported;

	/* Load structure to point to IRP handlers */
	DriverObject->DriverUnload = UnloadDriver;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = KDispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = KDispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KDispatchIoctl;

	//pProcessManager->pCurrentProcessEvent = NULL;
	/* Register process callback function */

	ntStatus = PsSetCreateProcessNotifyRoutine(ProcessCallback, FALSE);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ProcessMonitorDriver: ERROR PsSetCreateProcessNotifyRoutine - %08x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = PsSetLoadImageNotifyRoutine(ProcessImageCallback);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ProcessMonitorDriver: ERROR PsSetLoadImageNotifyRoutine - %08x\n", ntStatus);
		return ntStatus;
	}

	/* Process Manager is ready to receive processes */
	pProcessManager->bReady = TRUE;

	DbgPrint("ProcessMonitorDriver: Successfully Loaded\n");

	/* Return success */
	return STATUS_SUCCESS;
}

/***************************************************************************************************/

NTSTATUS KDispatchCreateClose(IN PDEVICE_OBJECT, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

/***************************************************************************************************/

NTSTATUS GetProcessImageName(HANDLE processId, PUNICODE_STRING ProcessImageName)
{
	NTSTATUS status;
	ULONG returnedLength;
	ULONG bufferLength;
	HANDLE hProcess;
	PVOID buffer;
	PEPROCESS eProcess;
	PUNICODE_STRING imageName;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	hProcess = NULL;

	status = PsLookupProcessByProcessId(processId, &eProcess);

	if (NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, KernelMode, &hProcess);
		if (NT_SUCCESS(status))
		{
		}
		else {
			DbgPrint("ProcessMonitorDriver ObOpenObjectByPointer Failed: %08x\n", status);
		}
		ObDereferenceObject(eProcess);
	}
	else {
		DbgPrint("ProcessMonitorDriver PsLookupProcessByProcessId Failed: %08x\n", status);
	}

	if (NULL == ZwQueryInformationProcess) {

		UNICODE_STRING routineName;

		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

		ZwQueryInformationProcess =
			(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (NULL == ZwQueryInformationProcess) {
			DbgPrint("ProcessMonitorDriver: Cannot resolve ZwQueryInformationProcess\n");
		}
	}

	/* Query the actual size of the process path */
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		NULL, // buffer
		0, // buffer size
		&returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return status;
	}

	/* Check there is enough space to store the actual process
	path when it is found. If not return an error with the
	required size */
	bufferLength = returnedLength - sizeof(UNICODE_STRING);
	if (ProcessImageName->MaximumLength < bufferLength)
	{
		ProcessImageName->MaximumLength = (USHORT)bufferLength;
		return STATUS_BUFFER_OVERFLOW;
	}

	/* Allocate a temporary buffer to store the path name */
	buffer = ExAllocatePoolWithTag(NonPagedPool, returnedLength, PROCESS_POOL_TAG);
	if (NULL == buffer) return STATUS_INSUFFICIENT_RESOURCES;

	/* Retrieve the process path from the handle to the process */
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		buffer,
		returnedLength,
		&returnedLength);
	if (NT_SUCCESS(status))
	{
		/* Copy the path name */
		imageName = (PUNICODE_STRING)buffer;
		RtlCopyUnicodeString(ProcessImageName, imageName);
	}

	/* Free the temp buffer which stored the path */
	ExFreePoolWithTag(buffer, PROCESS_POOL_TAG);

	return status;
}

/***************************************************************************************************/

VOID GetProcessUser(HANDLE processId, void *usersid) {

	NTSTATUS status;
	HANDLE hProcess;
	HANDLE hToken;
	ULONG length;
	PTOKEN_USER tokenInfoBuffer;
	PEPROCESS processObject = NULL;
	
	status = PsLookupProcessByProcessId(processId, &processObject);
	if (status != STATUS_SUCCESS) { DbgPrint("ProcessMonitorDriver GetProcessUser PsLookupProcessByProcessId ERROR status=%lu\n", status); return; }

	status = ObOpenObjectByPointer(processObject, 0, NULL, KEY_ALL_ACCESS, NULL, KernelMode, &hProcess);
	if (status != STATUS_SUCCESS) { DbgPrint("ProcessMonitorDriver GetProcessUser ObOpenObjectByPointer ERROR status=%lu\n", status); return; }

	//hProcess = ZwOpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	//if (hProcess == NULL) { DbgPrint("ProcessMonitorDriver GetProcessUser OpenProcess ERROR\n"); return; }

	status = ZwOpenProcessTokenEx(hProcess, GENERIC_READ, OBJ_KERNEL_HANDLE, &hToken);
	if (status != STATUS_SUCCESS) { ZwClose(hProcess); DbgPrint("ProcessMonitorDriver GetProcessUser ZwOpenProcessTokenEx(%ul) ERROR status=%lu\n", processId, status); return; }

	length = SECURITY_MAX_SID_SIZE;
	//status = ZwQueryInformationToken(hToken, TokenUser, NULL, 0, &length);
	//if (status!=STATUS_BUFFER_TOO_SMALL) { ZwClose(hToken); DbgPrint("ProcessMonitorDriver GetProcessUser ZwQueryInformationToken ERROR\n"); return; }
	//if (length == 0) { ZwClose(hToken); ZwClose(hProcess); return; }

	tokenInfoBuffer = (PTOKEN_USER)ExAllocatePoolWithTag(NonPagedPool, length, PROCESS_POOL_TAG);
	if (!tokenInfoBuffer) { ZwClose(hToken); ZwClose(hProcess); DbgPrint("ProcessMonitorDriver GetProcessUser ExAllocatePoolWithTag ERROR\n"); return; }

	//RtlZeroMemory(tokenInfoBuffer, length);

	status = ZwQueryInformationToken(hToken, TokenUser, tokenInfoBuffer, length, &length);
	if (!NT_SUCCESS(status)) {
		ZwClose(hToken);
		ZwClose(hProcess);
		if (tokenInfoBuffer) ExFreePool(tokenInfoBuffer);
		DbgPrint("Error getting token information: %x\n", status);
		return;
	}

	RtlCopyMemory(usersid, tokenInfoBuffer->User.Sid, length);

	if (tokenInfoBuffer) ExFreePool(tokenInfoBuffer);

	ZwClose(hToken);
	ZwClose(hProcess);
}

/***************************************************************************************************/

VOID ProcessImageCallback(
	IN PUNICODE_STRING  FullImageName,
	IN HANDLE  hProcessId, // where image is mapped
	IN PIMAGE_INFO 
)
{
	//NTSTATUS status;
	//LARGE_INTEGER currentSystemTime;
	//TIME_FIELDS timeFields;
	//UNICODE_STRING processImagePath;
	PROCESS_EVENT_PACKET* processEventPacket;
	PCAPTURE_PROCESS_MANAGER pProcessManager;

	/* Get the process manager from the device extension */
	pProcessManager = (PCAPTURE_PROCESS_MANAGER)gpDeviceObject->DeviceExtension;

	processEventPacket = (PROCESS_EVENT_PACKET *)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_EVENT_PACKET), PROCESS_POOL_TAG);
	if (processEventPacket == NULL) return;

	//RtlCopyMemory(&processEventPacket->processEvent.time, &timeFields, sizeof(TIME_FIELDS));

	RtlStringCbCopyUnicodeString(processEventPacket->processEvent.processPath, 1024, (PCUNICODE_STRING)FullImageName);

	KeQuerySystemTime(&(processEventPacket->processEvent.time));
	//RtlTimeToTimeFields(&currentSystemTime, &timeFields);

	processEventPacket->processEvent.hParentProcessId = hProcessId;
	processEventPacket->processEvent.hProcessId = hProcessId;
	processEventPacket->processEvent.bCreated = 2;

	GetProcessUser(hProcessId, processEventPacket->processEvent.ProcessSID);

	// Queue the process event
	ExInterlockedInsertTailList(&pProcessManager->lQueuedProcessEvents, &processEventPacket->Link, &pProcessManager->lQueuedProcessEventsSpinLock);

	pProcessManager->nQueuedProcessEvents++;
	DbgPrint("ProcessMonitorDriver %5lu ProcessImageCallback: %i:%wZ\n", pProcessManager->nQueuedProcessEvents, hProcessId, FullImageName);

	KeSetEvent(pProcessManager->eNewProcessEvent, 0, FALSE);
	KeClearEvent(pProcessManager->eNewProcessEvent);
}

/***************************************************************************************************/

/*
Process Callback that is called every time a process event occurs. Creates
a kernel event which can be used to notify userspace processes.
*/
VOID ProcessCallback(
	IN HANDLE  hParentId,
	IN HANDLE  hProcessId,
	IN BOOLEAN bCreate
)
{
	NTSTATUS status;
	//LARGE_INTEGER currentSystemTime;
	//TIME_FIELDS timeFields;
	UNICODE_STRING processImagePath;
	PROCESS_EVENT_PACKET* processEventPacket;
	PCAPTURE_PROCESS_MANAGER pProcessManager;

	/* Get the process manager from the device extension */
	pProcessManager = (PCAPTURE_PROCESS_MANAGER)gpDeviceObject->DeviceExtension;

	processEventPacket = (PROCESS_EVENT_PACKET *)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_EVENT_PACKET), PROCESS_POOL_TAG);
	if (processEventPacket == NULL) return;

	//RtlCopyMemory(&processEventPacket->processEvent.time, &timeFields, sizeof(TIME_FIELDS));

	processImagePath.Length = 0;
	processImagePath.MaximumLength = 0;

	status = GetProcessImageName(hProcessId, &processImagePath);
	if (status == STATUS_BUFFER_OVERFLOW)
	{
		processImagePath.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, processImagePath.MaximumLength, PROCESS_POOL_TAG);
		if (processImagePath.Buffer != NULL)
		{
			status = GetProcessImageName(hProcessId, &processImagePath);
			if (NT_SUCCESS(status)) RtlStringCbCopyUnicodeString(processEventPacket->processEvent.processPath, 1024, &processImagePath);
			ExFreePoolWithTag(processImagePath.Buffer, PROCESS_POOL_TAG);
		}
	}
	else DbgPrint("ProcessMonitorDriver GetProcessImageName status=%d\n", status);

	KeQuerySystemTime(&(processEventPacket->processEvent.time));
	//RtlTimeToTimeFields(&currentSystemTime, &timeFields);
	
	processEventPacket->processEvent.hParentProcessId = hParentId;
	processEventPacket->processEvent.hProcessId = hProcessId;
	processEventPacket->processEvent.bCreated = bCreate;

	GetProcessUser(hParentId, processEventPacket->processEvent.ParentSID);
	GetProcessUser(hProcessId, processEventPacket->processEvent.ProcessSID);

	// Queue the process event
	ExInterlockedInsertTailList(&pProcessManager->lQueuedProcessEvents, &processEventPacket->Link, &pProcessManager->lQueuedProcessEventsSpinLock);

	pProcessManager->nQueuedProcessEvents++;
	DbgPrint("ProcessMonitorDriver %5lu ProcessCallback: %i %llu=>%llu %wZ\n", 
		pProcessManager->nQueuedProcessEvents, bCreate, (unsigned long long)hParentId, (unsigned long long)hProcessId, &processImagePath);

	KeSetEvent(pProcessManager->eNewProcessEvent, 0, FALSE);
	KeClearEvent(pProcessManager->eNewProcessEvent);
}

/***************************************************************************************************/

NTSTATUS KDispatchIoctl(IN PDEVICE_OBJECT, IN PIRP Irp)
{
	NTSTATUS					status = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION			irpStack = IoGetCurrentIrpStackLocation(Irp);
	PCHAR						pOutputBuffer;
	UINT						dwDataWritten = 0;
	PCAPTURE_PROCESS_MANAGER	pProcessManager;

	/* Get the process manager from the device extension */
	pProcessManager = (PCAPTURE_PROCESS_MANAGER)gpDeviceObject->DeviceExtension;

	//DbgPrint("IoControlCode=%lu IOCTL_CAPTURE_GET_PROCINFO=%lu\n", irpStack->Parameters.DeviceIoControl.IoControlCode, (ULONG)IOCTL_CAPTURE_GET_PROCINFO);

	switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_CAPTURE_GET_PROCINFO:

		//DbgPrint("IOCTL_CAPTURE_GET_PROCINFO %lu %lu\n", irpStack->Parameters.DeviceIoControl.OutputBufferLength, (ULONG)sizeof(PROCESS_EVENT));
		/* Update the time the user space program last sent an IOCTL */
		//UpdateLastContactTime();
		/* Return some of the process events that are queued */
		if (irpStack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(PROCESS_EVENT))
		{
			//ULONG left = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
			ULONG done = 0;
			pOutputBuffer = (PCHAR)Irp->UserBuffer;
			__try {
				ProbeForWrite(pOutputBuffer,
					irpStack->Parameters.DeviceIoControl.OutputBufferLength,
					__alignof (PROCESS_EVENT));
				//ExAcquireFastMutex(&pProcessManager->mProcessWaitingSpinLock);
				//if(pProcessManager->pCurrentProcessEvent != NULL)
				//{
				//	RtlCopyMemory(pOutputBuffer+done, pProcessManager->pCurrentProcessEvent, sizeof(PROCESS_EVENT));
				//	done += sizeof(PROCESS_EVENT);
				//	ExFreePoolWithTag(pProcessManager->pCurrentProcessEvent, PROCESS_POOL_TAG);
				//	pProcessManager->pCurrentProcessEvent = NULL;
				//}
				//ExReleaseFastMutex(&pProcessManager->mProcessWaitingSpinLock);

				if (!IsListEmpty(&pProcessManager->lQueuedProcessEvents))
				{
					PLIST_ENTRY head;
					PPROCESS_EVENT_PACKET pProcessEventPacket;
					head = ExInterlockedRemoveHeadList(&pProcessManager->lQueuedProcessEvents, &pProcessManager->lQueuedProcessEventsSpinLock);
					pProcessManager->nQueuedProcessEvents--;
					pProcessEventPacket = CONTAINING_RECORD(head, PROCESS_EVENT_PACKET, Link);

					RtlCopyMemory(pOutputBuffer, &pProcessEventPacket->processEvent, sizeof(PROCESS_EVENT));
					done = sizeof(PROCESS_EVENT);

					ExFreePool(pProcessEventPacket);

					DbgPrint("ProcessMonitorDriver nQueuedProcessEvents=%lu\n", pProcessManager->nQueuedProcessEvents);

					// Notify that we still have process events queued
					if (pProcessManager->nQueuedProcessEvents)
						KeSetEvent(pProcessManager->eNewProcessEvent, 0, FALSE);
					else
						KeClearEvent(pProcessManager->eNewProcessEvent);
				}

				dwDataWritten = done;
				status = STATUS_SUCCESS;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("ProcessMonitorDriver: EXCEPTION IOCTL_CAPTURE_GET_PROCINFO - %08x\n", GetExceptionCode());
				status = GetExceptionCode();
			}
		}
		break;
	default:
		status = STATUS_SUCCESS;
		break;
	}
	Irp->IoStatus.Status = status;

	// Set # of bytes to copy back to user-mode...
	if (status == STATUS_SUCCESS)
		Irp->IoStatus.Information = dwDataWritten;
	else
		Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

/***************************************************************************************************/

void UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING uszDeviceString;
	NTSTATUS ntStatus;
	PCAPTURE_PROCESS_MANAGER pProcessManager;

	/* Get the process manager from the device extension */
	pProcessManager = (PCAPTURE_PROCESS_MANAGER)gpDeviceObject->DeviceExtension;

	/* Remove the callback routines */
	if (pProcessManager->bReady)
	{
		ntStatus = PsSetCreateProcessNotifyRoutine(ProcessCallback, TRUE);
		PsRemoveLoadImageNotifyRoutine(ProcessImageCallback);
		pProcessManager->bReady = FALSE;
	}

	ExAcquireFastMutex(&pProcessManager->mProcessWaitingSpinLock);
	/*
	if (pProcessManager->pCurrentProcessEvent != NULL)
	{
		ExFreePoolWithTag(pProcessManager->pCurrentProcessEvent, PROCESS_POOL_TAG);
		pProcessManager->pCurrentProcessEvent = NULL;
	}
	*/
	ExReleaseFastMutex(&pProcessManager->mProcessWaitingSpinLock);

	RtlUnicodeStringInit(&uszDeviceString, DEVICE_LINK);
	/* Delete the symbolic link */
	IoDeleteSymbolicLink(&uszDeviceString);

	/* Delete the device */
	if (DriverObject->DeviceObject != NULL) IoDeleteDevice(DriverObject->DeviceObject);
}

/***************************************************************************************************/