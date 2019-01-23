/* Basat en https://code.google.com/p/ulib-win/source/browse/trunk/demo/ddk/process_spy/ */
/* bcdedit - set loadoptions DISABLE_INTEGRITY_CHECKS */
/* bcdedit - set TESTSIGNING ON */

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include <Psapi.h>

#include "ProcessMonitorDriver.h"

#define FILELOGPROCESS L"\\SystemRoot\\Temp\\SauronProcessMonitor.log"
#define FILELOGIMAGE L"\\SystemRoot\\Temp\\SauronImageMonitor.log"

//extern "C" NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
//extern "C" UCHAR *PsGetProcessImageFileName(IN PEPROCESS Process);

PDEVICE_OBJECT g_DriverDevice;
char outBufProcess[1024], outBufImage[1024];
//ULONG ProcessNameOffset = 0;
PVOID gpEventObjectProcess = NULL, gpEventObjectImage = NULL;

/**********************************************************************************/

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

	status = PsLookupProcessByProcessId(processId, &eProcess);

	if (NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, KernelMode, &hProcess);
		if (NT_SUCCESS(status))
		{
		}
		else {
			DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
		}
		ObDereferenceObject(eProcess);
	}
	else {
		DbgPrint("PsLookupProcessByProcessId Failed: %08x\n", status);
	}


	if (NULL == ZwQueryInformationProcess) {

		UNICODE_STRING routineName;

		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

		ZwQueryInformationProcess =
			(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (NULL == ZwQueryInformationProcess) {
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
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

	if (NULL == buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

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

/**********************************************************************************/

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
		sprintf_s(str2, 128, "%s\n", str);

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

/**********************************************************************************/

/*
void ImageMonitorLog(char *str) {

	UNICODE_STRING FileName;
	NTSTATUS Status;
	HANDLE FileHandle;
	OBJECT_ATTRIBUTES ObjAttr;
	IO_STATUS_BLOCK IoStatus;
	char str2[128];

	RtlInitUnicodeString(&FileName, FILELOGIMAGE);

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
		sprintf_s(str2, 128, "%s\n", str);

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

/**********************************************************************************/

VOID ImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO) {

	PEPROCESS EProcess;
	NTSTATUS  status;
	char strtime[32], strFullImageName[1024], EFileName[1024];
	LARGE_INTEGER time;
	TIME_FIELDS tf;
	//ANSI_STRING as_str;
	size_t count;
	ULONG returnedLength;

	// if (strlen(outBufImage) > 0) ImageMonitorLog(outBufImage);	// Guardar en log temporal (el servei sauron.exe encara no l'ha llegit)

	KeQuerySystemTime(&time);
	RtlTimeToTimeFields(&time, &tf);

	sprintf_s(strtime, 32, "%04d%02d%02dT%02d%02d%02d.%03d",
		tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second, tf.Milliseconds);

	EProcess = NULL;
	status = PsLookupProcessByProcessId(ProcessId, &EProcess);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("ProcessMonitor: PsLookupProcessByProcessId(EProcess) status=%u\n", status);
		return;
	}

	count = wcstombs(strFullImageName, (wchar_t *)(FullImageName->Buffer), 1024);

	//as_str.Length = 0;
	//as_str.MaximumLength = (USHORT) RtlUnicodeStringToAnsiSize(FullImageName);
	//as_str.Buffer = strFullImageName;
	//RtlUnicodeStringToAnsiString(&as_str, FullImageName, FALSE);
	//strFullImageName[as_str.Length] = ANSI_NULL;

	// ImageInfo->ImageSize;
	// ImageInfo->SystemModeImage (0=user/1=kernel)
	// ImageInfo->ImageBase (pointer)
	// ImageInfo->ImageMappedToAllPids(0/1)
	// ImageInfo->ExtendedInfoPresent(0/1)

    status = ZwQueryInformationProcess(EProcess, ProcessImageFileName, EFileName, returnedLength, &returnedLength);
	//f (QueryFullProcessImageNameA(EProcess, 0, EFileName, 1024) > 0)
	//if (GetProcessImageFileNameA(EProcess, EFileName, 1024)>0)
	if (NT_SUCCESS(status))
  	  sprintf_s(outBufImage, 1024, "%s\tI\t%llu\t%s\t%s",
		strtime,
		(unsigned long long int)ProcessId,
		EFileName,
		strFullImageName
		);

	ObDereferenceObject(EProcess);
	EProcess = NULL;

	if (gpEventObjectImage != NULL) KeSetEvent((PRKEVENT)gpEventObjectImage, 0, FALSE);
}

/**********************************************************************************/

VOID ProcessNotify(HANDLE hParentId, HANDLE PId, BOOLEAN bCreate)
{
	PEPROCESS EProcess, PProcess;
	NTSTATUS  status, status2;
	char strtime[32], EImageFileName[1024], PImageFileName[1024];
	LARGE_INTEGER time;
	TIME_FIELDS tf;
	ULONG returnedLength;

	//DbgPrint("ProcessMonitor: ProcessNotify hParentId=%u pId=%u bCreate=%hu\n", hParentId, PId, bCreate);

	//if (strlen(outBufProcess) > 0) ProcessMonitorLog(outBufProcess);	// Guardar en log temporal (el servei sauron.exe encara no l'ha llegit)

	KeQuerySystemTime(&time);
	RtlTimeToTimeFields(&time, &tf);

	sprintf_s(strtime, 32, "%04d%02d%02dT%02d%02d%02d.%03d",
		tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second, tf.Milliseconds);

	if (bCreate) // Create Process
	{
		EProcess = NULL;
		status = PsLookupProcessByProcessId(PId, &EProcess);		// NtosKrnl.exe
		if (!NT_SUCCESS(status))
		{
			//DbgPrint("ProcessMonitor: PsLookupProcessByProcessId(EProcess) status=%u\n", status);
			return;
		}

		// PsReferencePrimaryToken() for getting Token.
		// Then getting SID by calling SeQueryInformationToken()

		PProcess = NULL;
		status = PsLookupProcessByProcessId(hParentId, &PProcess);	// NtosKrnl.exe
		if (!NT_SUCCESS(status))
		{
			//DbgPrint("ProcessMonitor: PsLookupProcessByProcessId(PProcess) status=%u\n", status);
			return;
		}

		/*
		DbgPrint("P:%18s%9d%25s%9d\n",
		PsGetProcessImageFileName(EProcess),
		PId,
		PsGetProcessImageFileName(PProcess),
		hParentId
		);
		*/

		status = ZwQueryInformationProcess(EProcess, ProcessImageFileName, EImageFileName, returnedLength, &returnedLength);
		status2 = ZwQueryInformationProcess(PProcess, ProcessImageFileName, PImageFileName, returnedLength, &returnedLength);

		//if ((QueryFullProcessImageNameA(EProcess, 0, EImageFileName, 1024) > 0) &&
		//	(QueryFullProcessImageNameA(PProcess, 0, PImageFileName, 1024) > 0))
		//if ((GetProcessImageFileNameA(EProcess, EImageFileName, 1024) > 0) &&
		//	(GetProcessImageFileNameA(PProcess, PImageFileName, 1024) > 0))
		if ((NT_SUCCESS(status)) && (NT_SUCCESS(status2)))
		  sprintf_s(outBufProcess, 1024, "%s\tP\t%llu\t%s\t%llu\t%s",
			strtime,
			(unsigned long long int)PId,
			EImageFileName,
			(unsigned long long int)hParentId,
			PImageFileName
			);

		ObDereferenceObject(EProcess);
		EProcess = NULL;

		ObDereferenceObject(PProcess);
		PProcess = NULL;
	}
	else // Terminate process
	{
		//DbgPrint("TERMINATED == PROCESS ID: %d\n", PId);

		sprintf_s(outBufProcess, 1024, "%s\tT\t%llu", strtime, (unsigned long long int)PId);
	}

	if (gpEventObjectProcess != NULL) KeSetEvent((PRKEVENT)gpEventObjectProcess, 0, FALSE);
}

/**********************************************************************************/

NTSTATUS Unsupported(PDEVICE_OBJECT, PIRP){

	return STATUS_NOT_SUPPORTED;
}

/**********************************************************************************/

VOID OnUnload(IN PDRIVER_OBJECT DriverObject){

	UNICODE_STRING deviceLink;

	PsSetCreateProcessNotifyRoutine(ProcessNotify, TRUE);
	//DbgPrint("ProcessMonitor: PsSetCreateProcessNotifyRoutine.\n");

	PsRemoveLoadImageNotifyRoutine(ImageNotify);
	//DbgPrint("ProcessMonitor: PsRemoveLoadImageNotifyRoutine.\n");

	RtlInitUnicodeString(&deviceLink, DEVICE_LINK);
	IoDeleteSymbolicLink(&deviceLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	//DbgPrint("ProcessMonitor: removed I/O device.\n");
}

/**********************************************************************************/

NTSTATUS DeviceIoControlDispatch(
	IN  PDEVICE_OBJECT,
	IN  PIRP pIrp
	)
{
	PIO_STACK_LOCATION              irpStack;
	NTSTATUS                        status;
	PVOID                           inputBuffer;
	ULONG                           inputLength;
	ULONG                           outputLength;
	OBJECT_HANDLE_INFORMATION       objHandleInfo;

	status = STATUS_SUCCESS;

	irpStack = IoGetCurrentIrpStackLocation(pIrp);

	switch (irpStack->MajorFunction) {

	case IRP_MJ_CREATE:

		//DbgPrint("ProcessMonitor: IRP_MJ_CREATE\n");
		break;

	case IRP_MJ_CLOSE:

		//DbgPrint("ProcessMonitor: IRP_MJ_CLOSE\n");
		break;

	case IRP_MJ_DEVICE_CONTROL:
		//DbgPrint("ProcessMonitor: IRP_MJ_DEVICE_CONTROL\n");
		inputLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
		outputLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
		switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {

		case IOCTL_PASSEVENT_PROCESS:

			inputBuffer = pIrp->AssociatedIrp.SystemBuffer;

			//DbgPrint("ProcessMonitor inputBuffer:%08x\n", (HANDLE)inputBuffer);
			status = ObReferenceObjectByHandle(*(HANDLE *)inputBuffer,
				GENERIC_ALL,
				NULL,
				KernelMode,
				&gpEventObjectProcess,
				&objHandleInfo);
			if (status != STATUS_SUCCESS)
			{
				//DbgPrint("ProcessMonitor: wrong\n");
				break;
			}

			break;

		case IOCTL_PASSEVENT_IMAGE:

			inputBuffer = pIrp->AssociatedIrp.SystemBuffer;

			//DbgPrint("ProcessMonitor inputBuffer:%08x\n", (HANDLE)inputBuffer);
			status = ObReferenceObjectByHandle(*(HANDLE *)inputBuffer,
				GENERIC_ALL,
				NULL,
				KernelMode,
				&gpEventObjectImage,
				&objHandleInfo);
			if (status != STATUS_SUCCESS)
			{
				//DbgPrint("ProcessMonitor: wrong\n");
				break;
			}

			break;

		case IOCTL_UNPASSEVENT:

			if (gpEventObjectProcess) ObDereferenceObject(gpEventObjectProcess);
			if (gpEventObjectImage) ObDereferenceObject(gpEventObjectImage);
			//DbgPrint("ProcessMonitor: UNPASSEVENT called\n");

			break;

		case IOCTL_PASSBUF_PROCESS:				/* Cridat des de ProcessMonitor.c */

			if (outputLength > 1024) outputLength = 1024;

			RtlCopyMemory(pIrp->UserBuffer, outBufProcess, outputLength);
			strcpy(outBufProcess, "");

			break;

		case IOCTL_PASSBUF_IMAGE:				/* Cridat des de ProcessMonitor.c */

			if (outputLength > 1024) outputLength = 1024;

			RtlCopyMemory(pIrp->UserBuffer, outBufImage, outputLength);
			strcpy(outBufImage, "");

			break;

		default:

			break;
		}

		break;

	default:

		//DbgPrint("ProcessMonitor: IRP_MJ_UNKNOWN\n");

		break;
	}

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

/**********************************************************************************/

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING)
{
	UNICODE_STRING deviceName, deviceLink;
	NTSTATUS status;
	UINT i;

	strcpy(outBufProcess, "");
	strcpy(outBufImage, "");

	DriverObject->DriverUnload = OnUnload;

	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	RtlInitUnicodeString(&deviceLink, DEVICE_LINK);

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &g_DriverDevice);
	if (NT_SUCCESS(status)) {
		status = IoCreateSymbolicLink(&deviceLink, &deviceName);
		//DbgPrint("ProcessMonitor: I/O device created.\n");
	}
	else{
		//DbgPrint("ProcessMonitor: failed to create I/O device\n");
		return STATUS_UNSUCCESSFUL;
	}

	// set unsupported 
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = Unsupported;

	// register handling function
	//DriverObject->MajorFunction[IRP_MJ_READ] = OnRead;
	//DriverObject->MajorFunction[IRP_MJ_WRITE] = OnWrite;
	//DriverObject->MajorFunction[IRP_MJ_CREATE] = OnCreate;
	//DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlDispatch;

	g_DriverDevice->Flags |= DO_DIRECT_IO;
	g_DriverDevice->Flags &= ~DO_DEVICE_INITIALIZING;

	if (PsSetCreateProcessNotifyRoutine(ProcessNotify, FALSE) != STATUS_SUCCESS) {
		//DbgPrint("ProcessMonitor: Error PsSetCreateProcessNotifyRoutine.\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (PsSetLoadImageNotifyRoutine(ImageNotify) != STATUS_SUCCESS) {
		//DbgPrint("ProcessMonitor: Error PsSetLoadImageNotifyRoutineImageNotify.\n");
		return STATUS_UNSUCCESSFUL;
	}

	//DbgPrint("ProcessMonitor: DriverEntry end.\n");

	return STATUS_SUCCESS;
}

/**********************************************************************************/
