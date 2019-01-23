#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include <dbt.h>
#include <conio.h>
#include <cfgmgr32.h>   // for MAX_DEVICE_ID_LEN, CM_Get_Parent and CM_Get_Device_ID
#include <devguid.h>    // for GUID_DEVCLASS_CDROM etc
#include <setupapi.h>
#include <initguid.h>

#include "log.h"

/* Setupapi.lib */

/* http://www.velleman.eu/images/tmp/usbfind.c */
/* http://stackoverflow.com/questions/3438366/setupdigetdeviceproperty */
/* http://www.forensicswiki.org/wiki/USB_History_Viewing */

// include DEVPKEY_Device_BusReportedDeviceDesc from WinDDK\7600.16385.1\inc\api\devpropdef.h
#ifdef DEFINE_DEVPROPKEY
#undef DEFINE_DEVPROPKEY
#endif
#ifdef INITGUID
#define DEFINE_DEVPROPKEY(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, pid) EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY name = { { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }, pid }
#else
#define DEFINE_DEVPROPKEY(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, pid) EXTERN_C const DEVPROPKEY name
#endif // INITGUID

// include DEVPKEY_Device_BusReportedDeviceDesc from WinDDK\7600.16385.1\inc\api\devpkey.h
DEFINE_DEVPROPKEY(DEVPKEY_Device_BusReportedDeviceDesc, 0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2, 4);     // DEVPROP_TYPE_STRING
DEFINE_DEVPROPKEY(DEVPKEY_Device_ContainerId, 0x8c7ed206, 0x3f8a, 0x4827, 0xb3, 0xab, 0xae, 0x9e, 0x1f, 0xae, 0xfc, 0x6c, 2);     // DEVPROP_TYPE_GUID
DEFINE_DEVPROPKEY(DEVPKEY_Device_FriendlyName, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 14);    // DEVPROP_TYPE_STRING
DEFINE_DEVPROPKEY(DEVPKEY_DeviceDisplay_Category, 0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57, 0x5a);  // DEVPROP_TYPE_STRING_LIST
DEFINE_DEVPROPKEY(DEVPKEY_Device_LocationInfo, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 15);    // DEVPROP_TYPE_STRING
DEFINE_DEVPROPKEY(DEVPKEY_Device_Manufacturer, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 13);    // DEVPROP_TYPE_STRING
DEFINE_DEVPROPKEY(DEVPKEY_Device_SecuritySDS, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 26);    // DEVPROP_TYPE_SECURITY_DESCRIPTOR_STRING

#define ARRAY_SIZE(arr)     (sizeof(arr)/sizeof(arr[0]))

typedef BOOL(WINAPI *FN_SetupDiGetDevicePropertyW)(
	__in       HDEVINFO DeviceInfoSet,
	__in       PSP_DEVINFO_DATA DeviceInfoData,
	__in       const DEVPROPKEY *PropertyKey,
	__out      DEVPROPTYPE *PropertyType,
	__out_opt  PBYTE PropertyBuffer,
	__in       DWORD PropertyBufferSize,
	__out_opt  PDWORD RequiredSize,
	__in       DWORD Flags
	);

HANDLE hThread;

LPCWSTR windowClassName = L"USBMsgOnlyWindow";

static GUID GUID_DEVINTERFACE_USB_HUB = { 0xf18a0e88, 0xc30c, 0x11d0, { 0x88, 0x15, 0x00, 0xa0, 0xc9, 0x06, 0xbe, 0xd8 } };
static GUID GUID_DEVINTERFACE_USB_DEVICE = { 0xA5DCBF10L, 0x6530, 0x11D2, { 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED } };
static GUID GUID_DEVINTERFACE_USB_HOST_CONTROLLER = { 0x3abf6f2d, 0x71c4, 0x462a, { 0x8a, 0x92, 0x1e, 0x68, 0x61, 0xe6, 0xaf, 0x27 } };

/**********************************************************************************/

BOOL DoRegisterDeviceInterfaceToHwnd(
	IN GUID InterfaceClassGuid,
	IN HWND hWnd,
	OUT HDEVNOTIFY *hDeviceNotify
	)
{
	DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;

	InterfaceClassGuid;

	ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
	NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
	NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	NotificationFilter.dbcc_reserved = 0;
	NotificationFilter.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;

	*hDeviceNotify = RegisterDeviceNotification(
		hWnd,                       // events recipient
		&NotificationFilter,        // type of device
		DEVICE_NOTIFY_WINDOW_HANDLE // type of recipient handle
		);
	if (NULL == *hDeviceNotify)
	{
		printf("ERROR RegisterDeviceNotification\n");
		return FALSE;
	}

	return TRUE;
}

/**********************************************************************************/

void ListUSBDevices(CONST GUID *pClassGuid, LPCTSTR pszEnumerator)
{
	unsigned i, j;
	DWORD dwSize, dwPropertyRegDataType;
	DEVPROPTYPE ulPropertyType;
	CONFIGRET status;
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA DeviceInfoData;
	const static LPCTSTR arPrefix[3] = { TEXT("VID_"), TEXT("PID_"), TEXT("MI_") };
	TCHAR szDeviceInstanceID[MAX_DEVICE_ID_LEN];
	TCHAR szDesc[1024], szHardwareIDs[4096];
	WCHAR szBuffer[4096], wstr[1024];
	LPTSTR pszToken, pszNextToken;
	TCHAR szVid[MAX_DEVICE_ID_LEN], szPid[MAX_DEVICE_ID_LEN], szMi[MAX_DEVICE_ID_LEN];
	FN_SetupDiGetDevicePropertyW fn_SetupDiGetDevicePropertyW = (FN_SetupDiGetDevicePropertyW)
		GetProcAddress(GetModuleHandle(TEXT("Setupapi.dll")), "SetupDiGetDevicePropertyW");
	char str[1024];
	size_t n;

	// List all connected USB devices
	hDevInfo = SetupDiGetClassDevs(pClassGuid, pszEnumerator, NULL,
		pClassGuid != NULL ? DIGCF_PRESENT : DIGCF_ALLCLASSES | DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE)
		return;

	// Find the ones that are driverless
	for (i = 0;; i++)  {

		wcscpy_s(wstr, 1024, L"U\t");

		DeviceInfoData.cbSize = sizeof(DeviceInfoData);
		if (!SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData)) break;

		status = CM_Get_Device_ID(DeviceInfoData.DevInst, szDeviceInstanceID, MAX_PATH, 0);
		if (status != CR_SUCCESS) continue;

		// Display device instance ID
		_tprintf(TEXT("%s\n"), szDeviceInstanceID);
		wcscat_s(wstr, 1024, szDeviceInstanceID);

		if (SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_DEVICEDESC,
			&dwPropertyRegDataType, (BYTE*)szDesc,
			sizeof(szDesc),   // The size, in bytes
			&dwSize)) {
			_tprintf(TEXT("    Device Description: \"%s\"\n"), szDesc);
			wcscat_s(wstr, 1024, L"\t");
			wcscat_s(wstr, 1024, szDesc);
		}

		if (SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_HARDWAREID,
			&dwPropertyRegDataType, (BYTE*)szHardwareIDs,
			sizeof(szHardwareIDs),    // The size, in bytes
			&dwSize)) {
			LPCTSTR pszId;
			_tprintf(TEXT("    Hardware IDs:\n"));
			for (pszId = szHardwareIDs;
				*pszId != TEXT('\0') && pszId + dwSize / sizeof(TCHAR) <= szHardwareIDs + ARRAYSIZE(szHardwareIDs);
				pszId += lstrlen(pszId) + 1) {

				_tprintf(TEXT("        \"%s\"\n"), pszId);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, pszId);
			}
		}

		// Retreive the device description as reported by the device itself
		// On Vista and earlier, we can use only SPDRP_DEVICEDESC
		// On Windows 7, the information we want ("Bus reported device description") is
		// accessed through DEVPKEY_Device_BusReportedDeviceDesc
		if (fn_SetupDiGetDevicePropertyW && fn_SetupDiGetDevicePropertyW(hDevInfo, &DeviceInfoData, &DEVPKEY_Device_BusReportedDeviceDesc,
			&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0)) {

			if (fn_SetupDiGetDevicePropertyW(hDevInfo, &DeviceInfoData, &DEVPKEY_Device_BusReportedDeviceDesc,
				&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0)) {
				_tprintf(TEXT("    Bus Reported Device Description: \"%ls\"\n"), szBuffer);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, szBuffer);
			}

			if (fn_SetupDiGetDevicePropertyW(hDevInfo, &DeviceInfoData, &DEVPKEY_Device_Manufacturer,
				&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0)) {
				_tprintf(TEXT("    Device Manufacturer: \"%ls\"\n"), szBuffer);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, szBuffer);
			}

			if (fn_SetupDiGetDevicePropertyW(hDevInfo, &DeviceInfoData, &DEVPKEY_Device_FriendlyName,
				&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0)) {
				_tprintf(TEXT("    Device Friendly Name: \"%ls\"\n"), szBuffer);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, szBuffer);
			}

			if (fn_SetupDiGetDevicePropertyW(hDevInfo, &DeviceInfoData, &DEVPKEY_Device_LocationInfo,
				&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0)) {
				_tprintf(TEXT("    Device Location Info: \"%ls\"\n"), szBuffer);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, szBuffer);
			}

			if (fn_SetupDiGetDevicePropertyW(hDevInfo, &DeviceInfoData, &DEVPKEY_Device_SecuritySDS,
				&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0)) {
				// See Security Descriptor Definition Language on MSDN
				// (http://msdn.microsoft.com/en-us/library/windows/desktop/aa379567(v=vs.85).aspx)
				_tprintf(TEXT("    Device Security Descriptor String: \"%ls\"\n"), szBuffer);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, szBuffer);
			}

			if (fn_SetupDiGetDevicePropertyW(hDevInfo, &DeviceInfoData, &DEVPKEY_Device_ContainerId,
				&ulPropertyType, (BYTE*)szDesc, sizeof(szDesc), &dwSize, 0)) {
				StringFromGUID2((REFGUID)szDesc, szBuffer, ARRAY_SIZE(szBuffer));
				_tprintf(TEXT("    ContainerId: \"%ls\"\n"), szBuffer);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, szBuffer);
			}

			if (fn_SetupDiGetDevicePropertyW(hDevInfo, &DeviceInfoData, &DEVPKEY_DeviceDisplay_Category,
				&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0)) {
				_tprintf(TEXT("    Device Display Category: \"%ls\"\n"), szBuffer);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, szBuffer);
			}
		}

		pszToken = _tcstok_s(szDeviceInstanceID, TEXT("\\#&"), &pszNextToken);
		while (pszToken != NULL) {
			szVid[0] = TEXT('\0');
			szPid[0] = TEXT('\0');
			szMi[0] = TEXT('\0');
			for (j = 0; j < 3; j++) {
				if (_tcsncmp(pszToken, arPrefix[j], lstrlen(arPrefix[j])) == 0) {
					switch (j) {
					case 0:
						_tcscpy_s(szVid, ARRAY_SIZE(szVid), pszToken);
						break;
					case 1:
						_tcscpy_s(szPid, ARRAY_SIZE(szPid), pszToken);
						break;
					case 2:
						_tcscpy_s(szMi, ARRAY_SIZE(szMi), pszToken);
						break;
					default:
						break;
					}
				}
			}

			if (szVid[0] != TEXT('\0')) {
				_tprintf(TEXT("    vid: \"%s\"\n"), szVid);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, szVid);
			}

			if (szPid[0] != TEXT('\0')) {
				_tprintf(TEXT("    pid: \"%s\"\n"), szPid);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, szPid);
			}

			if (szMi[0] != TEXT('\0')) {
				_tprintf(TEXT("    mi: \"%s\"\n"), szMi);
				wcscat_s(wstr, 1024, L"\t");
				wcscat_s(wstr, 1024, szMi);
			}

			wcstombs_s(&n, str, 1024, wstr, 1024);
			Logs(str);

			pszToken = _tcstok_s(NULL, TEXT("\\#&"), &pszNextToken);
		}
	}

	return;
}

/**********************************************************************************/

INT_PTR WINAPI USBWinProcCallback(
	HWND hWnd,
	UINT message,
	WPARAM wParam,
	LPARAM lParam
	) {

	LRESULT lRet = 1;
	static HDEVNOTIFY hDeviceNotify;
	static HWND hEditWnd;
	static ULONGLONG msgCount = 0;
	char name[1024], str[1024];
	size_t n;

	PDEV_BROADCAST_DEVICEINTERFACE pDevInt = (PDEV_BROADCAST_DEVICEINTERFACE)lParam;

	switch (message)
	{
	case WM_CREATE:

		if (!DoRegisterDeviceInterfaceToHwnd(
			GUID_DEVINTERFACE_USB_DEVICE,
			hWnd,
			&hDeviceNotify))
		{
			printf("DoRegisterDeviceInterfaceToHwnd");
			ExitProcess(1);
		}

		break;

	case WM_DEVICECHANGE:
	{
		//printf("WM_DEVICECHANGE WPARAM=x%04x LPARAM=x%04x\n", wParam, lParam);

		switch (wParam)
		{
		case DBT_DEVICEARRIVAL:

			printf("DBT_DEVICEARRIVAL\n");
			if (pDevInt->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {

				//printf("dbch_size=%i\n", pDevInt->dbcc_size);
				wprintf(L"dbcc_name=<%s>\n", pDevInt->dbcc_name);
				wcstombs_s(&n, name, 1024, pDevInt->dbcc_name, 1024);
				sprintf_s(str, 1024, "M\t%s", name);
				Logs(str);

				// dbcc_name="\\?\USB#VID_13FE&PID_1A00#5B6B1185EF55#{a5dcbf10-6530-11d2-901f-00c04-fb951ed}"
				// "USB\Vid_04e8&Pid_503b\0002F9A9828E0F06"
				//usb_detail();
				ListUSBDevices(NULL, TEXT("USBSTOR"));

				// Mirar HKLM\System\MountedDevices
			}
			else printf("dbch_devicetype=%i\n", pDevInt->dbcc_devicetype);

			break;

		case DBT_DEVICEREMOVECOMPLETE:
			printf("DBT_DEVICEREMOVECOMPLETE\n");
			break;
		case DBT_DEVNODES_CHANGED:
			printf("DBT_DEVNODES_CHANGED\n");
			break;
		default:
			printf("WPARAM=%04x\n", (unsigned int)wParam);
			break;
		}
	}
	break;
	case WM_CLOSE:
		if (!UnregisterDeviceNotification(hDeviceNotify))
			printf("UnregisterDeviceNotification");
		DestroyWindow(hWnd);
		break;

	case WM_DESTROY:
		PostQuitMessage(0);
		break;

	default:
		lRet = DefWindowProc(hWnd, message, wParam, lParam);
		break;
	}

	return lRet;
}

/**********************************************************************************/

BOOL InitWindowClass()
{
	WNDCLASSEX wndClass;

	wndClass.cbSize = sizeof(WNDCLASSEX);
	wndClass.style = CS_OWNDC | CS_HREDRAW | CS_VREDRAW;
	//wndClass.hInstance = reinterpret_cast<HINSTANCE>(GetModuleHandle(0));
	wndClass.hInstance = GetModuleHandle(0);
	//wndClass.lpfnWndProc = reinterpret_cast<WNDPROC>(USBWinProcCallback);
	wndClass.lpfnWndProc = USBWinProcCallback;
	wndClass.cbClsExtra = 0;
	wndClass.cbWndExtra = 0;
	wndClass.hIcon = LoadIcon(0, IDI_APPLICATION);
	wndClass.hbrBackground = CreateSolidBrush(RGB(192, 192, 192));
	wndClass.hCursor = LoadCursor(0, IDC_ARROW);
	wndClass.lpszClassName = windowClassName;
	wndClass.lpszMenuName = NULL;
	wndClass.hIconSm = wndClass.hIcon;

	if (!RegisterClassEx(&wndClass))
	{
		printf("Error RegisterClassEx\n");
		return FALSE;
	}

	return TRUE;
}

/**********************************************************************************/

DWORD WINAPI USBMonitorThread(LPVOID lpParam)
{
	MSG msg;

	lpParam;

	InitWindowClass();

	HWND hWnd = CreateWindow(windowClassName, 0, 0, 0, 0, 0, 0, HWND_MESSAGE, 0, 0, 0);
	if (hWnd == NULL) { printf("Error CreateWindow"); ExitProcess(1); }

	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}

/**********************************************************************************/

void InitializeUSBMonitor(void)
{
	hThread = CreateThread(NULL, 0, USBMonitorThread, NULL, 0, NULL);
	if (hThread == NULL)
	{
		printf("ERROR: InitializeUSBMonitor - CreateThread\n");
		return;
	}
}

/**********************************************************************************/