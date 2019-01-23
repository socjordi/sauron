#define LOG_FILE_TIMEOUT_MS 3600000

#define TIME_BUFFER_LENGTH 32
#define TIME_ERROR "time error"

#define INSTANCE_NAME_MAX_CHARS 255

#define FILE_MONITOR_NAME "FileMonitor"
#define FILE_MONITOR_DEVICE_NAME  "\\\\.\\FileMonitor"

void InitializeFileMonitor(void);
DWORD WINAPI FileMonitorThread(LPVOID);
