#define SYSMON_HASH_MD5 0
#define SYSMON_HASH_SHA1 1
#define SYSMON_HASH_SHA256 2
#define SYSMON_HASH_IMPHASH 3

void InitializeEventMonitor(void);
void LoadHashes(void);
