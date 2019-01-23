void InitializeParameters(void);
void SetParameter(char *, int, char *);
char* GetParameter(char *, int);
void ReadConfiguration(void);
void WriteConfiguration(void);
void PrintConfiguration(void);
int AESEncryptDecrypt(char *, unsigned long *, unsigned long, int);
void decrypt_file(char *, char *);
void encrypt_file(char *, char *);
