#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>

#define BUFSIZE 1024

/**********************************************************************************/

DWORD calc_hash(unsigned alg_id, char *filename, char *hash, DWORD *dwFileSize, DWORD *dwFileType,
	            FILETIME *CreationTime, FILETIME *LastWriteTime)
{
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	//DWORD cbHash;
	DWORD cbRead = 0, pbHashSize, dwHashLen, dwStatus = 0, i;
	BYTE *rgbHash=NULL, *rgbFile=NULL;
	CHAR rgbDigits[] = "0123456789abcdef";

	//printf("calc_hash alg_id=%i filename=<%s>\n", alg_id, filename);

	hFile = CreateFileA(filename,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		dwStatus = GetLastError();
		printf("calc_hash - Error opening file %s\nError: %d\n", filename,
			dwStatus);
		return dwStatus;
	}

	*dwFileType = GetFileType(hFile);
	*dwFileSize = GetFileSize(hFile, NULL);
	GetFileTime(hFile, CreationTime, NULL, LastWriteTime);

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_AES,
		CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		return dwStatus;
	}

	if (!CryptCreateHash(hProv, alg_id, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	rgbFile = malloc(*dwFileSize);
	while (bResult = ReadFile(hFile, rgbFile, *dwFileSize, &cbRead, NULL))
	{
		if (cbRead==0) break;

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			if (rgbFile) free(rgbFile);
			dwStatus = GetLastError();
			printf("CryptHashData failed: %d\n", dwStatus);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return dwStatus;
		}
	}

	if (!bResult)
	{
		if (rgbFile) free(rgbFile);
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return dwStatus;
	}

	dwHashLen = sizeof(DWORD);
	CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&pbHashSize, &dwHashLen, 0);
	// printf("alg_id=%08x pbHashSize=%i\n", alg_id, pbHashSize);

	rgbHash = malloc(pbHashSize+1);

	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &pbHashSize, 0))
	{
		// printf(L"Hash of file %s is: ", filename);
		for (i = 0; (i < pbHashSize); i++)
		{
			hash[i + i] = rgbDigits[rgbHash[i] >> 4];
			hash[i + i + 1] = rgbDigits[rgbHash[i] & 0xf];

			// printf("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
		}
		hash[i + i] = 0;
		//printf("\n");
	}
	else
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	if (rgbFile) free(rgbFile);
	if (rgbHash) free(rgbHash);

	return dwStatus;
}

/**********************************************************************************/

DWORD calc_hash_string(unsigned alg_id, char *str, char *hash)
{
	DWORD dwStatus = 0, i;
	//BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE *rgbHash=NULL;
	//DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	DWORD dwHashLen, pbHashSize;

	//printf("calc_hash_string alg_id=%i\n", alg_id);

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_AES,
		CRYPT_VERIFYCONTEXT)) {
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		return dwStatus;
	}

	if (!CryptCreateHash(hProv, alg_id, 0, 0, &hHash)) {
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	if (!CryptHashData(hHash, (BYTE *)str, (DWORD)strlen(str), 0)) {
		dwStatus = GetLastError();
		printf("CryptHashData failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return dwStatus;
	}

	dwHashLen = sizeof(DWORD);
	CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&pbHashSize, &dwHashLen, 0);
	// printf("alg_id=%08x pbHashSize=%i\n", alg_id, pbHashSize);

	rgbHash = malloc(pbHashSize + 1);

	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &pbHashSize, 0))
	{
		// printf(L"Hash of file %s is: ", filename);
		for (i = 0; (i < pbHashSize); i++)
		{
			hash[i + i] = rgbDigits[rgbHash[i] >> 4];
			hash[i + i + 1] = rgbDigits[rgbHash[i] & 0xf];

			// printf("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
		}
		hash[i + i] = 0;
		//printf("\n");
	}
	else
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	if (rgbHash) free(rgbHash);

	return dwStatus;
}

/**********************************************************************************/

