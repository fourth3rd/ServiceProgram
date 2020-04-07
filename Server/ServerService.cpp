#include "ServerService.h"
#include "ThreadPool.h"

#include <errno.h>
#include <process.h>
#include <direct.h>
#include <conio.h>
#include <Windows.h>
#include <sddl.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <stdio.h>


typedef struct Section
{
	char Name[8];
	int VirtualSize;
	int RVA;
	int SizeOfRawData;
	int PoitnerToRawData;
	int POinterToRelocations;
	int PointerToLineNumber;
	WORD NumberOfRelocations;
	WORD NumberOfLineNumbers;
	int Characteristics;
	int TempOffset;
}Section;

typedef struct RelocData
{
	int TypeRva;
	int i32LoadOffset;
	int i32MemoryOffset;
	int i32FileOffset;
}RelocData;

#define PIPE_NAME L"\\\\.\\pipe\\FLProtectionPipe"
#define BUF_SIZE 1024
wchar_t szName[] = L"Global\\MyFileMappingObject";
wchar_t szMsg[] = L"Success(x86).";
int CommToClient(HANDLE);

#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
EXTERN_C NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID, PULONG, ULONG, PULONG);

IMAGE_DOS_HEADER* cDosHeader = NULL;
IMAGE_NT_HEADERS32* cNtHeader = NULL;
IMAGE_SECTION_HEADER* cTextHeader = NULL;
IMAGE_SECTION_HEADER* pSecH = NULL;
char* pBuf = NULL;
char* pBufReloc = NULL;
char* buf = NULL;
std::vector<std::pair<int, int> > vctSectionRva;
char cName[0x50] = { 0 };

BOOL SetPrivilege(
	HANDLE hToken,          // token handle
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
	);


CServerService::CServerService(PWSTR pszServiceName, bool bCanStop, bool bCanShutdown, bool bCanPauseContinue) : CServiceBase(pszServiceName, bCanStop, bCanShutdown, bCanPauseContinue)
{
	m_hStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if(m_hStoppedEvent == NULL)
		throw GetLastError();

	//DuplicateHandle(
}

CServerService::~CServerService()
{
}

void CServerService::OnStart(DWORD dwArgc, PWSTR* pszArgv)
{
	bool bResult = false;

	do
	{
		////////////////////////////////////////////////////////////////////////////////////
		// 요기 아래에 코딩

		OutputDebugStringA("OnStart");

		HANDLE hProcess;
		HANDLE hToken;

		if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
		{
			OutputDebugStringA("OpenThreadToken Failed");
		}

		if(!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
		{
			OutputDebugStringA("SetPrivilege Failed");

			// close token handle
			CloseHandle(hToken);

			// indicate failur
		}

		if((hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,19548) // PID from commandline
			) == NULL)
		{
			OutputDebugStringA("OpenProcess Failed");
		}

		bResult = true;

		////////////////////////////////////////////////////////////////////////////////////
	}
	while(false);

	OutputDebugStringA("OnStart Finish");

	if(bResult)
		CThreadPool::QueueUserWorkItem(&CServerService::ServiceWorkerThread, this);
	else
		throw GetLastError();

	OutputDebugStringA("End of OnStart");

}

void CServerService::OnStop()
{
	m_bStopping = true;

	////////////////////////////////////////////////////////////////////////////////////
	// 요기 아래에 코딩

	OutputDebugStringA("OnStop");


	////////////////////////////////////////////////////////////////////////////////////


	if(WaitForSingleObject(m_hStoppedEvent, INFINITE) != WAIT_OBJECT_0)
		throw GetLastError();
}

void CServerService::OnPause()
{
	OutputDebugStringA("OnPause");
}

void CServerService::OnContinue()
{
	OutputDebugStringA("OnContinue");
}

void CServerService::OnShutdown()
{
	OutputDebugStringA("OnShutdown");
}

void CServerService::ServiceWorkerThread()
{
	OutputDebugStringA("Start WorkThread");

	while(!m_bStopping)
	{
		////////////////////////////////////////////////////////////////////////////////////
		// 요기 아래에 코딩
		OutputDebugStringA("while Thread Start\n");

		HANDLE hMapFile;
		LPCTSTR pBuf;

		//SECURITY_ATTRIBUTES attributes;
		//ZeroMemory(&attributes, sizeof(attributes));
		//attributes.nLength = sizeof(attributes);
		//TCHAR* szSD = TEXT("D:P")       // Discretionary ACL
		//	TEXT("(A;OICI;GA;;;SY)")     // Deny access to 
		//								 // built-in guests
		//	TEXT("(A;OICI;GA;;;BA)")     // Deny access to 
		//								 // anonymous logon
		//	TEXT("(A;OICI;GR;;;IU)"); // Allow 
		//								 // read/write/execute 
		//								 // to authenticated 
		//								 // users
	/*	ConvertStringSecurityDescriptorToSecurityDescriptor(
			szSD,
			SDDL_REVISION_1,
			&attributes.lpSecurityDescriptor,
			NULL);*/

		SECURITY_ATTRIBUTES secAttr;
		char secDesc[SECURITY_DESCRIPTOR_MIN_LENGTH] = { 0 };
		secAttr.nLength = sizeof(secAttr);
		secAttr.bInheritHandle = FALSE;
		secAttr.lpSecurityDescriptor = &secDesc;
		InitializeSecurityDescriptor(secAttr.lpSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(secAttr.lpSecurityDescriptor, TRUE, 0, FALSE);

		HANDLE hPipe;

		while(!m_bStopping)
		{
			hPipe = CreateNamedPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 5, BUF_SIZE, BUF_SIZE, 2000, &secAttr);

			if(hPipe == INVALID_HANDLE_VALUE)
			{
				OutputDebugStringA("CreatePipe Failed\n");
				break;;
			}

			BOOL bIsSuccess = false;
			bIsSuccess = ConnectNamedPipe(hPipe, NULL);// ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);


			if(bIsSuccess)
				CommToClient(hPipe);
			else
				CloseHandle(hPipe);
		}


		//hMapFile = CreateFileMapping(
		//	INVALID_HANDLE_VALUE,    // use paging file
		//	&secAttr,                    // default security
		//	PAGE_READWRITE,          // read/write access
		//	0,                       // maximum object size (high-order DWORD)
		//	BUF_SIZE,                // maximum object size (low-order DWORD)
		//	szName);                 // name of mapping object
		//OutputDebugStringA("Success CreateFileMapping\n");


		//if(hMapFile == NULL)
		//{
		//	OutputDebugStringA("Could not create file mapping object\n");
		//	return;
		//}
		//pBuf = (LPTSTR)MapViewOfFile(hMapFile,   // handle to map object
		//							 FILE_MAP_ALL_ACCESS, // read/write permission
		//							 0,
		//							 0,
		//							 BUF_SIZE);

		//OutputDebugStringA("Success MapViewOfFile\n");

		//if(pBuf == NULL)
		//{
		//	OutputDebugStringA("Could not map view of file \n");

		//	CloseHandle(hMapFile);

		//	return;
		//}


		//CopyMemory((PVOID)pBuf, szMsg, (wcslen(szMsg) * sizeof(wchar_t)));

		//
		//OutputDebugStringA("Success CopyMemory\n");

		//LocalFree(secAttr.lpSecurityDescriptor);

		//UnmapViewOfFile(pBuf);

		//CloseHandle(hMapFile);


		////////////////////////////////////////////////////////////////////////////////////
		OutputDebugStringA("while Thread Finish\n");

		Sleep(1);
	}

	OutputDebugStringA("End WorkThread");

	// Signal the stopped event.
	SetEvent(m_hStoppedEvent);
}

int CommToClient(HANDLE hPipe)
{
	DWORD dwBytesWritten = BUF_SIZE;
	DWORD dwBytesRead = BUF_SIZE;

	char readDataBuf[BUF_SIZE] = { 0 };

	ReadFile(hPipe, readDataBuf, BUF_SIZE * sizeof(char), &dwBytesRead, NULL);//

	if(dwBytesRead != 0)
	{
		int32_t i32BaseAddress = 0;
		int32_t i32GetProcessId = 0;
		int32_t i32OEP = 0;
		int32_t i32FileBaseAddress = 0;


		memcpy((void*)&i32BaseAddress, (void*)&readDataBuf, 4);
		memcpy((void*)&i32GetProcessId, (void*)&readDataBuf[4], 4);
		memcpy((void*)&i32OEP, (void*)&readDataBuf[8], 4);
		memcpy((void*)&i32FileBaseAddress, (void*)&readDataBuf[0xc], 4);

		int i32cnt = 0x28;
		int i32Namecnt = 0;
		memset(cName, '\x0', sizeof(cName));
		while(1)
		{
			if(readDataBuf[i32cnt] == '\x0')
			{
				break;
			}
			cName[i32Namecnt++] = readDataBuf[i32cnt];
			i32cnt += 2;
		}

		char cBaseAddress[4] = { 0 };
		char cGetProcessId[4] = { 0 };

		sprintf(cBaseAddress, "%x", i32BaseAddress);
		sprintf(cGetProcessId, "%x", i32GetProcessId);

		std::string strOutputResult;
		strOutputResult = cBaseAddress;
		strOutputResult.push_back(' ');
		strOutputResult += cGetProcessId;
		strOutputResult.push_back('\n');
		strOutputResult += cName;
		strOutputResult.push_back('\n');
		//printf("%x %x\n %s\n", i32BaseAddress, i32GetProcessId, cName);

		OutputDebugStringA(strOutputResult.c_str());

		cDosHeader = new IMAGE_DOS_HEADER;
		cNtHeader = new IMAGE_NT_HEADERS32;
		cTextHeader = new IMAGE_SECTION_HEADER;

		memset(cDosHeader, '\x0', sizeof(IMAGE_DOS_HEADER));
		memset(cNtHeader, '\x0', sizeof(IMAGE_NT_HEADERS32));
		memset(cTextHeader, '\x0', sizeof(IMAGE_SECTION_HEADER));

		HANDLE hToken;

		int32_t i32GetNumber = 0;
		HANDLE hGetHandle = OpenProcess(MAXIMUM_ALLOWED, false, i32GetProcessId);

		if(hGetHandle == NULL)
		{
			int32_t i32Result = GetLastError();
			char cResult[4] = { 0, };
			sprintf(cResult, "%x", i32Result);
			std::string strResult= "Failed to get Handle ";
			strResult += cResult;
			strResult += '\n';
			OutputDebugStringA(strResult.c_str());
			return 1;
		}

		int32_t i32OffsetNtHeader = 0;

		int32_t i32OffsetToText = 0;

		ReadProcessMemory((HANDLE)hGetHandle, (PVOID)i32BaseAddress, cDosHeader, sizeof(IMAGE_DOS_HEADER), (PULONG)i32GetNumber);

		memcpy((void*)&i32OffsetNtHeader, (void*)&cDosHeader->e_lfanew, 4);

		ReadProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32OffsetNtHeader), cNtHeader, sizeof(IMAGE_NT_HEADERS32), (PULONG)i32GetNumber);

		int32_t i32RelocRVA = 0;
		int32_t i32RelocPointerToRawData = 0;
		int32_t i32RelocSizeofRawData = 0;
		int32_t i32RelocVirtualSize = 0;

		int32_t i32VirtualSizeText = 0;
		int32_t i32PointerToRawData = 0;
		int32_t i32RVA = 0;
		int32_t i32SizeOfRawData = 0;
		int32_t i32FileTextRva = 0;
		int32_t i32SizeOfCode = cNtHeader->OptionalHeader.SizeOfCode;
		int32_t i32TextSection = 0;
		int32_t i32CfgSection = -2;
		int32_t i32cfgRVA = 0;
		int32_t i32cfgPointerToRawData = 0;
		int32_t i32cfgSizeofRawData = 0;


		int32_t i32DataRVA = 0;
		int32_t i32DataSizeOfRawData = 0;
		int32_t i32DataPointerToRawData = 0;
		int32_t i32DataVirtualSize = 0;
		bool bCheckReloc = false;


		for(int i = 0; i < cNtHeader->FileHeader.NumberOfSections; i++)
		{
			int32_t i32SectionOffset = (int32_t)(cDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
			IMAGE_SECTION_HEADER* pSecH = new IMAGE_SECTION_HEADER;

			ReadProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32SectionOffset), pSecH, sizeof(IMAGE_SECTION_HEADER), (PULONG)i32GetNumber);

			vctSectionRva.push_back({ pSecH->VirtualAddress , pSecH->PointerToRawData });

			if(!strcmp((const char*)pSecH->Name, ".text"))
			{
				i32PointerToRawData = pSecH->PointerToRawData;
				i32RVA = pSecH->VirtualAddress;
				i32SizeOfRawData = pSecH->SizeOfRawData;

				i32VirtualSizeText = pSecH->Misc.VirtualSize;
				i32TextSection = i;
			}
			else if(!strcmp((const char*)pSecH->Name, ".reloc"))
			{
				i32RelocRVA = pSecH->VirtualAddress;
				i32RelocPointerToRawData = pSecH->PointerToRawData;
				i32RelocSizeofRawData = pSecH->SizeOfRawData;
				i32RelocVirtualSize = pSecH->Misc.VirtualSize;
				bCheckReloc = true;
			}
			else if(!strcmp((const char*)pSecH->Name, ".00cfg"))
			{
				i32cfgRVA = pSecH->VirtualAddress;
				i32cfgPointerToRawData = pSecH->PointerToRawData;
				i32cfgSizeofRawData = pSecH->SizeOfRawData;
				i32CfgSection = i;
			}
			else if(!strcmp((const char*)pSecH->Name, ".data"))
			{
				i32DataRVA = pSecH->VirtualAddress;
				i32DataSizeOfRawData = pSecH->SizeOfRawData;;
				i32DataPointerToRawData = pSecH->PointerToRawData;;
				i32DataVirtualSize = pSecH->Misc.VirtualSize;
			}


			delete pSecH;
		}


		int32_t i32SizeOfImage = cNtHeader->OptionalHeader.SizeOfImage;

		int32_t i32SizeOfImageTemp = i32SizeOfImage - i32RVA;

		pBuf = new char[i32SizeOfImageTemp];
		memset(pBuf, '\x00', sizeof(char) * i32SizeOfImageTemp);
		ReadProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32RVA), pBuf, i32SizeOfImageTemp, (PULONG)i32GetNumber);

		for(int i = 0; i < i32SizeOfCode; i++)
		{
			pBuf[i] = ~pBuf[i];
		}

		int32_t i32DataStart = i32DataRVA - i32RVA;

		for(int i = i32DataStart; i < i32DataSizeOfRawData + i32DataStart; i++)
		{
			pBuf[i] = ~pBuf[i];
		}

		pBufReloc = new char[i32RelocVirtualSize];
		memset(pBufReloc, '\x00', sizeof(char) * i32RelocVirtualSize);
		ReadProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32RelocRVA), pBufReloc, i32RelocVirtualSize, NULL);

		int32_t i32RelocCnt = 0;

		FILE* fp = fopen(cName, "rb");
		size_t stSize = 0;
		if(fp)
		{
			fseek(fp, 0, SEEK_END);//
			stSize = ftell(fp);
			buf = new char[stSize];
			memset(buf, '\x00', sizeof(char) * stSize);
			fseek(fp, 0, SEEK_SET);
			fread(buf, stSize, 1, fp);

			fclose(fp);
		}

		std::vector<RelocData > vctCheck;
		vctCheck.clear();
		if(bCheckReloc)
		{
			while(1)
			{
				int32_t i32RVAofBlock = 0;
				int32_t i32SizeofBlock = 0;
				memcpy((void*)&i32RVAofBlock, (void*)&pBufReloc[i32RelocCnt], 4);
				i32RelocCnt += 4;
				memcpy((void*)&i32SizeofBlock, (void*)&pBufReloc[i32RelocCnt], 4);
				i32RelocCnt += 4;
				if(i32SizeofBlock == 0)
					break;

				int32_t i32SecionIdx = -1;

				for(int i = 0; i < vctSectionRva.size() - 1; i++)
				{
					int32_t i32FromRva = vctSectionRva[i].first;
					int32_t i32ToRva = vctSectionRva[i + 1].first;

					if(i32FromRva <= i32RVAofBlock && i32RVAofBlock < i32ToRva)
					{
						i32SecionIdx = i;
						break;
					}
				}
				int32_t i32BaseRelocationSize = i32SizeofBlock - 8;
				/*		if ((i32TextSection != i32SecionIdx) && (i32SecionIdx != i32CfgSection))
						{
							i32RelocCnt += i32BaseRelocationSize;
							continue;
						}*/
				for(int i = 0; i < i32BaseRelocationSize; i += 2)
				{
					int32_t i32Delta = i32BaseAddress - i32FileBaseAddress;
				/*	if (i32Delta > i32FileBaseAddress)
						i32Delta = i32Delta - i32FileBaseAddress;
					else
						i32Delta = i32FileBaseAddress - i32Delta;*/
					WORD TypeRva = 0;
					int32_t i32FileOffset = i32RVAofBlock - vctSectionRva[i32SecionIdx].first;

					memcpy((void*)&TypeRva, (void*)&pBufReloc[i32RelocCnt], 2);
					if(TypeRva == 0)
					{
						i32RelocCnt += 2;
						continue;
					}

					TypeRva &= 0x0fff;
					i32FileOffset += TypeRva + vctSectionRva[i32SecionIdx].second;

					int32_t i32MemoryOffset = 0;


					int32_t i32LoadOffset = 0;
					i32LoadOffset = TypeRva + i32RVAofBlock - i32RVA;

					/*	if (i32LoadOffset <= i32SizeOfCode)
						{
							for (int j = 0;j < 4;j++)
							{
								pBuf[i32LoadOffset + j] = ~pBuf[i32LoadOffset + j];
							}
						}*/

					memcpy((void*)&i32MemoryOffset, (void*)&buf[i32FileOffset], 4);

					i32MemoryOffset += i32Delta;

					vctCheck.push_back({ TypeRva,i32LoadOffset,i32MemoryOffset,i32FileOffset });
					//i32FileOffset += i32BaseAddress;
					//if (TypeRva + i32RVAofBlock - vctSectionRva[i32SecionIdx].first < i32SizeOfCode)
					memcpy((void*)&pBuf[i32LoadOffset], (void*)&i32MemoryOffset, 4);

					i32RelocCnt += 2;
				}


			}
		}
		int32_t i32Result = WriteProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32RVA), pBuf, i32SizeOfImageTemp, NULL);

		if(!i32Result)
		{
			OutputDebugStringA("WriteProcessMemory Decode Failed\n");
			if(pBuf != NULL)
				delete pBuf;
			if(pBufReloc != NULL)
				delete pBufReloc;
			if(buf != NULL)
				delete buf;
			//printf("error code: %d \n", GetLastError());
			return 1;
		}



		////int32_t i32SetPermission = (int32_t)VirtualAllocEx(hGetHandle, (PVOID)(i32BaseAddress-0x1000), 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//DWORD dwOld = 0;

		//NtProtectVirtualMemory(hGetHandle, (PVOID)(i32BaseAddress-0x1000),(PULONG)0x1000, PAGE_READWRITE, &dwOld);

		///*if(!i32SetPermission)
		//{
		//	printf("error code: %d \n", GetLastError());
		//	return 1;
		//}*/


		int32_t i32CheckFinishEncoding = cNtHeader->OptionalHeader.AddressOfEntryPoint + 0x478;//

		int32_t i32FinshEncoding = 1;

		i32Result = WriteProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32CheckFinishEncoding), (void*)&i32FinshEncoding, 4, NULL);

		if(!i32Result)//
		{
			OutputDebugStringA("WriteProcessMemory Loop Failed\n");
			if(pBuf != NULL)
				delete pBuf;
			if(pBufReloc != NULL)
				delete pBufReloc;
			if(buf != NULL)
				delete buf;
			//printf("error code: %d \n", GetLastError());
			return 1;
		}

		//int32_t i32EntryPointIdxAddress = cDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 0x10;

		//char cOEP[4] = { 0 };
		//memcpy((void*)&cOEP, (void*)&i32OEP, 4);

		//i32Result = WriteProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32EntryPointIdxAddress), cOEP, 4, NULL);

		//if(!i32Result)
		//{
		//	printf("error code: %d \n", GetLastError());
		//	return 1;
		//}
		//

		vctSectionRva.clear();
		dwBytesRead = 0;
		if(pBuf != NULL)
			delete pBuf;
		if(pBufReloc != NULL)
			delete pBufReloc;
		if(buf != NULL)
			delete buf;
	}

	//Sleep(5);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	return 1;
}

BOOL SetPrivilege(
	HANDLE hToken,  // token handle 
	LPCTSTR Privilege,  // Privilege to enable/disable 
	BOOL bEnablePrivilege  // TRUE to enable. FALSE to disable 
	)
{
	TOKEN_PRIVILEGES tp = { 0 };
	// Initialize everything to zero 
	LUID luid;
	DWORD cb = sizeof(TOKEN_PRIVILEGES);
	if(!LookupPrivilegeValue(NULL, Privilege, &luid))
		return FALSE;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if(bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}
	AdjustTokenPrivileges(hToken, FALSE, &tp, cb, NULL, NULL);
	if(GetLastError() != ERROR_SUCCESS)
		return FALSE;

	return TRUE;
}