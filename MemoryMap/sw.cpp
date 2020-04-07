#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
//#pragma comment(lib, "user32.lib")

#define PipeName L"\\\\.\\pipe\\FLProtectionPipe123123"
#define BUF_SIZE 256
wchar_t szName[] =L"Global\\MyFileMappingObject";

int _tmain()
{


	HANDLE hPipe;//

	TCHAR readDataBuf[BUF_SIZE + 1] = { 0, };

	while(1)
	{
		hPipe = CreateFile(PipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

		if(hPipe != INVALID_HANDLE_VALUE)
			break;

		if(GetLastError() != ERROR_PIPE_BUSY)
		{
			printf("Could not open pipe\n");
			return 0;
		}

		if(!WaitNamedPipe(PipeName, 20000))
		{
			printf("Could not topen pipe\n");
			return 0;
		}
	}

//	WaitNamedPipe(PipeName,NMPWAIT_WAIT_FOREVER);

	//DWORD pipeMode = PIPE_TYPE_BYTE;
	//BOOL isSuccess = SetNamedPipeHandleState(hPipe, &pipeMode, NULL, NULL);

	//if(!isSuccess)
	//{
	//	printf("SetNamedPipeHandleState Failed!\n");
	//}

	DWORD bytesRead = 0;

	DWORD dwBytesWritten = 8;

	DWORD dwProcessId = GetCurrentProcessId();

	char SendBuf[BUF_SIZE] = { "Pipe Communication Success"};

	WriteFile(hPipe, SendBuf, BUF_SIZE, &dwBytesWritten, NULL);

	CloseHandle(hPipe);
	return 0;

    //HANDLE hMapFile;
    //LPCTSTR pBuf;

    //hMapFile = OpenFileMapping(
    //    FILE_MAP_READ | FILE_MAP_WRITE,   // read/write access
    //    FALSE,                 // do not inherit the name
    //    szName);               // name of mapping object

    //if(hMapFile == NULL)
    //{
    //    printf("Could not open file mapping object (%d).\n", GetLastError());
    //    return 1;
    //}

    //pBuf = (LPTSTR)MapViewOfFile(hMapFile, // handle to map object
    //                             FILE_MAP_ALL_ACCESS,  // read/write permission
    //                             0,
    //                             0,
    //                             BUF_SIZE);

    //if(pBuf == NULL)
    //{
    //    printf("Could not map view of file (%d).\n", GetLastError());

    //    CloseHandle(hMapFile);

    //    return 1;
    //}

    //MessageBox(NULL, pBuf, TEXT("Process2"), MB_OK);

    //UnmapViewOfFile(pBuf);

    //CloseHandle(hMapFile);

    //return 0;
}