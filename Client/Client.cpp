#include "Client.h"

#include <stdio.h>
#include <tchar.h>
#include <WinSock2.h>
#include <atlconv.h>

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
					  _In_opt_ HINSTANCE hPrevInstance,
					  _In_ LPWSTR    lpCmdLine,
					  _In_ int       nCmdShow)
{
	int nReturn = 1;

	USES_CONVERSION;

	SOCKET hSocket = 0;
	FILE* fp1 = nullptr;
	FILE* fp2 = nullptr;

	wchar_t* pStrFileVersion			= L"  FILEVERSION       ";
	wchar_t* pStrProductVersion			= L"  PRODUCTVERSION    ";
	wchar_t* pStrStringFileVersion		= L"            VALUE \"FileVersion\",     ";
	wchar_t* pStrStringProductVersion	= L"            VALUE \"ProductVersion\",  ";

	LPWSTR* pArgv = nullptr;
	int argc = 0;
	pArgv = CommandLineToArgvW(GetCommandLineW(), &argc);

	do
	{
		wchar_t* pModuleName = pArgv[1];
		wchar_t* pTargetVersionPos = pArgv[2];
		wchar_t* pSolutionDir = pArgv[3];

		// test
// 		argc = 4;
// 		pModuleName = L"FLBase";
// 		pTargetVersionPos = L"3";
// 		pSolutionDir = L"C:\\FL\\Dev\\";
		//////////////////////////////////////////////////////////////////////////

		if(argc != 4)
			break;

		if(!pModuleName || !wcslen(pModuleName))
			break;

		if(!pTargetVersionPos || !wcslen(pTargetVersionPos))
			break;

		if(!pSolutionDir || !wcslen(pSolutionDir))
			break;

		WSADATA	wsaData;

		if(::WSAStartup(MAKEWORD(2, 2), &wsaData))
			break;

		SOCKADDR_IN servAddr;
		servAddr.sin_family = AF_INET;
		servAddr.sin_addr.s_addr = GetIPAddr("fourthlogic.co.kr");
		servAddr.sin_port = ::htons(32548);

		hSocket = ::socket(AF_INET, SOCK_STREAM, 0);

		if(connect(hSocket, (SOCKADDR*)&servAddr, sizeof(servAddr)) == SOCKET_ERROR)
			break;

		wchar_t buf[100000];
		char buf2[1000];
		wchar_t buf3[1000];

		wcscpy(buf, pModuleName);
		wcscat(buf, L" ");
		wcscat(buf, pTargetVersionPos);

		int nResult = send(hSocket, W2A(buf), (int)wcslen(buf) + 1, 0);

		if(nResult <= 0)
			break;

		nResult = recv(hSocket, buf2, 1000, 0);

		if(nResult <= 0)
			break;

		long arrVersion[4];
		memcpy(arrVersion, buf2, sizeof(arrVersion));

		wchar_t arrStringVersion[1000];
		wsprintf(arrStringVersion, L"%d.%d.%d.%d", arrVersion[0], arrVersion[1], arrVersion[2], arrVersion[3]);

		wchar_t strRCFile[1000], strRCFileTemp[1000];
		
		wcscpy(strRCFile, pSolutionDir);
		
		if(strRCFile[wcslen(strRCFile)-1] != L'\\')
			wcscat(strRCFile, L"\\");

		wcscat(strRCFile, pModuleName);
		wcscat(strRCFile, L"\\res\\");
		wcscat(strRCFile, pModuleName);
		wcscat(strRCFile, L".rc2");

		wcscpy(strRCFileTemp, strRCFile);
		wcscat(strRCFileTemp, L".tmp");

		fp1 = _wfopen(strRCFile, L"rb");

		if(!fp1)
			break;

		fp2 = _wfopen(strRCFileTemp, L"wb");

		if(!fp2)
			break;

		fseek(fp1, 0, SEEK_SET);
		fseek(fp2, 0, SEEK_SET);

		memset(buf,0,sizeof(buf));
		int nRead = (int)fread(buf, 2, 50000, fp1);

		int index = 0;
		while(buf[index])
		{
			int i = index;

			while(buf[index] && buf[index] != L'\n')
				++index;

			if(!buf[index])
				break;

			++index;

			int nlength = index-i;

			memset(buf3, 0, sizeof(buf3));
			memcpy(buf3, &buf[i], nlength*sizeof(wchar_t));

			int kkk = 0; 

			if(!memcmp(buf3, pStrFileVersion, wcslen(pStrFileVersion) * sizeof(wchar_t)))
			{
				wcscpy(buf3, pStrFileVersion);
				wcscat(buf3, arrStringVersion);
				wcscat(buf3, L"\r\n");
			}
			else if(!memcmp(buf3, pStrProductVersion, wcslen(pStrProductVersion) * sizeof(wchar_t)))
			{
				wcscpy(buf3, pStrProductVersion);
				wcscat(buf3, arrStringVersion);
				wcscat(buf3, L"\r\n");
			}
			else if(!memcmp(buf3, pStrStringFileVersion, wcslen(pStrStringFileVersion) * sizeof(wchar_t)))
			{
				wcscpy(buf3, pStrStringFileVersion);
				wcscat(buf3, L"\"");
				wcscat(buf3, arrStringVersion);
				wcscat(buf3, L"\"");
				wcscat(buf3, L"\r\n");
			}
			else if(!memcmp(buf3, pStrStringProductVersion, wcslen(pStrStringProductVersion) * sizeof(wchar_t)))
			{
				wcscpy(buf3, pStrStringProductVersion);
				wcscat(buf3, L"\"");
				wcscat(buf3, arrStringVersion);
				wcscat(buf3, L"\"");
				wcscat(buf3, L"\r\n");
			}
			fwrite(buf3, 2, wcslen(buf3), fp2);
		}

		fclose(fp1);
		fclose(fp2);

		DWORD dwBackup = GetFileAttributes(strRCFile);

		if(!SetFileAttributes(strRCFile, FILE_ATTRIBUTE_NORMAL))
			break;

		if(!::MoveFileEx(strRCFileTemp, strRCFile, MOVEFILE_REPLACE_EXISTING))
			break;

		if(!SetFileAttributes(strRCFile, dwBackup))
			break;

		nReturn = 0;
	}
	while(false);

	if(hSocket)
		closesocket(hSocket);

	if(fp1)
	{
		fclose(fp1);
		fp1 = nullptr;
	}

	if(fp2)
	{
		fclose(fp2);
		fp2 = nullptr;
	}

	return nReturn;
}

long GetIPAddr(const char *host_name)
{
	struct hostent *host_entry;
	long host_ip = 0;

	if((host_ip = inet_addr(host_name)) == -1)
	{
		host_entry = gethostbyname(host_name);
		if(host_entry != NULL)
			host_ip = *((unsigned long *)(host_entry->h_addr_list[0]));
	}

	return host_ip;
}