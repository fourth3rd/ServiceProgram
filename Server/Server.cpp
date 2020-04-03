#include <winsock2.h>
#include <windows.h>
#include <tchar.h>
#include "ServiceInstaller.h"
#include "ServerService.h"

// 
// Settings of the service
// 

// Internal name of the service
#define SERVICE_NAME             L"FL Version Manager Server"

// Displayed name of the service
#define SERVICE_DISPLAY_NAME     L"FL Version Manager Server Service"

// Service start options.
#define SERVICE_START_TYPE       SERVICE_AUTO_START

// List of service dependencies - "dep1\0dep2\0\0"
#define SERVICE_DEPENDENCIES     L""

// The name of the account under which the service should run
#define SERVICE_ACCOUNT          L"NT AUTHORITY\\LocalService"

// The password to the service account name
#define SERVICE_PASSWORD         NULL

int _tmain(int argc, TCHAR *argv[])
{
	if((argc > 1) && ((*argv[1] == L'-' || (*argv[1] == L'/'))))
	{
		if(_tcsicmp(L"install", argv[1] + 1) == 0)
		{
			// Install the service when the command is 
			// "-install" or "/install".
			InstallService(
				SERVICE_NAME,               // Name of service
				SERVICE_DISPLAY_NAME,       // Name to display
				SERVICE_START_TYPE,         // Service start type
				SERVICE_DEPENDENCIES,       // Dependencies
				SERVICE_ACCOUNT,            // Service running account
				SERVICE_PASSWORD            // Password of the account
			);
		}
		else if(!_tcsicmp(L"remove", argv[1] + 1) ||
				!_tcsicmp(L"uninstall", argv[1] + 1))
		{
			// Uninstall the service when the command is 
			// "-remove" or "/remove".
			UninstallService(SERVICE_NAME);
		}
	}
	else
	{
		_tprintf(L"Parameters:\n");
		_tprintf(L" -install  to install the service.\n");
		_tprintf(L" -remove or -uninstall  to remove the service.\n");

		CServerService service(SERVICE_NAME);
		if(!CServiceBase::Run(service))
		{
			_tprintf(L"Service failed to run w/err 0x%08lx\n", GetLastError());
		}
	}

	return 0;
}