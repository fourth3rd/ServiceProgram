#include "ServerService.h"
#include "ThreadPool.h"

#include <errno.h>
#include <process.h>
#include <direct.h>

CServerService::CServerService(PWSTR pszServiceName, bool bCanStop, bool bCanShutdown, bool bCanPauseContinue) : CServiceBase(pszServiceName, bCanStop, bCanShutdown, bCanPauseContinue)
{
	m_hStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if(m_hStoppedEvent == NULL)
		throw GetLastError();
}

CServerService::~CServerService()
{
}

void CServerService::OnStart(DWORD dwArgc, PWSTR *pszArgv)
{
	bool bResult = false;

	do
	{
		////////////////////////////////////////////////////////////////////////////////////
		// 요기 아래에 코딩

		OutputDebugStringA("OnStart");

		bResult = true;

		////////////////////////////////////////////////////////////////////////////////////
	}
	while(false);


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




		////////////////////////////////////////////////////////////////////////////////////

		Sleep(1);
	}

	OutputDebugStringA("End WorkThread");

	// Signal the stopped event.
	SetEvent(m_hStoppedEvent);
}
