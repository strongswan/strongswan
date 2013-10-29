/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <library.h>
#include <hydra.h>
#include <daemon.h>

#include <utils/backtrace.h>
#include <threading/thread.h>

/**
 * The name of our service, both internal and external
 */
#define SERVICE_NAME "charon-svc"

/**
 * Current service status
 */
static SERVICE_STATUS status;

/**
 * Handle for service status
 */
static SERVICE_STATUS_HANDLE handle;

/**
 * Wait event for main thread
 */
static HANDLE event;

/**
 * hook in library for debugging messages
 */
extern void (*dbg) (debug_t group, level_t level, char *fmt, ...);

/**
 * Logging hook for library logs, using stderr output
 */
static void dbg_stderr(debug_t group, level_t level, char *fmt, ...)
{
	va_list args;

	if (level <= 1)
	{
		va_start(args, fmt);
		fprintf(stderr, "00[%N] ", debug_names, group);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
}

/**
 * Log strongSwan/Windows version during startup
 */
static void print_version()
{
	OSVERSIONINFOEX osvie;

	memset(&osvie, 0, sizeof(osvie));
	osvie.dwOSVersionInfoSize = sizeof(osvie);

	if (GetVersionEx((LPOSVERSIONINFO)&osvie))
	{
		DBG1(DBG_DMN, "Starting IKE service %s (strongSwan %s, "
			 "Windows %s %d.%d.%d (SP %d.%d)", SERVICE_NAME, VERSION,
			 osvie.wProductType == VER_NT_WORKSTATION ? "Client" : "Server",
			 osvie.dwMajorVersion, osvie.dwMinorVersion, osvie.dwBuildNumber,
			 osvie.wServicePackMajor, osvie.wServicePackMinor);
	}
}

/**
 * Update service state to SCM, increase check point if state didn't change
 */
static void update_status(DWORD state)
{
	if (state == status.dwCurrentState)
	{
		status.dwCheckPoint++;
	}
	else
	{
		status.dwCheckPoint = 0;
	}
	status.dwCurrentState = state;
	if (handle)
	{
		SetServiceStatus(handle, &status);
	}
}

/**
 * Initialize and run charon
 */
static void init_and_run(DWORD dwArgc, LPTSTR *lpszArgv)
{
	level_t levels[DBG_MAX];
	int i;

	for (i = 0; i < DBG_MAX; i++)
	{
		levels[i] = LEVEL_CTRL;
	}

	update_status(SERVICE_START_PENDING);
	event = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (event)
	{
		update_status(SERVICE_START_PENDING);
		if (library_init(NULL, SERVICE_NAME))
		{
			update_status(SERVICE_START_PENDING);
			if (libhydra_init())
			{
				update_status(SERVICE_START_PENDING);
				if (libcharon_init())
				{
					charon->load_loggers(charon, levels, TRUE);
					print_version();
					update_status(SERVICE_START_PENDING);
					if (charon->initialize(charon, PLUGINS))
					{
						update_status(SERVICE_START_PENDING);
						lib->plugins->status(lib->plugins, LEVEL_CTRL);

						charon->start(charon);

						status.dwWin32ExitCode = 0;
						update_status(SERVICE_RUNNING);

						/* main thread goes to sleep */
						WaitForSingleObjectEx(event, INFINITE, TRUE);
					}
					update_status(SERVICE_STOP_PENDING);
					libcharon_deinit();
				}
				update_status(SERVICE_STOP_PENDING);
				libhydra_deinit();
			}
			update_status(SERVICE_STOP_PENDING);
			library_deinit();
		}
		update_status(SERVICE_STOP_PENDING);
		CloseHandle(event);
	}
	update_status(SERVICE_STOPPED);
}

/**
 * Control handler for console
 */
static BOOL console_handler(DWORD dwCtrlType)
{
	switch (dwCtrlType)
	{
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
			DBG1(DBG_DMN, "application is stopping, cleaning up");
			charon->bus->alert(charon->bus, ALERT_SHUTDOWN_SIGNAL, dwCtrlType);
			/* signal main thread to clean up */
			SetEvent(event);
			return TRUE;
		default:
			return FALSE;
	}
}

/**
 * Main routine when running from console
 */
static void console_main(DWORD dwArgc, LPTSTR *lpszArgv)
{
	status.dwWin32ExitCode = 1;

	if (SetConsoleCtrlHandler(console_handler, TRUE))
	{
		init_and_run(dwArgc, lpszArgv);
		SetConsoleCtrlHandler(console_handler, FALSE);
	}
}

/**
 * Service handler function
 */
static DWORD service_handler(DWORD dwControl, DWORD dwEventType,
							 LPVOID lpEventData, LPVOID lpContext)
{
	switch (dwControl)
	{
		case SERVICE_CONTROL_STOP:
		case SERVICE_CONTROL_SHUTDOWN:
			DBG1(DBG_DMN, "service is stopping, cleaning up");
			charon->bus->alert(charon->bus, ALERT_SHUTDOWN_SIGNAL, dwControl);
			/* signal main thread to clean up */
			SetEvent(event);
			return NO_ERROR;
		case SERVICE_CONTROL_INTERROGATE:
			return NO_ERROR;
		default:
			return ERROR_CALL_NOT_IMPLEMENTED;
	}
}

/**
 * Service main routine when running as service
 */
static void service_main(DWORD dwArgc, LPTSTR *lpszArgv)
{
	memset(&status, 0, sizeof(status));
	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	status.dwWin32ExitCode = 1;

	handle = RegisterServiceCtrlHandlerEx(SERVICE_NAME, service_handler, NULL);
	if (handle)
	{
		init_and_run(dwArgc, lpszArgv);
	}
}

/**
 * Main function, starts the service
 */
int main(int argc, char *argv[])
{
	SERVICE_TABLE_ENTRY services[] = {
		{
			.lpServiceName = SERVICE_NAME,
			.lpServiceProc = service_main,
		},
		{ NULL, NULL },
	};
	DWORD err;

	dbg = dbg_stderr;

	if (!StartServiceCtrlDispatcher(services))
	{
		err = GetLastError();
		if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
		{
			console_main(argc, argv);
		}
		else
		{
			return 2;
		}
	}
	return status.dwWin32ExitCode;
}
