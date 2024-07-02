#include <core/include/process.hpp>
namespace Process {

	DWORD GetProcessIdByName (LPSTR proc) {
		HEXANE

		HANDLE hSnap 			= { };
		PROCESSENTRY32 entry 	= { };
		entry.dwSize 			= sizeof(PROCESSENTRY32);

		if (!(hSnap = Ctx->win32.CreateToolhelp32Snapshot(0x02, 0))) {
			return_defer(ERROR_INVALID_HANDLE);
		}

		if (Ctx->win32.Process32First(hSnap, &entry) == TRUE) {
			while (Ctx->win32.Process32Next(hSnap, &entry) == TRUE) {
				if (x_strcmp(proc, entry.szExeFile) == 0) {

					Ctx->Nt.NtClose(hSnap);
					return entry.th32ProcessID;
				}
			}
		}
		defer:
		if (hSnap) {
			Ctx->Nt.NtClose(hSnap);
		}
		return 0;
	}

	HANDLE NtOpenProcess (DWORD access, DWORD pid) {
		HEXANE

		HANDLE handle			= { };
		CLIENT_ID client 		= { };
		OBJECT_ATTRIBUTES attrs = { };

		InitializeObjectAttributes(&attrs, nullptr, 0, nullptr, nullptr);
		client.UniqueProcess 	= (HANDLE)pid;
		client.UniqueThread 	= nullptr;

		if (!NT_SUCCESS(Ctx->Nt.NtOpenProcess(&handle, access, &attrs, &client))) {
			return_defer(ntstatus);
		}

		defer:
		return handle;
	}

	VOID NtCloseUserProcess (PIMAGE proc) {
		HEXANE

		if (proc->Attrs) {
			Ctx->Nt.RtlFreeHeap(proc->lpHeap, 0, proc->Attrs);
			proc->Attrs = nullptr;
		}
		if (proc->lpHeap) {
			Ctx->Nt.RtlDestroyHeap(proc->lpHeap);
			proc->lpHeap = nullptr;
		}
		if (proc->Params) {
			Ctx->Nt.RtlDestroyProcessParameters(proc->Params);
			proc->Params = nullptr;
		}
		if (proc->pHandle) {
			Ctx->Nt.NtTerminateProcess(proc->pHandle, ERROR_SUCCESS);
		}
	}

	VOID NtCreateUserProcess (PIMAGE proc, PCHAR path) {
		HEXANE

		PWCHAR wName 			= {0};
		UNICODE_STRING uName 	= {0};

		x_mbstowcs(wName, path, x_strlen(path));
		Ctx->Nt.RtlInitUnicodeString(&uName, wName);

		proc->Create = { };
		proc->Create.Size 	= sizeof(proc->Create);
		proc->Create.State 	= PsCreateInitialState;

		proc->lpHeap 	= nullptr;
		proc->Params 	= nullptr;
		proc->Attrs 	= nullptr;

		if (
			!NT_SUCCESS(ntstatus = Ctx->Nt.RtlCreateProcessParametersEx(&proc->Params, &uName, nullptr, DESKTOP_ENVIRONMENT_NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED))) {
			return_defer(ntstatus);
		}
		if (
			!(proc->lpHeap 	= Ctx->Nt.RtlCreateHeap(HEAP_GROWABLE, HEAP_NO_COMMIT)) ||
			!(proc->Attrs 	= (PPS_ATTRIBUTE_LIST) Ctx->Nt.RtlAllocateHeap(proc->lpHeap, HEAP_ZERO_MEMORY, PS_ATTR_LIST_SIZE(1)))) {
			return_defer(ERROR_NOT_ENOUGH_MEMORY);
		}

		proc->Attrs->TotalLength 				= PS_ATTR_LIST_SIZE(1);
		proc->Attrs->Attributes[0].Attribute 	= PS_ATTRIBUTE_IMAGE_NAME;
		proc->Attrs->Attributes[0].Value 		= (ULONG_PTR)uName.Buffer;
		proc->Attrs->Attributes[0].Size 		= uName.Length;

		ntstatus = Ctx->Nt.NtCreateUserProcess(&proc->pHandle, &proc->pThread, PROCESS_CREATE_ALL_ACCESS_SUSPEND, proc->Params, &proc->Create, proc->Attrs);

		defer:
		if (ntstatus != ERROR_SUCCESS) {
			if (proc->Attrs) {
				Ctx->Nt.RtlFreeHeap(proc->lpHeap, 0, proc->Attrs);
			}
			if (proc->lpHeap) {
				Ctx->Nt.RtlDestroyHeap(proc->lpHeap);
			}
		}
	}
}
