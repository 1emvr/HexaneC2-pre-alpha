#include <core/corelib.hpp>
namespace Process {

	ULONG GetProcessIdByName(LPSTR proc) {

		HEXANE
		HANDLE hSnap = { };
		PROCESSENTRY32 entry = { };

		entry.dwSize = sizeof(PROCESSENTRY32);

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

	HANDLE LdrGetParentHandle(PBYTE Parent) {

		HEXANE
		HANDLE Proc = { };
		HANDLE Snap = { };
		CLIENT_ID Cid = { };
		PROCESSENTRY32 Entry = { };
		OBJECT_ATTRIBUTES Attr = { };

		Entry.dwSize = sizeof(PROCESSENTRY32);

		if (!(Snap = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))) {
			return nullptr;
		}

		if (Ctx->win32.Process32First(Snap, &Entry) == TRUE) {
			while (Ctx->win32.Process32Next(Snap, &Entry) == TRUE) {

				if (x_strcmp(Entry.szExeFile, RCAST(LPSTR, Parent)) == 0) {
					Cid.UniqueThread = nullptr;
					Cid.UniqueProcess = RCAST(HANDLE, Entry.th32ProcessID);

					InitializeObjectAttributes(&Attr, nullptr, 0, nullptr, nullptr);
					if (!NT_SUCCESS(Ctx->Nt.NtOpenProcess(&Proc, PROCESS_ALL_ACCESS, &Attr, &Cid))) {
						return nullptr;
					}

					break;
				}
			}
		}

		if (Snap) {
			Ctx->Nt.NtClose(Snap);
		}

		return Proc;
	}

	HANDLE NtOpenProcess(ULONG access, ULONG pid) {

		HEXANE
		HANDLE handle				= { };
		CLIENT_ID client			= { };
		OBJECT_ATTRIBUTES attrs     = { };

		InitializeObjectAttributes(&attrs, nullptr, 0, nullptr, nullptr);
		client.UniqueProcess = RCAST(HANDLE, pid);
		client.UniqueThread = nullptr;

		if (!NT_SUCCESS(Ctx->Nt.NtOpenProcess(&handle, access, &attrs, &client))) {
			return_defer(ntstatus);
		}

	defer:
		return handle;
	}

	VOID NtCloseUserProcess(PIMAGE proc) {

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

	VOID NtCreateUserProcess(PIMAGE proc, LPCSTR path) {

		HEXANE
		LPWSTR wName			= { };
		UNICODE_STRING uName	= { };

		x_mbstowcs(wName, path, x_strlen((PCHAR)path));
		Ctx->Nt.RtlInitUnicodeString(&uName, wName);

		proc->Create = {};
		proc->Create.Size = sizeof(proc->Create);
		proc->Create.State = PsCreateInitialState;

		proc->lpHeap = nullptr;
		proc->Params = nullptr;
		proc->Attrs = nullptr;

		if (
			!NT_SUCCESS(ntstatus = Ctx->Nt.RtlCreateProcessParametersEx(&proc->Params, &uName, nullptr, DESKTOP_ENVIRONMENT_NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED))) {
			return_defer(ntstatus);
		}
		if (
			!(proc->lpHeap = Ctx->Nt.RtlCreateHeap(HEAP_GROWABLE, HEAP_NO_COMMIT)) ||
			!(proc->Attrs = SCAST(PPS_ATTRIBUTE_LIST, Ctx->Nt.RtlAllocateHeap(proc->lpHeap, HEAP_ZERO_MEMORY, PS_ATTR_LIST_SIZE(1))))) {
			return_defer(ERROR_NOT_ENOUGH_MEMORY);
		}

		proc->Attrs->TotalLength = PS_ATTR_LIST_SIZE(1);
		proc->Attrs->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
		proc->Attrs->Attributes[0].Value = RCAST(ULONG_PTR, uName.Buffer);
		proc->Attrs->Attributes[0].Size = uName.Length;

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
