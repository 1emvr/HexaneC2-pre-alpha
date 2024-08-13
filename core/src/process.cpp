#include <core/include/process.hpp>
namespace Process {
	ULONG GetProcessIdByName(const char *const name) {
		HEXANE

		HANDLE hSnap = { };
		PROCESSENTRY32 entry = { };

		entry.dwSize = sizeof(PROCESSENTRY32);

		if (!(hSnap = Ctx->win32.CreateToolhelp32Snapshot(0x02, 0))) {
			return_defer(ERROR_INVALID_HANDLE);
		}

		if (Ctx->win32.Process32First(hSnap, &entry)) {
			while (Ctx->win32.Process32Next(hSnap, &entry)) {

				if (x_strncmp(name, entry.szExeFile, x_strlen(entry.szExeFile)) == 0) {
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

	HANDLE OpenParentProcess(const char *const name) {
		HEXANE

        PROCESSENTRY32 entry = { };
		HANDLE process = { };
		HANDLE snap = { };

		entry.dwSize = sizeof(PROCESSENTRY32);
		if (!(snap = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))) {
			return nullptr;
		}

		if (Ctx->win32.Process32First(snap, &entry) == TRUE) {
			while (Ctx->win32.Process32Next(snap, &entry) == TRUE) {

				if (x_strncmp(name, entry.szExeFile, x_strlen(entry.szExeFile)) == 0) {
					if (!NT_SUCCESS(Process::NtOpenProcess(&process, PROCESS_ALL_ACCESS, entry.th32ProcessID))) {
						return nullptr;
					}
					break;
				}
			}
		}
		if (snap) {
			Ctx->Nt.NtClose(snap);
		}

		return process;
	}

	NTSTATUS NtOpenProcess(void **pp_process, const uint32_t access, const uint32_t pid) {
		HEXANE

		CLIENT_ID client			= { };
		OBJECT_ATTRIBUTES attrs     = { };

		client.UniqueProcess = R_CAST(HANDLE, pid);
		client.UniqueThread = nullptr;

        InitializeObjectAttributes(&attrs, nullptr, 0, nullptr, nullptr);
		return Ctx->Nt.NtOpenProcess(pp_process, access, &attrs, &client);
	}

	VOID NtCloseUserProcess(_executable *const image) {
		HEXANE

		if (image->Attrs) {
			Ctx->Nt.RtlFreeHeap(image->lpHeap, 0, image->Attrs);
			image->Attrs = nullptr;
		}
		if (image->lpHeap) {
			Ctx->Nt.RtlDestroyHeap(image->lpHeap);
			image->lpHeap = nullptr;
		}
		if (image->Params) {
			Ctx->Nt.RtlDestroyProcessParameters(image->Params);
			image->Params = nullptr;
		}
		if (image->pHandle) {
			Ctx->Nt.NtTerminateProcess(image->pHandle, ERROR_SUCCESS);
		}
	}

	VOID NtCreateUserProcess(_executable *const image, const char *const path) {
		HEXANE

		LPWSTR w_name = { };
		UNICODE_STRING u_name = { };

		x_mbstowcs(w_name, path, x_strlen(path));
		Ctx->Nt.RtlInitUnicodeString(&u_name, w_name);

		image->Create = { };
		image->Create.Size = sizeof(image->Create);
		image->Create.State = PsCreateInitialState;

		image->lpHeap = nullptr;
		image->Params = nullptr;
		image->Attrs = nullptr;

		if (!NT_SUCCESS(ntstatus = Ctx->Nt.RtlCreateProcessParametersEx(&image->Params, &u_name, nullptr, DESKTOP_ENVIRONMENT_NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED))) {
			return_defer(ntstatus);
		}

		if (
			!(image->lpHeap = Ctx->Nt.RtlCreateHeap(HEAP_GROWABLE, HEAP_NO_COMMIT)) ||
			!(image->Attrs = S_CAST(PPS_ATTRIBUTE_LIST, Ctx->Nt.RtlAllocateHeap(image->lpHeap, HEAP_ZERO_MEMORY, PS_ATTR_LIST_SIZE(1))))) {
			return_defer(ERROR_NOT_ENOUGH_MEMORY);
		}

		image->Attrs->TotalLength 				= PS_ATTR_LIST_SIZE(1);
		image->Attrs->Attributes[0].Attribute 	= PS_ATTRIBUTE_IMAGE_NAME;
		image->Attrs->Attributes[0].Value 		= R_CAST(ULONG_PTR, u_name.Buffer);
		image->Attrs->Attributes[0].Size 		= u_name.Length;

		ntstatus = Ctx->Nt.NtCreateUserProcess(&image->pHandle, &image->pThread, PROCESS_CREATE_ALL_ACCESS_SUSPEND, image->Params, &image->Create, image->Attrs);

	defer:
		if (!NT_SUCCESS(ntstatus)) {
			if (image->Attrs) {
				Ctx->Nt.RtlFreeHeap(image->lpHeap, 0, image->Attrs);
			}
			if (image->lpHeap) {
				Ctx->Nt.RtlDestroyHeap(image->lpHeap);
			}
		}
	}
}