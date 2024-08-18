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
					Ctx->nt.NtClose(hSnap);
					return entry.th32ProcessID;
				}
			}
		}

		defer:
		if (hSnap) {
			Ctx->nt.NtClose(hSnap);
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
			Ctx->nt.NtClose(snap);
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
		return Ctx->nt.NtOpenProcess(pp_process, access, &attrs, &client);
	}

	VOID CloseUserProcess(_executable *const image) {
		HEXANE

		if (image->attrs) {
			Ctx->nt.RtlFreeHeap(image->heap, 0, image->attrs);
			image->attrs = nullptr;
		}
		if (image->heap) {
			Ctx->nt.RtlDestroyHeap(image->heap);
			image->heap = nullptr;
		}
		if (image->params) {
			Ctx->nt.RtlDestroyProcessParameters(image->params);
			image->params = nullptr;
		}
		if (image->handle) {
			Ctx->nt.NtTerminateProcess(image->handle, ERROR_SUCCESS);
		}
	}

	VOID CreateUserProcess(_executable *const image, const char *const path) {
		HEXANE

		LPWSTR w_name = { };
		UNICODE_STRING u_name = { };

		x_mbstowcs(w_name, path, x_strlen(path));
		Ctx->nt.RtlInitUnicodeString(&u_name, w_name);

		image->create = { };
		image->create.Size = sizeof(image->create);
		image->create.State = PsCreateInitialState;

		image->heap = nullptr;
		image->params = nullptr;
		image->attrs = nullptr;

		//TODO: fix this to not always create suspended
		if (!NT_SUCCESS(ntstatus = Ctx->nt.RtlCreateProcessParametersEx(&image->params, &u_name, nullptr, DESKTOP_ENVIRONMENT_NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED))) {
			return_defer(ntstatus);
		}

		if (
			!(image->heap = Ctx->nt.RtlCreateHeap(HEAP_GROWABLE, HEAP_NO_COMMIT)) ||
			!(image->attrs = S_CAST(PPS_ATTRIBUTE_LIST, Ctx->nt.RtlAllocateHeap(image->heap, HEAP_ZERO_MEMORY, PS_ATTR_LIST_SIZE(1))))) {
			return_defer(ERROR_NOT_ENOUGH_MEMORY);
		}

		image->attrs->TotalLength 				= PS_ATTR_LIST_SIZE(1);
		image->attrs->Attributes[0].Attribute 	= PS_ATTRIBUTE_IMAGE_NAME;
		image->attrs->Attributes[0].Value 		= R_CAST(ULONG_PTR, u_name.Buffer);
		image->attrs->Attributes[0].Size 		= u_name.Length;

		ntstatus = Ctx->nt.NtCreateUserProcess(&image->handle, &image->thread, PROCESS_CREATE_ALL_ACCESS_SUSPEND, image->params, &image->create, image->attrs);

	defer:
		if (ntstatus != ERROR_SUCCESS) {
			if (image->attrs) {
				Ctx->nt.RtlFreeHeap(image->heap, 0, image->attrs);
			}
			if (image->heap) {
				Ctx->nt.RtlDestroyHeap(image->heap);
			}
		}
	}
}