#include <core/include/process.hpp>
namespace Process {

	ULONG GetProcessIdByName(const char *name) {
		HEXANE;

		PROCESSENTRY32 entry = { };
		HANDLE snap = { };
		DWORD pid	= 0;

		entry.dwSize = sizeof(PROCESSENTRY32);

		snap = Ctx->win32.CreateToolhelp32Snapshot(0x02, 0);
		Ctx->win32.Process32First(snap, &entry);

		while (Ctx->win32.Process32Next(snap, &entry)) {
			if (MbsBoundCompare(name, entry.szExeFile, MbsLength(entry.szExeFile)) == 0) {
				pid = entry.th32ProcessID;
				break;
			}
		}

		defer:
		if (snap) { Ctx->nt.NtClose(snap); }
		return pid;
	}

	HANDLE OpenParentProcess(const char *name) {
		HEXANE;

        PROCESSENTRY32 entry = { };
		HANDLE process	= { };
		HANDLE snap		= { };

		entry.dwSize = sizeof(PROCESSENTRY32);

		snap = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		Ctx->win32.Process32First(snap, &entry);

		while (Ctx->win32.Process32Next(snap, &entry) == TRUE) {
			if (MbsBoundCompare((char*) name, entry.szExeFile, MbsLength(entry.szExeFile)) == 0) {
				x_ntassert(Process::NtOpenProcess(&process, PROCESS_ALL_ACCESS, entry.th32ProcessID));
				break;
			}
		}

		defer:
		if (snap) { Ctx->nt.NtClose(snap); }
		return process;
	}

	NTSTATUS NtOpenProcess(void **pp_process, uint32_t access, uint32_t pid) {
		HEXANE;

		OBJECT_ATTRIBUTES attrs = { };
		CLIENT_ID client		= { };

		client.UniqueProcess = (HANDLE) pid;
		client.UniqueThread = nullptr;

        InitializeObjectAttributes(&attrs, nullptr, 0, nullptr, nullptr);
		return Ctx->nt.NtOpenProcess(pp_process, access, &attrs, &client);
	}

	VOID CloseUserProcess(_executable *image) {
		HEXANE;

		if (image->attrs) 	{ Ctx->nt.RtlFreeHeap(image->heap, 0, image->attrs); image->attrs = nullptr; }
		if (image->heap) 	{ Ctx->nt.RtlDestroyHeap(image->heap); image->heap = nullptr; }
		if (image->params) 	{ Ctx->nt.RtlDestroyProcessParameters(image->params); image->params = nullptr; }
		if (image->handle) 	{ Ctx->nt.NtTerminateProcess(image->handle, ERROR_SUCCESS); }
	}

	VOID CreateUserProcess(_executable *image, const char *path) {
		HEXANE;

		LPWSTR w_name			= { };
		UNICODE_STRING u_name	= { };

		MbsToWcs(w_name, path, MbsLength(path));
		Ctx->nt.RtlInitUnicodeString(&u_name, w_name);

		image->create.Size 	= sizeof(image->create);
		image->create.State = PsCreateInitialState;

		image->heap 	= nullptr;
		image->params 	= nullptr;
		image->attrs 	= nullptr;

		//TODO: fix CreateUserProcess to not always create suspended
		Ctx->nt.RtlCreateProcessParametersEx(&image->params, &u_name, nullptr, DESKTOP_ENVIRONMENT_NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

		x_assert(image->heap 	= Ctx->nt.RtlCreateHeap(HEAP_GROWABLE, HEAP_NO_COMMIT));
		x_assert(image->attrs 	= (PPS_ATTRIBUTE_LIST) Ctx->nt.RtlAllocateHeap(image->heap, HEAP_ZERO_MEMORY, PS_ATTR_LIST_SIZE(1)));

		image->attrs->TotalLength 				= PS_ATTR_LIST_SIZE(1);
		image->attrs->Attributes[0].Attribute 	= PS_ATTRIBUTE_IMAGE_NAME;
		image->attrs->Attributes[0].Value 		= (ULONG_PTR) u_name.Buffer;
		image->attrs->Attributes[0].Size 		= u_name.Length;

		ntstatus = Ctx->nt.NtCreateUserProcess(&image->handle, &image->thread, PROCESS_CREATE_ALL_ACCESS_SUSPEND, image->params, &image->create, image->attrs);

		defer:
		if (ntstatus != ERROR_SUCCESS) {
			if (image->attrs) 	{ Ctx->nt.RtlFreeHeap(image->heap, 0, image->attrs); }
			if (image->heap) 	{ Ctx->nt.RtlDestroyHeap(image->heap); }
		}
	}
}
