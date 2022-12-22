#include "utils.h"

int s_fclose(FILE* f) {
	
	if (!f || fclose(f)) {
		return 1;
	}

	return 0;
}

void *s_malloc(size_t sz) {
	uint8_t *p = malloc(sz);
	if (!p) {
		printf("[!!]\tCRITICAL: Error alocating %lu bytes\nExiting...\n", sz);
		exit(1);
	}
	assert(p != NULL);
	return p;
}

void print_hex(uint8_t *buffer, uint32_t sz) {
	for (uint32_t i = 0; i < sz; i++) {
		printf("%02X", buffer[i]);
	}
	printf("\n");
}

t_list* get_process_regions(HANDLE hProcess) {
	t_list* regions;
	t_region_info* region;
	MEMORY_BASIC_INFORMATION	mbi;
	LPVOID						offset;

	regions = NULL;
	offset = NULL;
	while (VirtualQueryEx(hProcess, offset, &mbi, sizeof(mbi)))
	{
		region = s_malloc(sizeof(t_region_info));
		offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
		region->base = mbi.BaseAddress;
		region->allocation = mbi.AllocationBase;
		region->protect = mbi.Protect;
		region->size = mbi.RegionSize;
		region->state = mbi.State;
		region->type = mbi.Type;
		lstadd_back(&regions, lstnew((void*)region));
	}
	return regions;
}

uint8_t *get_prot_str(DWORD prot) {
	switch (prot) {
		case PAGE_EXECUTE:
			return "PAGE_EXECUTE";
		case PAGE_EXECUTE_READ:
			return "PAGE_EXECUTE_READ";
		case PAGE_EXECUTE_READWRITE:
			return "PAGE_EXECUTE_READWRITE";
		case PAGE_EXECUTE_WRITECOPY:
			return "PAGE_EXECUTE_WRITECOPY";
		case PAGE_NOACCESS:
			return "PAGE_NOACCESS";
		case PAGE_READONLY:
			return "PAGE_READONLY";
		case PAGE_READWRITE:
			return "PAGE_READWRITE";
		case PAGE_WRITECOPY:
			return "PAGE_WRITECOPY";
		case PAGE_TARGETS_INVALID:
			return "PAGE_TARGETS_INVALID / PAGE_TARGETS_NO_UPDATE";
		case PAGE_GUARD:
			return "PAGE_GUARD";
		case PAGE_NOCACHE:
			return "PAGE_NOCACHE";
		case PAGE_WRITECOMBINE:
			return "PAGE_WRITECOMBINE";
		case PAGE_GUARD | PAGE_READWRITE:
			return "PAGE_GUARD | PAGE_READWRITE";
	}
	return "Private, uncommited";
}

uint8_t* get_time() {
	SYSTEMTIME	time;
	uint8_t		*s;

	s = s_malloc(10);
	s[9] = 0;
	GetSystemTime(&time);
	sprintf(s, "%02u:%02u:%02u", time.wHour, time.wMinute, time.wSecond);
	return s;
}

uint8_t* wide_to_str(wchar_t* s) {
	uint8_t* procname;
	int			bwritten;

	procname = s_malloc(wcslen(s));
	bwritten = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s,
		wcslen(s), procname,
		wcslen(s) + 1, NULL, NULL);
	if (!bwritten) {
		return NULL;
	}
	procname[bwritten] = 0;
	return procname;
}

HANDLE s_open_process(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD pid) {
	HANDLE hProc;

	hProc = OpenProcess(dwDesiredAccess, bInheritHandle, pid);
	if (!hProc) {
		printf("[!]\tError: Unable to open PID: %d, Error: %ld\n", pid, GetLastError());
		return NULL;
	}
	return hProc;
}