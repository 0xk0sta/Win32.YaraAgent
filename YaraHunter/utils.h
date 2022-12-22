#pragma once
#include <Windows.h>
#include <malloc.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "list.h"

typedef struct s_region_info {
	DWORD* base;
	DWORD* allocation;
	DWORD	protect;
	size_t	size;
	DWORD	state;
	DWORD	type;
} t_region_info;

int			s_fclose(FILE* f);
void		*s_malloc(size_t sz);
void		print_hex(uint8_t *buffer, uint32_t sz);
uint8_t		*get_prot_str(DWORD prot);
t_list		*get_process_regions(HANDLE hProcess);
uint8_t*	get_time();
uint8_t*	wide_to_str(wchar_t* s);
HANDLE		s_open_process(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD pid);