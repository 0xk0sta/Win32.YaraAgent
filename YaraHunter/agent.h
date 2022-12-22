#pragma once
#include <Windows.h>
#include <winnt.h>
#include <tlhelp32.h>
#include <stringapiset.h>
#include <yara.h>
#include "list.h"
#include "utils.h"
#include "yara_engine.h"
#define HUNDREDMB 104857600 

typedef struct s_udata {
	uint8_t* procname;
	DWORD* base;
	DWORD	pid;
} t_udata;

void	cb_proc_scan(HANDLE hProc, t_udata* psi, void* yara_engine);
void	deploy_agent();