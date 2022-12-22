#pragma once
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <winnt.h>
#include <stdlib.h>
#include <crtdbg.h>
#include <yara.h>
#include <stdint.h>
#include <winbase.h>
#include "utils.h"
#include "resource.h"

typedef struct s_yara {
	YR_COMPILER *compiler;
	YR_RULES	*rules;
}t_yara;

typedef struct s_yara_info {
	void *p;
}t_yara_info;

void yr_finish(void);
void init_yara_engine(t_yara *yara_engine, uint8_t *filename);