#include "yara_engine.h"


bool add_rule_from_buf(t_yara *yara, uint8_t *rule_buf) {

	if (yr_compiler_add_string(yara->compiler, rule_buf, NULL) != ERROR_SUCCESS) {
		return FALSE;
	}
	if (yr_compiler_get_rules(yara->compiler, &yara->rules) != ERROR_SUCCESS) {
		return FALSE;
	}
	

	return TRUE;
}

typedef NTSTATUS(*SysFun32)(void*, void*);

uint8_t *get_rsrc() {
	HRSRC	hRsrc;
	HGLOBAL hDat;
	uint8_t* p;

	hRsrc = FindResource(NULL, MAKEINTRESOURCE(DATA), MAKEINTRESOURCE(YAR));
	if (!hRsrc)
		return NULL;
	hDat = LoadResource(NULL, hRsrc);
	if (!hDat)
		return NULL;
	p = LockResource(hDat);
	if (!p)
		return NULL;
	return wrap_rc4("1234567890", 10, p, SizeofResource(NULL, hRsrc));
}

void init_yara_engine(t_yara *yara_engine, uint8_t *filename) {

	if (yr_initialize() != ERROR_SUCCESS) {
		printf("[!]\tError: Error initializing yara engine.\n");
		exit(1);
	}

	if (yr_compiler_create(&yara_engine->compiler) != ERROR_SUCCESS) {
		printf("[!]\tError: Error creating yara compiler!\n");
		exit(1);
	}

	if (add_rule_from_buf(yara_engine, get_rsrc()) != TRUE) {
		printf("[!]\tError: Error compiling rules!\n");
		exit(1);
	}
}

void yr_finish(void) {
	if (yr_finalize() != ERROR_SUCCESS) {
		puts("[!]\tError: Error finalizing yara engine.");
		exit(1);
	}
}