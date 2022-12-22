#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "utils.h"


//Call this to encrypt
uint8_t* wrap_rc4(uint8_t* key, uint64_t kl, uint8_t* data, uint64_t dl);

typedef struct s_rc4 {
	uint8_t			S[256];
	uint32_t		i;
	uint32_t		j;
} t_rc4;