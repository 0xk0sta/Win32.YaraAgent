#include "rc4.h"

void swap(t_rc4* rc4) {
	uint8_t temp;

	temp = rc4->S[rc4->i];
	rc4->S[rc4->i] = rc4->S[rc4->j];
	rc4->S[rc4->j] = temp;
}

void rc4_init_stream(t_rc4* rc4) {
	for (rc4->i = 0; rc4->i < 256; rc4->i++) {
		rc4->S[rc4->i] = rc4->i;
	}
}

void rc4_setup_keystream(t_rc4* rc4, uint8_t* key, uint64_t kl) {
	for (rc4->i = rc4->j = 0; rc4->i < 256; rc4->i++) {
		rc4->j = (rc4->j + key[rc4->i % kl] + rc4->S[rc4->i]) & 0xff;
		swap(rc4);
	}
	rc4->i = rc4->j = 0;
}

uint8_t rc4_prga(t_rc4* rc4) {
	rc4->i = (rc4->i + 1) & 255;
	rc4->j = (rc4->j + rc4->S[rc4->i]) & 255;

	swap(rc4);

	return rc4->S[(rc4->S[rc4->i] + rc4->S[rc4->j]) & 255];
}

uint8_t* rc4_encode(t_rc4* rc4, uint8_t* in_buf, uint64_t in_len) {
	uint8_t* outbuf;

	outbuf = s_malloc((size_t)in_len);
	for (uint64_t i = 0; i < in_len; i++) {
		*(outbuf + i) = *(in_buf + i) ^ rc4_prga(rc4);
	}

	return outbuf;
}

uint8_t* wrap_rc4(uint8_t* key, uint64_t kl, uint8_t* data, uint64_t dl) {
	uint8_t* out_buf;
	t_rc4	rc4;

	rc4_init_stream(&rc4);
	rc4_setup_keystream(&rc4, key, kl);
	out_buf = rc4_encode(&rc4, data, dl);

	return out_buf;
}