package ue_procedures

import "C"
import (
	"fmt"
	"unsafe"
)

/*

#cgo CFLAGS: -I/home/julius/dev/my5G-core/lib/bearssl/inc
//#cgo LDFLAGS: -L./lib -lbearssl -Wl,-rpath=\$ORIGIN/lib/bearssl
#cgo LDFLAGS: /home/julius/dev/my5G-core/lib/bearssl/libbearssl.a
#include "bearssl.h"
#include <stdlib.h>
#include <stdio.h>
//ec
 const unsigned char TA0_DN[] = {
        0x30, 0x7F, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x44, 0x45, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0C, 0x16, 0x4E, 0x6F, 0x72, 0x74, 0x68, 0x20, 0x52, 0x68, 0x69, 0x6E,
        0x65, 0x2D, 0x57, 0x65, 0x73, 0x74, 0x70, 0x68, 0x61, 0x6C, 0x69, 0x61,
        0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x04, 0x42,
        0x6F, 0x6E, 0x6E, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x0A,
        0x0C, 0x05, 0x73, 0x63, 0x68, 0x75, 0x65, 0x31, 0x0E, 0x30, 0x0C, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0C, 0x05, 0x73, 0x63, 0x68, 0x75, 0x65, 0x31,
        0x20, 0x30, 0x1E, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x09, 0x01, 0x16, 0x11, 0x73, 0x63, 0x68, 0x75, 0x65, 0x40, 0x65, 0x78,
        0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D
};

 const unsigned char TA0_EC_Q[] = {
        0x04, 0xBC, 0xFE, 0x13, 0xEC, 0x54, 0x5E, 0xFE, 0xC8, 0x10, 0x68, 0x37,
        0x82, 0xB2, 0x5F, 0x22, 0x49, 0x86, 0xDA, 0xA8, 0xF3, 0x49, 0xF8, 0xA9,
        0x6F, 0x43, 0x16, 0x22, 0x0F, 0x6F, 0x6B, 0x19, 0x48, 0xE5, 0x2C, 0x69,
        0x38, 0xD1, 0xBE, 0xAF, 0x58, 0x79, 0x25, 0x87, 0xB9, 0x07, 0xF8, 0x35,
        0xF7, 0xAD, 0x51, 0x1E, 0x5E, 0xC1, 0xBB, 0x2A, 0xC2, 0xBB, 0x24, 0x04,
        0xE4, 0x77, 0x88, 0x13, 0xCA, 0x2D, 0xDF, 0xBB, 0x00, 0xD1, 0x2D, 0x3C,
        0x38, 0xCB, 0xA1, 0xA4, 0xFC, 0x55, 0x93, 0xAD, 0xF9, 0xE6, 0x88, 0x34,
        0xCD, 0xB9, 0x96, 0xF4, 0x8E, 0xBA, 0xA4, 0xE1, 0xAE, 0xA6, 0xDF, 0xF8,
        0xFE
};

 const br_x509_trust_anchor TAs[1] = {
        {
                { (unsigned char *)TA0_DN, sizeof TA0_DN },
                0,
                {
                        BR_KEYTYPE_EC,
                        { .ec = {
                                BR_EC_secp384r1,
                                (unsigned char *)TA0_EC_Q, sizeof TA0_EC_Q,
                        } }
                }
        }
};

#define TAs_NUM   1

 const unsigned char CERT0[] = {
        0x30, 0x82, 0x03, 0x39, 0x30, 0x82, 0x02, 0xBE, 0xA0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x62, 0xC9, 0x54, 0xD7, 0x45, 0x68, 0x92, 0x5D, 0x85,
        0x5E, 0x04, 0xEF, 0x5E, 0x4F, 0x5A, 0xDB, 0xE0, 0x18, 0x34, 0xED, 0x30,
        0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30,
        0x7F, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x44, 0x45, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C,
        0x16, 0x4E, 0x6F, 0x72, 0x74, 0x68, 0x20, 0x52, 0x68, 0x69, 0x6E, 0x65,
        0x2D, 0x57, 0x65, 0x73, 0x74, 0x70, 0x68, 0x61, 0x6C, 0x69, 0x61, 0x31,
        0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x04, 0x42, 0x6F,
        0x6E, 0x6E, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C,
        0x05, 0x73, 0x63, 0x68, 0x75, 0x65, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0C, 0x05, 0x73, 0x63, 0x68, 0x75, 0x65, 0x31, 0x20,
        0x30, 0x1E, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
        0x01, 0x16, 0x11, 0x73, 0x63, 0x68, 0x75, 0x65, 0x40, 0x65, 0x78, 0x61,
        0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x1E, 0x17, 0x0D,
        0x32, 0x33, 0x30, 0x35, 0x32, 0x34, 0x30, 0x39, 0x35, 0x31, 0x35, 0x35,
        0x5A, 0x17, 0x0D, 0x32, 0x34, 0x30, 0x35, 0x32, 0x33, 0x30, 0x39, 0x35,
        0x31, 0x35, 0x35, 0x5A, 0x30, 0x7F, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x1F, 0x30, 0x1D, 0x06,
        0x03, 0x55, 0x04, 0x08, 0x0C, 0x16, 0x4E, 0x6F, 0x72, 0x74, 0x68, 0x20,
        0x52, 0x68, 0x69, 0x6E, 0x65, 0x2D, 0x57, 0x65, 0x73, 0x74, 0x70, 0x68,
        0x61, 0x6C, 0x69, 0x61, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
        0x07, 0x0C, 0x04, 0x42, 0x6F, 0x6E, 0x6E, 0x31, 0x0E, 0x30, 0x0C, 0x06,
        0x03, 0x55, 0x04, 0x0A, 0x0C, 0x05, 0x73, 0x63, 0x68, 0x75, 0x65, 0x31,
        0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x05, 0x73, 0x63,
        0x68, 0x75, 0x65, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x09, 0x2A, 0x86, 0x48,
        0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x11, 0x73, 0x63, 0x68, 0x75,
        0x65, 0x40, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F,
        0x6D, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
        0x04, 0xBC, 0xFE, 0x13, 0xEC, 0x54, 0x5E, 0xFE, 0xC8, 0x10, 0x68, 0x37,
        0x82, 0xB2, 0x5F, 0x22, 0x49, 0x86, 0xDA, 0xA8, 0xF3, 0x49, 0xF8, 0xA9,
        0x6F, 0x43, 0x16, 0x22, 0x0F, 0x6F, 0x6B, 0x19, 0x48, 0xE5, 0x2C, 0x69,
        0x38, 0xD1, 0xBE, 0xAF, 0x58, 0x79, 0x25, 0x87, 0xB9, 0x07, 0xF8, 0x35,
        0xF7, 0xAD, 0x51, 0x1E, 0x5E, 0xC1, 0xBB, 0x2A, 0xC2, 0xBB, 0x24, 0x04,
        0xE4, 0x77, 0x88, 0x13, 0xCA, 0x2D, 0xDF, 0xBB, 0x00, 0xD1, 0x2D, 0x3C,
        0x38, 0xCB, 0xA1, 0xA4, 0xFC, 0x55, 0x93, 0xAD, 0xF9, 0xE6, 0x88, 0x34,
        0xCD, 0xB9, 0x96, 0xF4, 0x8E, 0xBA, 0xA4, 0xE1, 0xAE, 0xA6, 0xDF, 0xF8,
        0xFE, 0xA3, 0x81, 0xFA, 0x30, 0x81, 0xF7, 0x30, 0x1D, 0x06, 0x03, 0x55,
        0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x6A, 0x1A, 0x1D, 0xE3, 0xCE, 0xDF,
        0x9B, 0xE0, 0xAC, 0x95, 0x9D, 0x2C, 0x19, 0x2E, 0x1B, 0x53, 0x20, 0xB3,
        0x00, 0x68, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30,
        0x16, 0x80, 0x14, 0x6A, 0x1A, 0x1D, 0xE3, 0xCE, 0xDF, 0x9B, 0xE0, 0xAC,
        0x95, 0x9D, 0x2C, 0x19, 0x2E, 0x1B, 0x53, 0x20, 0xB3, 0x00, 0x68, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0B,
        0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x05, 0xA0, 0x30,
        0x6F, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x68, 0x30, 0x66, 0x82, 0x09,
        0x73, 0x63, 0x68, 0x75, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x0D, 0x77,
        0x77, 0x77, 0x2E, 0x73, 0x63, 0x68, 0x75, 0x65, 0x2E, 0x63, 0x6F, 0x6D,
        0x82, 0x0E, 0x6D, 0x61, 0x69, 0x6C, 0x2E, 0x73, 0x63, 0x68, 0x75, 0x65,
        0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x0D, 0x66, 0x74, 0x70, 0x2E, 0x73, 0x63,
        0x68, 0x75, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x09, 0x6C, 0x6F, 0x63,
        0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x82, 0x15, 0x6C, 0x6F, 0x63, 0x61,
        0x6C, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x64,
        0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x82, 0x09, 0x31, 0x32, 0x37, 0x2E, 0x30,
        0x2E, 0x30, 0x2E, 0x31, 0x30, 0x2C, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x86, 0xF8, 0x42, 0x01, 0x0D, 0x04, 0x1F, 0x16, 0x1D, 0x4F, 0x70, 0x65,
        0x6E, 0x53, 0x53, 0x4C, 0x20, 0x47, 0x65, 0x6E, 0x65, 0x72, 0x61, 0x74,
        0x65, 0x64, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
        0x74, 0x65, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,
        0x03, 0x02, 0x03, 0x69, 0x00, 0x30, 0x66, 0x02, 0x31, 0x00, 0xEA, 0xB6,
        0x90, 0x43, 0xD3, 0x24, 0xC5, 0x61, 0x24, 0x70, 0x95, 0x57, 0x25, 0xCB,
        0xAF, 0xE7, 0x4A, 0xEA, 0x89, 0xC5, 0x5A, 0x04, 0x9C, 0x91, 0x2C, 0x0C,
        0xA5, 0x0F, 0x9A, 0xCC, 0x95, 0x08, 0xCB, 0x0A, 0x98, 0x2E, 0xCD, 0x1F,
        0x4A, 0x65, 0x44, 0xA5, 0x83, 0xFD, 0x2A, 0x61, 0x92, 0x32, 0x02, 0x31,
        0x00, 0x8A, 0xD7, 0xE4, 0xD2, 0x23, 0x96, 0xD7, 0x8C, 0x7E, 0x5E, 0x23,
        0x0D, 0x5A, 0x37, 0x68, 0x5C, 0xFF, 0x88, 0xB4, 0x5F, 0xA4, 0x40, 0x63,
        0x6E, 0x3D, 0x68, 0xEC, 0xA7, 0x8D, 0xF0, 0xDF, 0xA9, 0x69, 0x2E, 0x60,
        0x6D, 0x0A, 0x73, 0xEA, 0x82, 0xB5, 0x5F, 0x46, 0x4D, 0x88, 0xC0, 0x75,
        0x00
};

 const br_x509_certificate CHAIN[] = {
        { (unsigned char *)CERT0, sizeof CERT0 }
};

#define CHAIN_LEN   1

 const unsigned char EC_X[] = {
        0xA8, 0x6E, 0xE2, 0x0A, 0xDF, 0x88, 0x05, 0x4B, 0x2C, 0x67, 0x20, 0xB2,
        0xA0, 0xFC, 0x75, 0xD0, 0x6B, 0x7B, 0x18, 0xC7, 0xD6, 0x03, 0x7E, 0x38,
        0xB6, 0x5B, 0x2D, 0x64, 0x3D, 0x65, 0x29, 0x25, 0x27, 0x9D, 0x0F, 0x46,
        0xB3, 0x45, 0x36, 0xC2, 0x1F, 0x7C, 0xE4, 0x81, 0xAF, 0x6D, 0x73, 0x66
};

 const br_ec_private_key EC = {
        24,
        (unsigned char *)EC_X, sizeof EC_X
};


char *host ="localhost";
typedef struct {
	br_ssl_client_context sc;
	br_x509_minimal_context xc;
} tls_client;
br_ssl_client_context sc;
br_x509_minimal_context xc;
tls_client create_client()
{
	tls_client client;
	return client;
}

void write_to_server(char *data, unsigned char *buf, size_t len, unsigned int bytes_written){
	memcpy(buf, data+bytes_written, len);
}

int read_from_server(char *data){
	int state = 0;
	state = br_ssl_engine_current_state(&sc.eng);
	if (state & BR_SSL_CLOSED) {
		return -1; // send failure
	}
	if (state & BR_SSL_SENDREC) {
		unsigned char *buf;
		size_t len;

		buf = br_ssl_engine_sendrec_buf(&sc.eng, &len);
		if (len == 0){
			return -1;
		}
		memcpy(data, buf, len);
		br_ssl_engine_sendrec_ack(&sc.eng, len);

	}

	return 1;
}

size_t get_size(unsigned char *array){
	return sizeof(array);
}

int handshake_done(){
	int state = br_ssl_engine_current_state(&sc.eng);
	if (state & BR_SSL_SENDAPP || state & BR_SSL_RECVAPP) {
		return 1;
	}
	return 0;
}

int check_engine_state () {
	int state = br_ssl_engine_current_state(&sc.eng);
	if (state & BR_SSL_SENDREC) {
		return 2;
	}
	if (state & BR_SSL_RECVAPP || state & BR_SSL_SENDAPP) {
		return 8;
	}
	if(state & BR_SSL_RECVREC) {
		return 4;
	}
	return 1;
}

static size_t
hextobin(unsigned char *dst, const char *src)
{
	size_t num;
	unsigned acc;
	int z;

	num = 0;
	z = 0;
	acc = 0;
	while (*src != 0) {
		int c = *src ++;
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else if (c >= 'A' && c <= 'F') {
			c -= ('A' - 10);
		} else if (c >= 'a' && c <= 'f') {
			c -= ('a' - 10);
		} else {
			continue;
		}
		if (z) {
			*dst ++ = (acc << 4) + c;
			num ++;
		} else {
			acc = c;
		}
		z = !z;
	}
	return num;
}
void deriveEMSK(void *emsk, void *random){
	br_ssl_session_parameters pp;
    memset(&pp, 0, sizeof pp);
    br_ssl_engine_get_session_parameters(&sc.eng, &pp);
    const char *label = "clientEAPencryption";
	unsigned char seed[100], out[500];
	size_t seed_len;
	br_tls_prf_seed_chunk chunks[2];
    seed_len = hextobin(seed, random);
 	chunks[0].data = seed;
	chunks[0].len = seed_len;
    br_tls12_sha256_prf(out, 200, pp.master_secret, 48, label, seed_len, chunks );
	memcpy(emsk, out, 128);
}

int
get_cert_signer_algo(br_x509_certificate *xc)
{
	br_x509_decoder_context dc;
	int err;

	br_x509_decoder_init(&dc, 0, 0);
	br_x509_decoder_push(&dc, xc->data, xc->data_len);
	err = br_x509_decoder_last_error(&dc);
	if (err != 0) {
		fprintf(stderr,
			"ERROR: certificate decoding failed with error %d\n",
			-err);
		return 0;
	}
	return br_x509_decoder_get_signer_key_type(&dc);
}
int usages = 32;
*/
import "C"
import (
	"errors"
)

var client_random []byte

func Client() {
	//var scc = C.struct_br_ssl_client_context{}
	//var xc = C.br_x509_minimal_context{}
	//var scp = (C.br_ssl_client_context)(new(C.br_ssl_client_context))
	//var client = C.struct_tls_client{}

	ibuf := make([]byte, 16709)
	obuf := make([]byte, 1495)
	cibuf := C.CBytes(ibuf)
	cobuf := C.CBytes(obuf)
	//x := *C.uchar(Ta)
	//println(TAs)
	C.br_ssl_client_init_full(&C.sc, &C.xc, &C.TAs[0], C.TAs_NUM)
	C.br_ssl_engine_set_buffers_bidi(&C.sc.eng, cibuf, C.ulong(16709), cobuf, C.ulong(1497))
	C.br_ssl_client_reset(&C.sc, C.host, 0)

	//C.br_ssl_client_set_single_rsa(&C.sc, &C.CHAIN[0], C.CHAIN_LEN, &C.RSA, C.br_rsa_pkcs1_sign_get_default())
	key_type := C.get_cert_signer_algo(&C.CHAIN[0])
	C.br_ssl_client_set_single_ec(&C.sc, &C.CHAIN[0], C.CHAIN_LEN, &C.EC, 32, C.uint(key_type), C.br_ec_get_default(), C.br_ecdsa_sign_asn1_get_default())
}

func WriteToServer(data []byte) error {
	cdata := (*C.char)(C.CBytes(data))
	state := C.uint(0)
	var bytes_written C.uint = 0
	for i := 0; i < 10; i++ {
		state = C.br_ssl_engine_current_state(&C.sc.eng)
		fmt.Printf("-----------------state during write process buf: %d \n", state)
		if (state & C.uint(4)) == 4 {
			var length C.size_t = 0
			buf := C.br_ssl_engine_recvrec_buf(&C.sc.eng, &length)
			fmt.Printf("-----------------Length buf: %d \n", length)
			if length != 0 {
				C.write_to_server(cdata, buf, length, bytes_written)
				C.br_ssl_engine_recvrec_ack(&C.sc.eng, length)
				bytes_written += C.uint(length)
			}
		} else {
			return nil
		}
		if int(bytes_written) >= len(data) {
			return nil
		}
	}
	return nil
}

func ReadFromServer() ([5][]byte, int, int, error) {

	data := [5][]byte{}
	tlsMessageLength := 0
	fragmentsCount := 0
	state := C.uint(0)

	for i := 0; i < 5; i++ {
		state = C.br_ssl_engine_current_state(&C.sc.eng)
		if (state & C.uint(1)) == 1 {
			return data, tlsMessageLength, fragmentsCount, errors.New("engine closed")
		}
		if (state & C.uint(2)) == 2 {
			var length C.size_t = 0

			buf := C.br_ssl_engine_sendrec_buf(&C.sc.eng, &length)
			if length == 0 {
				return data, tlsMessageLength, fragmentsCount, errors.New("length 0 nothing to read")
			}
			readData := (*C.char)(unsafe.Pointer(buf))
			string := C.GoStringN(readData, C.int(length))
			bytes := []byte(string)
			data[i] = bytes
			tlsMessageLength += int(length)
			fragmentsCount++

			C.br_ssl_engine_sendrec_ack(&C.sc.eng, length)
			if bytes[5] == 1 && bytes[0] == 22 {
				fmt.Println("ClientHELLO: %d", data[i])
				client_random = bytes[11:43]
			}
		}
	}
	return data, tlsMessageLength, fragmentsCount, nil
}

func Handshake_done() (bool, error) {
	/*
		state := C.uint(0)
		state = C.br_ssl_engine_current_state(&C.sc.eng)
		if (state & C.uint(1)) == 1 {
			test := C.br_ssl_engine_last_error(&C.sc.eng)
			fmt.Println("code", string(test))
			code := int(test)
			ret := "engine closed  code:" + string(code)
			return false, errors.New(ret) // send failure
		}
		if state & C.BR_SSL_RECVREC {
			return true, nil
		}
		return false, nil*/
	done := C.handshake_done()
	if done == 1 {
		return true, nil
	}
	return false, nil
}

func GetEMSK() []byte {
	b := make([]byte, 128)
	emsk := C.CBytes(b)
	random := C.CBytes(client_random)
	//fmt.Printf("client random : %d", client_random)
	C.deriveEMSK(emsk, random)
	data := (*C.char)(unsafe.Pointer(emsk))
	string := C.GoStringN(data, C.int(128))
	bEMSK := []byte(string)
	return bEMSK

}

func GetLastErroCode() int {
	test := C.br_ssl_engine_last_error(&C.sc.eng)
	return int(test)
}

func GetEngineState() int {
	return int(C.br_ssl_engine_current_state(&C.sc.eng))
}

func CheckEngineState() int {
	return int(C.check_engine_state())
}
