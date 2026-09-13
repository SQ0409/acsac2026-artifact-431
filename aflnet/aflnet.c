#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include "alloc-inl.h"
#include "milenage.h"
#include "aflnet.h"
#include "hmac-sha256.h"
#include <openssl/aes.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>

static unsigned char* kn_resolve_loc_ptr(uint8_t* b, unsigned int len, const char* loc);

#include <limits.h>
static void knowledge_rules_init_once(void);

int  g_knowledge_on = 0;
int  g_in_fuzzing   = 0;
static char g_knowledge_path[PATH_MAX] = {0};

#define MAX_RULES   64
#define MAX_ACTIONS 16
#define MAX_VALUES  16

typedef enum { OP_BIT_FLIP=1, OP_ENUM_SET=2, OP_SET_BYTE=3, OP_SET_BYTES=4 } op_t;

typedef struct {

  int   ngap_proc;
  int   ie_present[8];
  int   nas_outer_sht;
  int   nas_inner_mt;
  char  has_loc[128];

  int   logic_type;
  int   n_conditions;
  struct {
    char  field[64];
    int   values[8];
    int   n_values;
  } conditions[8];
} selector_t;

typedef struct {
  char  loc[128];
  op_t  op;
  double prob;
  int   n_values;
  unsigned char values[MAX_VALUES];
} action_t;

typedef struct {
  char       id[64];
  int        log;
  selector_t sel;
  int        n_actions;
  action_t   actions[MAX_ACTIONS];
  unsigned   hits_logged;
} rule_t;

static rule_t g_rules[MAX_RULES];
int    g_rule_count = 0;

void aflnet_set_knowledge_file(const char* path) {
  if (!path) return;
  g_knowledge_on = 1;
  strncpy(g_knowledge_path, path, sizeof(g_knowledge_path)-1);

}

void aflnet_mark_fuzzing_started(void) {
  g_in_fuzzing = 1;

  if (g_knowledge_on) {

    knowledge_rules_init_once();

  }
}

static int get_ngap_procedure_code_v15(const uint8_t* buf, unsigned int len);

static unsigned char* find_nas_message_type_smart(const uint8_t* buf, unsigned int len, int* range_len);

typedef struct {
    u32 original_code;
    u8* name;
} state_info;

#define MAX_STATES 1024
static state_info state_meanings[MAX_STATES];
static u32 state_meaning_count = 0;

#define MAX_RECV_BUFFER_SIZE (2 * 1024 * 1024)
#define MAX_REGION_COUNT 1000
#define MAX_STATE_COUNT 10000

#define MAX_BUF_SIZE 65536
#define ASN_NGAP_MAX_AMF_ID_LEN 5

static uint8_t latest_amf_id[5] = {0};
static uint8_t latest_amf_id_len = 3;
static uint32_t latest_amf_id_value = 0;

static int poll_fail_count = 0;
const int MAX_POLL_FAILS = 15  ;
int likely_crash = 0;

#define RES_STAR_LEN 16
#define ALGO_ID      0x01

#define SHA256_DIGEST_SIZE 32
#define MAX_NUM_OF_KDF_PARAM 16
#define OGS_KEY_LEN 16
#define OGS_SQN_XOR_AK_LEN 6
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

#define KEY_LEN 16
#define HASH_LEN 32
#define SQN_LEN 6
#define ABBA_LEN 2
#define SUPI_MAX_LEN 64
#define MAX_PARAM 4

#define FC_KAUSF  0x6A
#define FC_KSEAF  0x6C
#define FC_KAMF   0x6D
#define FC_NAS_ALG 0x69

typedef struct {
    const uint8_t *buf;
    uint16_t len;
} kdf_param_t[MAX_PARAM];

static char mcc_str[4] = "001";
static char mnc_str[4] = "01";

typedef uint8_t u8;
typedef uint32_t u32;

/* Replace with the reviewer's own 128-bit OPc. Never commit real credentials. */
static const uint8_t opc[16] = {
  0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
};
static const uint8_t k[16] = {
  0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
  /* Replace each byte with the private 128-bit subscriber key. */
};

static const uint8_t amf[2] = { 0x00, 0x00 };

/* Replace with a test SUPI/IMSI and ABBA from the local subscriber profile. */
const char *imsi = "001010000000001"; /* Replace with a local test IMSI. */
const uint8_t abba[2] = {0x00, 0x00};

static uint8_t latest_rand[16];
static uint8_t latest_sqn[6];
static int has_latest_rand = 0;
static uint8_t latest_autn[16];
static int has_latest_challenge = 0;

 uint8_t ck[16], ik[16], ak[6];
#define os_memcpy(x, y, z) memcpy(x, y, z)
#define os_memcmp(x, y, z) memcmp(x, y, z)
#define os_memset(x, y, z) memset(x, y, z)
#define os_malloc(x) malloc(x)
#define os_free(x) free(x)

#define RAND_TAG 0x21
#define AUTN_TAG 0x20
#define RES_TAG 0x2D

static int is_connection_alive(int sockfd) {
    struct sockaddr_in serv_addr;
    socklen_t len = sizeof(serv_addr);

    if (getpeername(sockfd, (struct sockaddr*)&serv_addr, &len) < 0) {
        perror("ERROR: getpeername failed");
        return 0;
    }

    return 1;
}

int milenage_f1(const u8 *opc, const u8 *k, const u8 *_rand, const u8 *sqn, const u8 *amf, u8 *mac_a, u8 *mac_s)
{
    u8 tmp1[16], tmp2[16], tmp3[16];
    int i;

    for (i = 0; i < 16; i++)
        tmp1[i] = _rand[i] ^ opc[i];
    if (aes_128_encrypt_block(k, tmp1, tmp1))
        return -1;

    os_memcpy(tmp2, sqn, 6);
    os_memcpy(tmp2 + 6, amf, 2);
    os_memcpy(tmp2 + 8, tmp2, 8);


    for (i = 0; i < 16; i++)
        tmp3[(i + 8) % 16] = tmp2[i] ^ opc[i];

    for (i = 0; i < 16; i++)
        tmp3[i] ^= tmp1[i];


    if (aes_128_encrypt_block(k, tmp3, tmp1))
        return -1;
    for (i = 0; i < 16; i++)
        tmp1[i] ^= opc[i];
    if (mac_a)
        os_memcpy(mac_a, tmp1, 8);
    if (mac_s)
        os_memcpy(mac_s, tmp1 + 8, 8);

    return 0;
}

int milenage_f2345(const u8 *opc, const u8 *k, const u8 *_rand, u8 *res, u8 *ck, u8 *ik, u8 *ak, u8 *akstar) {
    u8 tmp1[16], tmp2[16], tmp3[16];
    int i;

    for (i = 0; i < 16; i++) tmp1[i] = _rand[i] ^ opc[i];
    if (aes_128_encrypt_block(k, tmp1, tmp2)) return -1;

    for (i = 0; i < 16; i++) tmp1[i] = tmp2[i] ^ opc[i];
    tmp1[15] ^= 1;
    if (aes_128_encrypt_block(k, tmp1, tmp3)) return -1;
    for (i = 0; i < 16; i++) tmp3[i] ^= opc[i];
    if (res) memcpy(res, tmp3 + 8, 8);
    if (ak) memcpy(ak, tmp3, 6);

    if (ck) {
        for (i = 0; i < 16; i++) tmp1[(i + 12) % 16] = tmp2[i] ^ opc[i];
        tmp1[15] ^= 2;
        if (aes_128_encrypt_block(k, tmp1, ck)) return -1;
        for (i = 0; i < 16; i++) ck[i] ^= opc[i];
    }

    if (ik) {
        for (i = 0; i < 16; i++) tmp1[(i + 8) % 16] = tmp2[i] ^ opc[i];
        tmp1[15] ^= 4;
        if (aes_128_encrypt_block(k, tmp1, ik)) return -1;
        for (i = 0; i < 16; i++) ik[i] ^= opc[i];
    }

    if (akstar) {
        for (i = 0; i < 16; i++) tmp1[(i + 4) % 16] = tmp2[i] ^ opc[i];
        tmp1[15] ^= 8;
        if (aes_128_encrypt_block(k, tmp1, tmp1)) return -1;
        for (i = 0; i < 6; i++) akstar[i] = tmp1[i] ^ opc[i];
    }

    return 0;
}

void milenage_generate(const u8 *opc, const u8 *amf, const u8 *k, const u8 *sqn, const u8 *_rand, u8 *autn, u8 *ik,
                       u8 *ck, u8 *res, size_t *res_len)
{
    int i;
    u8 mac_a[8], ak[6];

    if (*res_len < 8)
    {
        *res_len = 0;
        return;
    }
    if (milenage_f1(opc, k, _rand, sqn, amf, mac_a, NULL) || milenage_f2345(opc, k, _rand, res, ck, ik, ak, NULL))
    {
        *res_len = 0;
        return;
    }
    *res_len = 8;

    for (i = 0; i < 6; i++)
        autn[i] = sqn[i] ^ ak[i];
    os_memcpy(autn + 6, amf, 2);
    os_memcpy(autn + 8, mac_a, 8);
}

static const uint8_t *find_nas_7e(const uint8_t *buf, unsigned int len) {
    for (unsigned int i = 0; i + 6 < len; i++) {
        if (buf[i] == 0x7E) return buf + i;
    }
    return NULL;
}

static int buf_contains_initial_ue_msg(const uint8_t *buf, unsigned int len) {
  if (!buf || len < 2) return 0;
  for (unsigned int i = 0; i + 1 < len; i++) {
    uint8_t pd = buf[i];
    uint8_t mt = buf[i + 1];
    if ((pd == 0x00 || pd == 0x20) && mt == 0x0F) {
      return 1;
    }
  }
  return 0;
}

static const uint8_t *find_len_pdu(const uint8_t *buf, unsigned int len) {
    for (unsigned int i = 0; i + 6 < len; i++) {
        if (buf[i] == 0x7E) return buf + i-1;
    }
    return NULL;
}

static int is_nas_sec_protected(const uint8_t *buf, unsigned int len) {
    for (unsigned int i = 0; i + 6 < len; i++) {
        if (buf[i] == 0x7E) {
            uint8_t sec_hdr_type = buf[i + 1] & 0x0F;

            return (sec_hdr_type >= 0x01 && sec_hdr_type <= 0x04);
        }
    }

    return 0;
}

void kdf_common(const uint8_t *key, size_t key_len,
                uint8_t fc, kdf_param_t param, uint8_t *out)
{
    uint8_t buf[512];
    size_t pos = 0;
    int i;

    buf[pos++] = fc;

    for (i = 0; i < MAX_PARAM && param[i].buf; i++) {
        memcpy(&buf[pos], param[i].buf, param[i].len);
        pos += param[i].len;
        uint16_t len_be = htobe16(param[i].len);
        memcpy(&buf[pos], &len_be, 2);
        pos += 2;
    }

    hmac_sha256(out,buf,pos,key, key_len);
}

void kdf_kausf(const uint8_t *ck, const uint8_t *ik,
               const char *sn_name, const uint8_t *autn,
               uint8_t *kausf)
{
    uint8_t key[KEY_LEN * 2];
    kdf_param_t param = {0};

    memcpy(key, ck, KEY_LEN);
    memcpy(key + KEY_LEN, ik, KEY_LEN);

    param[0].buf = (const uint8_t *)sn_name;
    param[0].len = strlen(sn_name);
    param[1].buf = autn;
    param[1].len = SQN_LEN;

    kdf_common(key, sizeof(key), FC_KAUSF, param, kausf);
}

void kdf_kseaf(const char *sn_name, const uint8_t *kausf, uint8_t *kseaf)
{
    kdf_param_t param = {0};
    param[0].buf = (const uint8_t *)sn_name;
    param[0].len = strlen(sn_name);
    kdf_common(kausf, HASH_LEN, FC_KSEAF, param, kseaf);
}

void kdf_kamf(const char *imsi, const uint8_t *abba, uint8_t abba_len,
              const uint8_t *kseaf, uint8_t *kamf)
{
    kdf_param_t param = {0};
    param[0].buf = (const uint8_t *)imsi;
    param[0].len = strlen(imsi);
    param[1].buf = abba;
    param[1].len = abba_len;
    kdf_common(kseaf, HASH_LEN, FC_KAMF, param, kamf);
}

void kdf_nas_int(uint8_t alg_type, uint8_t alg_id,
                 const uint8_t *kamf, uint8_t *knas_int)
{
    kdf_param_t param = {0};
    uint8_t out[HASH_LEN];
    param[0].buf = &alg_type;
    param[0].len = 1;
    param[1].buf = &alg_id;
    param[1].len = 1;

    kdf_common(kamf, HASH_LEN, FC_NAS_ALG, param, out);
    memcpy(knas_int, out + 16, 16);
}

bool aes_cmac_128(const uint8_t* key, const uint8_t* msg, size_t msg_len, uint8_t mac[4]) {
    CMAC_CTX* ctx = CMAC_CTX_new();
    if (!ctx) return false;

    size_t mac_len = 0;
    uint8_t full_mac[16];
    bool ok = CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL) &&
              CMAC_Update(ctx, msg, msg_len) &&
              CMAC_Final(ctx, full_mac, &mac_len);

    CMAC_CTX_free(ctx);

    if (ok && mac_len >= 4) {
        memcpy(mac, full_mac, 4);
        return true;
    }
    return false;
}

bool calculate_nas_mac_eia2(
    const uint8_t knas_int[16],
    uint32_t count,
    uint8_t bearer,
    uint8_t direction,
    const uint8_t* nas_data,
    size_t nas_len,
    uint8_t out_mac[4]
) {
    uint8_t input[8 + nas_len];
    input[0] = (count >> 24) & 0xFF;
    input[1] = (count >> 16) & 0xFF;
    input[2] = (count >> 8) & 0xFF;
    input[3] = count & 0xFF;
    input[4] = (bearer & 0x1F) << 3 | (direction & 0x01) << 2;
    input[5] = 0x00;
    input[6] = 0x00;
    input[7] = 0x00;
    memcpy(input + 8, nas_data, nas_len);

    return aes_cmac_128(knas_int, input, sizeof(input), out_mac);
}

bool insert_mac_into_nas(uint8_t *mem, unsigned int len)
{
    if(!mem||len<=0)return false;

    uint8_t *nas_ptr = find_nas_7e(mem, len);
    if (!nas_ptr || !is_nas_sec_protected(nas_ptr, len - (nas_ptr - mem)))
        return false;
    uint8_t *pdu_ptr = find_len_pdu(mem, len);
	if(!pdu_ptr)
	return false;
	if (nas_ptr + 6 > mem + len) return false;
	if (pdu_ptr + 1 > mem + len) return false;

    uint8_t kausf[32], kseaf[32], kamf[32], knas_int[16];
    kdf_kausf(ck, ik, "5G:mnc001.mcc001.3gppnetwork.org", latest_autn, kausf);
    kdf_kseaf("5G:mnc001.mcc001.3gppnetwork.org", kausf, kseaf);
    kdf_kamf(imsi, abba, sizeof(abba), kseaf, kamf);
    kdf_nas_int(0x02, 0x02, kamf, knas_int);

    int mac_input_len=pdu_ptr[0];
    mac_input_len=mac_input_len-6;
    if (mac_input_len <= 0 || nas_ptr + 6 + mac_input_len > mem + len)
    return false;

    if (nas_ptr + 6 > mem + len) return false;
    const uint8_t *mac_input = nas_ptr + 6;
    if(!mac_input)return false;

    uint32_t count=(uint32_t)(mac_input[0]);
    uint8_t bearer = 0x01;
    uint8_t direction = 0x00;
    uint8_t mac_buf[4];
    if (!mac_input || mac_input_len == 0 || mac_input_len > (mem + len - mac_input))
    return false;
    calculate_nas_mac_eia2(knas_int,count,bearer,direction,mac_input,mac_input_len,mac_buf);
    memcpy(nas_ptr + 2, mac_buf, 4);

    return true;
}

static int find_ie(const uint8_t *buf, unsigned int len, uint8_t iei) {
  for (unsigned int i = 0; i + 1 < len; i++)
    if (buf[i] == iei)
      return i;
  return -1;
}

static void extract_challenge(const uint8_t *buf, unsigned int len) {
  int off;

  if ((off = find_ie(buf, len, 0x21)) < 0 || off+1+16 > len) return;
  memcpy(latest_rand, buf + off + 1, 16);

  if ((off = find_ie(buf, len, 0x20)) < 0 || off+1+16 > len) return;
  memcpy(latest_autn, buf + off + 1, 16);

}

static int find_autn_offset_in_auth_request(const uint8_t *buf, unsigned int len) {
  for (unsigned int i = 0; i + 17 < len; i++) {
    if (buf[i] == 0x20 && buf[i+1] == 0x10)
      return i + 2;
  }
  return -1;
}

int extract_autn_from_auth_request(const uint8_t *buf, unsigned int len) {
  int off = find_autn_offset_in_auth_request(buf, len);
  if (off < 0) return -1;
  memcpy(latest_autn, buf + off, 16);

      milenage_f2345(opc, k, latest_rand, NULL, ck, ik, ak, NULL);

    for (int i = 0; i < 6; i++)
      latest_sqn[i] = latest_autn[i] ^ ak[i];

  has_latest_challenge = 1;
  return 0;
}

static int is_auth_response_message(const char *msg, unsigned int len) {
  for (unsigned int i = 0; i + 2 < len; i++) {
    if ((uint8_t)msg[i] == 0x7E && (uint8_t)msg[i+1] == 0x00 && (uint8_t)msg[i+2] == 0x57)
      return 1;
  }
  return 0;
}

int aes_128_encrypt_block(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(input, output, &aes_key);
    return 0;
}

static void compute_res_star(const uint8_t *rand, const uint8_t *res,
                             const uint8_t *ck, const uint8_t *ik,
                             const char *mcc, const char *mnc,
                             uint8_t *res_star)
{

    char mnc_fixed[4] = {0};
    char mcc_fixed[4] = {0};

    if (strlen(mcc) == 2) {
        snprintf(mcc_fixed, sizeof(mcc_fixed), "0%s", mcc);
    } else if (strlen(mcc) == 1) {
        snprintf(mcc_fixed, sizeof(mcc_fixed), "00%s", mcc);
    } else {
        strncpy(mcc_fixed, mcc, 3);
    }

    if (strlen(mnc) == 2) {
        snprintf(mnc_fixed, sizeof(mnc_fixed), "0%s", mnc);
    } else if (strlen(mnc) == 1) {
        snprintf(mnc_fixed, sizeof(mnc_fixed), "00%s", mnc);
    } else {
        strncpy(mnc_fixed, mnc, 3);
    }

    char snn_template[] = "5G:mnc%s.mcc%s.3gppnetwork.org";
    char snn_buffer[64];

    int snn_len = snprintf(snn_buffer, sizeof(snn_buffer), snn_template, mnc_fixed, mcc_fixed);

    char snn[32] = {0};
    if (snn_len < 32) {

        memcpy(snn, snn_buffer, snn_len);
        for (int i = snn_len; i < 32; i++) {
            snn[i] = ' ';
        }
    } else {

        memcpy(snn, snn_buffer, 32);
    }

    uint8_t hmac_key[32];
    memcpy(hmac_key, ck, 16);
    memcpy(hmac_key + 16, ik, 16);

    uint8_t data[63] = {

        0x6B,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        0x00, 0x20,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        0x00, 0x10,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        0x00, 0x08
    };

    memcpy(data + 1, snn, 32);
    memcpy(data + 35, rand, 16);
    memcpy(data + 53, res, 8);
uint8_t mac[32];
    hmac_sha256(mac, data, sizeof(data), hmac_key, 32);

    memcpy(res_star, mac + 16, 16);



}

static void inject_res_into_auth_response(char *msg, unsigned int msg_len) {
    int off;
    if (!has_latest_challenge) return;

    if ((off = find_ie((uint8_t*)msg, msg_len, RES_TAG)) < 0) return;

    size_t res_len = 8;
    uint8_t autn[16], ck[16], ik[16], res4[8];

    milenage_generate(opc, amf, k, latest_sqn, latest_rand,
                      autn, ik, ck, res4, &res_len);

    uint8_t res_star[RES_STAR_LEN];
    compute_res_star(latest_rand, res4, ck, ik, mcc_str, mnc_str, res_star);

    if (off < 0 || off + 2 + RES_STAR_LEN > msg_len) {

        return;
    }

    memcpy(&msg[off + 2], res_star, RES_STAR_LEN);





}

static int global_offset_delta = 0;
s32 region_offset_diff = 0;

#define MAX_AMF_ID_TLV_LEN 64
static uint8_t saved_amf_id_tlv[MAX_AMF_ID_TLV_LEN];
static size_t saved_amf_id_tlv_len = 0;

static void extract_ngap_id(const uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i + 5 < len; i++) {
        if (buf[i] == 0x00 && buf[i+1] == 0x0A) break;
    }
    if (i + 5 >= len) return;

    uint8_t li = buf[i+3];
    size_t vl;

    if (li < 0x80) {

        vl = li;
    } else {

        uint8_t len_bytes = li & 0x7F;
        if (i + 4 + len_bytes >= len) return;

        vl = 0;
        for (uint8_t j = 0; j < len_bytes; j++) {
            vl = (vl << 8) | buf[i+4+j];
        }
    }

    if (vl == 0 || i + 4 + vl > len) return;

    size_t tl = 4 + vl;
    if (tl > MAX_AMF_ID_TLV_LEN) {

        tl = MAX_AMF_ID_TLV_LEN;
    }

    memcpy(saved_amf_id_tlv, buf + i, tl);
    saved_amf_id_tlv_len = tl;
}

#define MAX_MESSAGE_SIZE (10 * 1024 * 1024)
#define MAX_TLV_SIZE 1024

int replace_ngap_id(uint8_t **buf_ptr, size_t *len_ptr) {
    if (saved_amf_id_tlv_len == 0) return 0;
    uint8_t *buf = *buf_ptr;
    size_t len = *len_ptr;

    if (len < 4 || len > MAX_MESSAGE_SIZE) {
        return 0;
    }

    size_t i;
    for (i = 0; i + 5 < len; i++) {
        if (buf[i] == 0x00 && buf[i+1] == 0x0A) break;
    }
    if (i + 5 >= len) return 0;

    uint8_t cli = buf[i+3];
    size_t cvl;

    if (cli < 0x80) {

        cvl = cli;
    } else {

        uint8_t len_bytes = cli & 0x7F;
        if (i + 4 + len_bytes >= len) return 0;

        cvl = 0;
        for (uint8_t j = 0; j < len_bytes; j++) {
            cvl = (cvl << 8) | buf[i+4+j];
        }
    }

    if (cvl == 0 || cvl > MAX_TLV_SIZE) {
        return 0;
    }

    size_t current_tlv_len = 4 + cvl;

    if (i + current_tlv_len > len) {
        return 0;
    }

    int64_t diff_64 = (int64_t)saved_amf_id_tlv_len - (int64_t)current_tlv_len;

    if (diff_64 > (int64_t)MAX_MESSAGE_SIZE || diff_64 < -(int64_t)MAX_MESSAGE_SIZE) {
        return 0;
    }

    int buffer_replaced = 0;

    if (diff_64 != 0) {

        int64_t new_size_64 = (int64_t)len + diff_64;


	if (new_size_64 < 0) {

	    return 0;
	}
	if (new_size_64 > (MAX_MESSAGE_SIZE / 2)) {

	    return 0;
	}

        size_t new_size = (size_t)new_size_64;

        uint8_t *new_buf = ck_alloc(new_size);
        if (!new_buf) {
            return 0;
        }

        memcpy(new_buf, buf, i);

        memcpy(new_buf + i, saved_amf_id_tlv, saved_amf_id_tlv_len);

        size_t suffix_start = i + current_tlv_len;
        size_t suffix_len = len - suffix_start;
        memcpy(new_buf + i + saved_amf_id_tlv_len,
               buf + suffix_start,
               suffix_len);

        uint8_t flags = buf[1];
        uint16_t pdu_len = new_size - 4;

        if (pdu_len > 0x3FFF) {
            ck_free(new_buf);
            return 0;
        }

        uint16_t old_raw_len = (buf[2] << 8) | buf[3];
        uint16_t new_raw_len = (old_raw_len & 0xC000) | (pdu_len & 0x3FFF);

        new_buf[2] = (new_raw_len >> 8) & 0xFF;
        new_buf[3] = new_raw_len & 0xFF;

        new_buf[1] = flags;

        *buf_ptr = new_buf;
        *len_ptr = new_size;
        ck_free(buf);
        buffer_replaced = 1;

        if (diff_64 >= INT_MIN && diff_64 <= INT_MAX) {
            region_offset_diff += (int)diff_64;
        }
    } else {

        memcpy(buf + i, saved_amf_id_tlv, saved_amf_id_tlv_len);
        buffer_replaced = 1;
    }

    return buffer_replaced;
}

static u32 message_code_counter = 0;
khash_t(32) *message_code_map = NULL;

void init_message_code_map(){
  message_code_map = kh_init(32);
}

void destroy_message_code_map(){
  kh_destroy(32, message_code_map);
}

u32 get_mapped_message_code (u32 ori_message_code){
  u32 mapped_message_code = 0;
  khiter_t k = kh_get(32, message_code_map, ori_message_code);
  if (k == kh_end(message_code_map)) {
    int ret;
    k = kh_put(32, message_code_map, ori_message_code, &ret);
    message_code_counter++;
    kh_value(message_code_map, k) = message_code_counter;

    mapped_message_code = message_code_counter;
  }
  else {
    mapped_message_code = kh_value(message_code_map, k);
  }

  return mapped_message_code;
}

const char* get_ngap_message_name(uint8_t msg_type) {
    switch (msg_type) {
        case 0x00: return "AMFConfigurationUpdate";
        case 0x01: return "AMFStatusIndication";
        case 0x02: return "CellTrafficTrace";
        case 0x03: return "DeactivateTrace";
        case 0x04: return "DownlinkNASTransport";
        case 0x05: return "DownlinkNonUEAssociatedNRPPaTransport";
        case 0x06: return "DownlinkRANConfigurationTransfer";
        case 0x07: return "DownlinkRANStatusTransfer";
        case 0x08: return "DownlinkUEAssociatedNRPPaTransport";
        case 0x09: return "ErrorIndication";
        case 0x0A: return "HandoverCancel";
        case 0x0B: return "HandoverNotification";
        case 0x0C: return "HandoverPreparation";
        case 0x0D: return "HandoverResourceAllocation";
        case 0x0E: return "InitialContextSetupResponse";
        case 0x0F: return "InitialUEMessage";
        case 0x10: return "LocationReportingControl";
        case 0x11: return "LocationReportingFailureIndication";
        case 0x12: return "LocationReport";
        case 0x13: return "NASNonDeliveryIndication";
        case 0x14: return "NGReset";
        case 0x15: return "NGSetupRequest";
        case 0x16: return "OverloadStart";
        case 0x17: return "OverloadStop";
        case 0x18: return "Paging";
        case 0x19: return "PathSwitchRequest";
        case 0x1A: return "PDUSessionResourceModify";
        case 0x1B: return "PDUSessionResourceModifyIndication";
        case 0x1C: return "PDUSessionResourceRelease";
        case 0x1D: return "PDUSessionResourceSetupResponse";
        case 0x1E: return "PDUSessionResourceNotify";
        case 0x1F: return "PrivateMessage";
        case 0x20: return "PWSCancel";
        case 0x21: return "PWSFailureIndication";
        case 0x22: return "PWSRestartIndication";
        case 0x23: return "RANConfigurationUpdate";
        case 0x24: return "RerouteNASRequest";
        case 0x25: return "RRCInactiveTransitionReport";
        case 0x26: return "TraceFailureIndication";
        case 0x27: return "TraceStart";
        case 0x28: return "UEContextModification";
        case 0x29: return "UEContextReleaseComplete";
        case 0x2A: return "UEContextReleaseRequest";
        case 0x2B: return "UERadioCapabilityCheck";
        case 0x2C: return "UERadioCapabilityInfoIndication";
        case 0x2D: return "UETNLABindingRelease";
        case 0x2E: return "UplinkNASTransport";
        case 0x2F: return "UplinkNonUEAssociatedNRPPaTransport";
        case 0x30: return "UplinkRANConfigurationTransfer";
        case 0x31: return "UplinkRANStatusTransfer";
        case 0x32: return "UplinkUEAssociatedNRPPaTransport";
        case 0x33: return "WriteReplaceWarning";
        case 0x34: return "SecondaryRATDataUsageReport";
        case 0x35: return "RegistrationComplete";
        case 0x36: return "DownlinkRIMInformationTransfer";
        case 0x37: return "RetrieveUEInformation";
        case 0x38: return "UEInformationTransfer";
        case 0x39: return "RANCPRelocationIndication";
        case 0x3A: return "UEContextResume";
        case 0x3B: return "UEContextSuspend";
        case 0x3C: return "UERadioCapabilityIDMapping";
        case 0x3D: return "HandoverSuccess";
        case 0x3E: return "UplinkRANEarlyStatusTransfer";
        case 0x3F: return "DownlinkRANEarlyStatusTransfer";
        case 0x40: return "AMFCPRelocationIndication";
        case 0x41: return "ConnectionEstablishmentIndication";
        case 0x42: return "BroadcastSessionModification";
        case 0x43: return "DeregistrationRequest";
        case 0x44: return "BroadcastSessionSetup";
        case 0x45: return "DistributionSetup";
        case 0x46: return "DistributionRelease";
        case 0x47: return "MulticastSessionActivation";
        case 0x48: return "MulticastSessionDeactivation";
        case 0x49: return "MulticastSessionUpdate";
        case 0x4A: return "MulticastGroupPaging";
        case 0x4B: return "BroadcastSessionReleaseRequired";
        case 0x4C: return "TimingSynchronisationStatus";
        case 0x4D: return "TimingSynchronisationStatusReport";
        case 0x4E: return "MTCommunicationHandling";
        case 0x4F: return "RANPagingRequest";
        case 0x50: return "BroadcastSessionTransport";
        default:   return "unknown";
    }
}

region_t* extract_requests_ngap(unsigned char* buf,
                                unsigned int buf_size,
                                unsigned int* region_count_ref) {
    unsigned int offset = 0, region_count = 0;
    region_t *regions = NULL;

    while (offset + 4 <= buf_size) {
        uint8_t pd = buf[offset];
        if (pd != 0x00 && pd != 0x20) {
            offset++;
            continue;
        }

        uint8_t msg_type = buf[offset + 1];
        const char* name = get_ngap_message_name(msg_type);
        if (!name) {
            offset++;
            continue;
        }

        uint16_t raw_len = ((uint16_t)buf[offset + 2] << 8) | buf[offset + 3];
        uint16_t msg_len = raw_len & 0x3FFF;
        unsigned int header_size = 4;

        if (buf[offset + 3] & 0x80) {
            header_size = 5;
            uint16_t high7 = buf[offset + 3] & 0x7F;
            msg_len = (high7 << 8) | buf[offset + 4];
        }

        if (msg_len == 0) {
            offset++;
            continue;
        }

        unsigned int ideal_end = offset + header_size + msg_len;
        if (ideal_end > buf_size) {
            ideal_end = buf_size;
        }

        unsigned int real_end = ideal_end;
        for (unsigned int scan = ideal_end; scan + 2 < buf_size; scan++) {
            uint8_t pd2 = buf[scan];
            uint8_t mt2 = buf[scan + 1];
            if ((pd2 == 0x00 || pd2 == 0x20)
             && get_ngap_message_name(mt2) != NULL) {
                real_end = scan;
                break;
            }
        }















	if (region_count >= MAX_REGION_COUNT) {
            fprintf(stderr, "WARNING: Region count limit reached (%d), truncating\n", MAX_REGION_COUNT);
            break;
        }

        regions = (region_t*)ck_realloc(regions,
                    (region_count + 1) * sizeof(region_t));

        if (!regions) {
            fprintf(stderr, "ERROR: Failed to realloc regions at count %u\n", region_count);
            *region_count_ref = 0;
            return NULL;
        }

        regions[region_count].start_byte     = offset;
        regions[region_count].end_byte       = real_end - 1;
        regions[region_count].state_sequence = NULL;
        regions[region_count].state_count    = 0;
        region_count++;
        offset = real_end;
    }

    if (region_count == 0 && buf_size > 0) {
        regions = (region_t*)ck_alloc(sizeof(region_t));
        regions[0].start_byte     = 0;
        regions[0].end_byte       = buf_size - 1;
        regions[0].state_sequence = NULL;
        regions[0].state_count    = 0;
        region_count = 1;

    }

    *region_count_ref = region_count;

    return regions;
}

static const uint16_t nas_state_map[256] = {
    [0x41] = 0x4100, [0x42] = 0x4200, [0x43] = 0x4300, [0x44] = 0x4400,
    [0x45] = 0x4500, [0x46] = 0x4600, [0x47] = 0x4700, [0x48] = 0x4800,
    [0x4C] = 0x4C00, [0x4D] = 0x4D00, [0x4E] = 0x4E00, [0x4F] = 0x4F00,
    [0x50] = 0x5000, [0x51] = 0x5100, [0x52] = 0x5200, [0x54] = 0x5400,
    [0x55] = 0x5500, [0x56] = 0x5600, [0x57] = 0x5700, [0x58] = 0x5800,
    [0x59] = 0x5900, [0x5A] = 0x5A00, [0x5B] = 0x5B00, [0x5C] = 0x5C00,
    [0x5D] = 0x5D00, [0x5E] = 0x5E00, [0x5F] = 0x5F00, [0x64] = 0x6400,
    [0x65] = 0x6500, [0x66] = 0x6600, [0x67] = 0x6700, [0x68] = 0x6800,
    [0xC1] = 0xC100, [0xC2] = 0xC200, [0xC3] = 0xC300,
    [0xC5] = 0xC500, [0xC6] = 0xC600, [0xC7] = 0xC700,
    [0xC9] = 0xC900, [0xCA] = 0xCA00, [0xCB] = 0xCB00, [0xCC] = 0xCC00, [0xCD] = 0xCD00,
    [0xD1] = 0xD100, [0xD2] = 0xD200, [0xD3] = 0xD300, [0xD4] = 0xD400, [0xD5] = 0xD500
};

 static const char* ngap_msg_map[256] = {
        [0x00] = "AMFConfigurationUpdate",
        [0x01] = "AMFStatusIndication",
        [0x02] = "CellTrafficTrace",
        [0x03] = "DeactivateTrace",
        [0x04] = "DownlinkNASTransport",
        [0x05] = "DownlinkNonUEAssociatedNRPPaTransport",
        [0x06] = "DownlinkRANConfigurationTransfer",
        [0x07] = "DownlinkRANStatusTransfer",
        [0x08] = "DownlinkUEAssociatedNRPPaTransport",
        [0x09] = "ErrorIndication",
        [0x0A] = "HandoverCancel",
        [0x0B] = "HandoverNotification",
        [0x0C] = "HandoverPreparation",
        [0x0D] = "HandoverResourceAllocation",
        [0x0E] = "InitialContextSetup",
        [0x0F] = "InitialUEMessage",
        [0x10] = "LocationReportingControl",
        [0x11] = "LocationReportingFailureIndication",
        [0x12] = "LocationReport",
        [0x13] = "NASNonDeliveryIndication",
        [0x14] = "NGReset",
        [0x15] = "NGSetupResponse",
        [0x16] = "OverloadStart",
        [0x17] = "OverloadStop",
        [0x18] = "Paging",
        [0x19] = "PathSwitchRequest",
        [0x1A] = "PDUSessionResourceModify",
        [0x1B] = "PDUSessionResourceModifyIndication",
        [0x1C] = "PDUSessionResourceRelease",
        [0x1D] = "PDUSessionResourceSetup",
        [0x1E] = "PDUSessionResourceNotify",
        [0x1F] = "PrivateMessage",
        [0x20] = "PWSCancel",
        [0x21] = "PWSFailureIndication",
        [0x22] = "PWSRestartIndication",
        [0x23] = "RANConfigurationUpdate",
        [0x24] = "RerouteNASRequest",
        [0x25] = "RRCInactiveTransitionReport",
        [0x26] = "TraceFailureIndication",
        [0x27] = "TraceStart",
        [0x28] = "UEContextModification",
        [0x29] = "UEContextReleaseCommand",
        [0x2A] = "UEContextReleaseRequest",
        [0x2B] = "UERadioCapabilityCheck",
        [0x2C] = "UERadioCapabilityInfoIndication",
        [0x2D] = "UETNLABindingRelease",
        [0x2E] = "UplinkNASTransport",
        [0x2F] = "UplinkNonUEAssociatedNRPPaTransport",
        [0x30] = "UplinkRANConfigurationTransfer",
        [0x31] = "UplinkRANStatusTransfer",
        [0x32] = "UplinkUEAssociatedNRPPaTransport",
        [0x33] = "WriteReplaceWarning",
        [0x34] = "SecondaryRATDataUsageReport",
        [0x35] = "UplinkRIMInformationTransfer",
        [0x36] = "DownlinkRIMInformationTransfer",
        [0x37] = "RetrieveUEInformation",
        [0x38] = "UEInformationTransfer",
        [0x39] = "RANCPRelocationIndication",
        [0x3A] = "UEContextResume",
        [0x3B] = "UEContextSuspend",
        [0x3C] = "UERadioCapabilityIDMapping",
        [0x3D] = "HandoverSuccess",
        [0x3E] = "UplinkRANEarlyStatusTransfer",
        [0x3F] = "DownlinkRANEarlyStatusTransfer",
        [0x40] = "AMFCPRelocationIndication",
        [0x41] = "ConnectionEstablishmentIndication",
        [0x42] = "BroadcastSessionModification",
        [0x43] = "BroadcastSessionRelease",
        [0x44] = "BroadcastSessionSetup",
        [0x45] = "DistributionSetup",
        [0x46] = "DistributionRelease",
        [0x47] = "MulticastSessionActivation",
        [0x48] = "MulticastSessionDeactivation",
        [0x49] = "MulticastSessionUpdate",
        [0x4A] = "MulticastGroupPaging",
        [0x4B] = "BroadcastSessionReleaseRequired",
        [0x4C] = "TimingSynchronisationStatus",
        [0x4D] = "TimingSynchronisationStatusReport",
        [0x4E] = "MTCommunicationHandling",
        [0x4F] = "RANPagingRequest",
        [0x50] = "BroadcastSessionTransport"
    };

uint16_t extract_nas_state(unsigned char* buf, unsigned int len, unsigned int* nas_end_offset) {
    const unsigned int max_search = len < 1000 ? len : 1000;

    uint8_t nas_type = 0;
    unsigned int start_offset = 0;
    unsigned int ie_len = 0;
    int found_ie = 0;
    *nas_end_offset = 0;

    for (unsigned int i = 0; i < max_search - 3; i++) {
        if (buf[i] == 0x00 && buf[i+1] == 0x26) {
            found_ie = 1;
            unsigned int len_offset = i + 2;

            if (len_offset >= len) break;

            uint8_t first_len_byte = buf[len_offset];
            if (first_len_byte & 0x80) {
                uint8_t len_bytes_count = first_len_byte & 0x7F;
                if (len_offset + 1 + len_bytes_count >= len) break;

                ie_len = 0;
                for (int j = 0; j < len_bytes_count; j++) {
                    ie_len = (ie_len << 8) | buf[len_offset + 1 + j];
                }
                start_offset = len_offset + 1 + len_bytes_count;
            } else {
                ie_len = first_len_byte;
                start_offset = len_offset + 1;
            }

            if (start_offset + ie_len > len) {
                ie_len = len - start_offset;
            }
            break;
        }
    }

    if (!found_ie) {
        for (unsigned int i = 0; i < max_search - 1; i++) {
            if (i >= len) break;
            if (buf[i] == 0x7E) {
                start_offset = i;
                found_ie = 1;
                break;
            }
        }
    }

    if (!found_ie) return 0;

    for (unsigned int j = start_offset; j < max_search - 1; j++) {
        if (buf[j] == 0x7E) {
            unsigned int nas_msg_len = 0;
            if (j > 0) {
                nas_msg_len = buf[j-1];
                *nas_end_offset = j + nas_msg_len;
            }

            uint8_t security_header = buf[j+1];
            uint8_t security_type = security_header & 0x0F;

            if (security_type == 0x00) {
                if (j + 2 < len) {
                    nas_type = buf[j+2];
                }
            }

            else if (security_type == 0x01 || security_type == 0x02 || security_type == 0x03 || security_type == 0x04) {

                unsigned int mac_end = j + 6;
                for (unsigned int k = mac_end; k < max_search - 1; k++) {
                    if (buf[k] == 0x7E) {
                        uint8_t inner_header = buf[k+1];
                        uint8_t inner_security_type = inner_header & 0x0F;

                        if (inner_security_type == 0x00 && k > mac_end) {
                            unsigned int message_type_pos = k + 2;
                            if (message_type_pos < len) {
                                nas_type = buf[message_type_pos];


                                if (nas_type == 0x68) {
                                    unsigned int payload_start = k + 3;
                                    unsigned int payload_length = (*nas_end_offset - payload_start);

                                    if (payload_length < 8) break;

                                    for (unsigned int m = payload_start; m < payload_start + payload_length - 3; m++) {
                                        if (buf[m] == 0x2E && (m - payload_start) >= 2) {
                                            unsigned int sm_type_pos = m + 3;
                                            if (sm_type_pos < len) {
                                                uint8_t sm_type = buf[sm_type_pos];
                                                nas_type = sm_type;
                                                break;
                                            }
                                        }
                                        else if (buf[m] == 0x7E) {
                                            unsigned int inner_nas_end = 0;
                                            uint16_t inner_state = extract_nas_state(buf + m, len - m, &inner_nas_end);

                                            if (inner_state != 0) {
                                                nas_type = (inner_state >> 8) & 0xFF;
                                                break;
                                            }
                                        }
                                    }
                                }

                                break;
                            }
                        }
                    }
                }
            }

            if (nas_type == 0) {
                if (security_type == 0x00) {
                    if (j + 2 < len) {
                        nas_type = buf[j+2];
                    }
                } else {
                    if (j + 6 < len) {
                        nas_type = buf[j+6];
                    }
                }
            }

            if (nas_type != 0) {
                uint16_t state = nas_state_map[nas_type];
                if (state != 0) return state;
                return nas_type << 8;
            }

            return 0x2600;
        }
    }
    return 0;
}

void add_state_meaning(u32 mapped_code, u32 original_code, const char* name) {
    if (mapped_code >= MAX_STATES) return;

    state_info* info = &state_meanings[mapped_code];
    if (info->name) ck_free(info->name);

    info->original_code = original_code;
    info->name = (u8*)ck_strdup((u8*)name);

    if (mapped_code > state_meaning_count)
        state_meaning_count = mapped_code;
}

const char* get_state_meaning(u32 mapped_code) {
    if (mapped_code < MAX_STATES && state_meanings[mapped_code].name)
        return (const char*)state_meanings[mapped_code].name;

    return "Unknown State";
}

void cleanup_state_meanings() {
    for (u32 i = 0; i <= state_meaning_count; i++) {
        if (state_meanings[i].name) {
            ck_free(state_meanings[i].name);
            state_meanings[i].name = NULL;
        }
    }
    state_meaning_count = 0;
}

const char* get_nas_message_name(u16 nas_state) {
    u8 message_type = nas_state >> 8;

    switch (message_type) {
        case 0x41: return "Registration Request";
        case 0x42: return "Registration Accept";
        case 0x43: return "Registration Complete";
        case 0x44: return "Registration Reject";
        case 0x45: return "Deregistration Request (UE Originating)";
        case 0x46: return "Deregistration Accept (UE Originating)";
        case 0x47: return "Deregistration Request (UE Terminated)";
        case 0x48: return "Deregistration Accept (UE Terminated)";
        case 0x4C: return "Service Request";
        case 0x4D: return "Service Reject";
        case 0x4E: return "Service Accept";
        case 0x4F: return "Control Plane Service Request";
        case 0x50: return "Network Slice-Specific Authentication Command";
        case 0x51: return "Network Slice-Specific Authentication Complete";
        case 0x52: return "Network Slice-Specific Authentication Result";
        case 0x54: return "Configuration Update Command";
        case 0x55: return "Configuration Update Complete";
        case 0x56: return "Authentication Request";
        case 0x57: return "Authentication Response";
        case 0x58: return "Authentication Reject";
        case 0x59: return "Authentication Failure";
        case 0x5A: return "Authentication Result";
        case 0x5B: return "Identity Request";
        case 0x5C: return "Identity Response";
        case 0x5D: return "Security Mode Command";
        case 0x5E: return "Security Mode Complete";
        case 0x5F: return "Security Mode Reject";
        case 0x64: return "5GMM Status";
        case 0x65: return "Notification";
        case 0x66: return "Notification Response";
        case 0x67: return "UL NAS Transport";
        case 0x68: return "DL NAS Transport";
        case 0xC1: return "PDU Session Establishment Request";
        case 0xC2: return "PDU Session Establishment Accept";
        case 0xC3: return "PDU Session Establishment Reject";
        case 0xC5: return "PDU Session Authentication Command";
        case 0xC6: return "PDU Session Authentication Complete";
        case 0xC7: return "PDU Session Authentication Result";
        case 0xC9: return "PDU Session Modification Request";
        case 0xCA: return "PDU Session Modification Reject";
        case 0xCB: return "PDU Session Modification Command";
        case 0xCC: return "PDU Session Modification Complete";
        case 0xCD: return "PDU Session Modification Command Reject";
        case 0xD1: return "PDU Session Release Request";
        case 0xD2: return "PDU Session Release Reject";
        case 0xD3: return "PDU Session Release Command";
        case 0xD4: return "PDU Session Release Complete";
        case 0xD5: return "5GSM Status";
        default: {
            static char buffer[64];
            snprintf(buffer, sizeof(buffer), "NAS Message (0x%02X)", message_type);
            return buffer;
        }
    }
}

unsigned int* extract_response_codes_ngap(unsigned char* buf,
                                         unsigned int buf_size,
                                         unsigned int* state_count_ref)
{










    static const uint16_t IGNORE_STATES[] = {
        0x0900, 0x2100, 0x2600
    };
    static const int NUM_IGNORE_STATES = sizeof(IGNORE_STATES) / sizeof(IGNORE_STATES[0]);

    unsigned int offset = 0;
    unsigned int state_count = 0;
    unsigned int *state_sequence = NULL;

    state_sequence = (unsigned int*)ck_alloc(sizeof(unsigned int));
    state_sequence[state_count++] = 0x0000;

    const unsigned int MAX_NGAP_MSG_SIZE = 4096;

    while (offset + 4 <= buf_size) {
        uint8_t pd = buf[offset];
        uint8_t msg_type = buf[offset+1];
        uint16_t raw_len = (buf[offset+2] << 8) | buf[offset+3];



        int valid_header = 0;
        if (pd == 0x00 || pd == 0x20) {
            uint16_t msg_len = raw_len & 0x3FFF;
            if (msg_len > 0 && msg_len <= MAX_NGAP_MSG_SIZE) {
                if (msg_type == 0x00 && raw_len > 0x400) {

                }
                else if ((msg_type <= 0x50) &&
                         (ngap_msg_map[msg_type] != NULL ||
                          msg_type == 0x00 || msg_type == 0x04 || msg_type == 0x2E)) {
                    valid_header = 1;
                }
            }
        }

        if (!valid_header) {
            int found_real_header = 0;
            for (int i = 1; i < 8 && (offset + i + 4) <= buf_size; i++) {
                uint8_t next_pd = buf[offset+i];
                uint8_t next_msg_type = buf[offset+i+1];
                uint16_t next_raw_len = (buf[offset+i+2] << 8) | buf[offset+i+3];
                uint16_t next_msg_len = next_raw_len & 0x3FFF;

                if ((next_pd == 0x00) &&
                    (next_msg_type == 0x00 || next_msg_type == 0x04 || next_msg_type == 0x2E) &&
                    next_msg_len > 0 && next_msg_len <= MAX_NGAP_MSG_SIZE) {
                    found_real_header = 1;
                    offset += i;
                    break;
                }
            }

            if (found_real_header) {
                pd = buf[offset];
                msg_type = buf[offset+1];
                raw_len = (buf[offset+2] << 8) | buf[offset+3];

            } else {
                offset++;
                continue;
            }
        }

        uint16_t msg_len = raw_len & 0x3FFF;
        const char* name = ngap_msg_map[msg_type] ? ngap_msg_map[msg_type] : "Unknown";



        if (msg_len == 0 || msg_len > MAX_NGAP_MSG_SIZE) {
            offset += 4;
            continue;
        }

        unsigned int total_len = 4 + msg_len;
        if (offset + total_len > buf_size) {

            break;
        }

        unsigned int actual_msg_len = msg_len;
        unsigned int payload_offset = offset + 4;





        if (payload_offset + 2 <= buf_size) {
            if (buf[payload_offset] == 0x00 && buf[payload_offset+1] == 0x00) {

            }
            else if (payload_offset + 3 <= buf_size &&
                     buf[payload_offset+1] == 0x00 &&
                     buf[payload_offset+2] == 0x00) {
                actual_msg_len = buf[payload_offset];
                total_len = 4 + actual_msg_len;
                payload_offset += 1;

            }
            else if ((msg_type == 0x04 || msg_type == 0x2E) &&
                     buf[payload_offset] == 0x00 &&
                     buf[payload_offset+1] == 0x26) {

            }
            else if (payload_offset + 4 <= buf_size &&
                     buf[payload_offset] == 0x00 &&
                     buf[payload_offset+2] == 0x00) {
        }
        }

        uint16_t state = 0;
        int extract_nas = 0;

        switch(msg_type) {
            case 0x15: state = 0x1500; break;
            case 0x29: state = 0x2900; break;
            case 0x04: case 0x0E: case 0x0F: case 0x13:
            case 0x24: case 0x2E: case 0x1D:
                state = msg_type << 8;
                extract_nas = 1;
                break;
            default:
                state = msg_type << 8;
        }



        unsigned int nas_end_offset = 0;
        if (extract_nas && actual_msg_len > 0) {
            uint16_t nas_state = extract_nas_state(
                buf + payload_offset,
                actual_msg_len,
                &nas_end_offset
            );

            if (nas_state != 0) {
                state = nas_state;
        }
        }

        int ignore_state = 0;
        for (int i = 0; i < NUM_IGNORE_STATES; i++) {
            if (state == IGNORE_STATES[i]) {
                ignore_state = 1;
                break;
            }
        }

        if (!ignore_state) {

            if (state_count >= MAX_STATE_COUNT) {
                fprintf(stderr, "WARNING: State count limit reached (%d), truncating\n", MAX_STATE_COUNT);
                break;
            }

            unsigned int mapped_state = get_mapped_message_code(state);

            if (extract_nas && state != 0) {
                const char* nas_name = get_nas_message_name(state);
                if (nas_name) {
                    add_state_meaning(mapped_state, state, nas_name);

                }
            } else {
                add_state_meaning(mapped_state, state, name);

            }

            state_sequence = (unsigned int*)ck_realloc(state_sequence, (state_count + 1) * sizeof(unsigned int));
            state_sequence[state_count] = mapped_state;
            state_count++;
        }

        offset += total_len;
    }

    *state_count_ref = state_count;

    return state_sequence;
}

static unsigned char dtls12_version[2] = {0xFE, 0xFD};

#define CCS_CONTENT_TYPE 0x14
#define ALERT_CONTENT_TYPE 0x15
#define HS_CONTENT_TYPE 0x16
#define APPLICATION_CONTENT_TYPE 0x17
#define HEARTBEAT_CONTENT_TYPE 0x18

#define UNKNOWN_CONTENT_TYPE 0xFF

#define UNKNOWN_MESSAGE_TYPE 0xFF
#define MALFORMED_MESSAGE_TYPE 0xFE

klist_t(lms) *construct_kl_messages(u8* fname, region_t *regions, u32 region_count)
{
  FILE *fseed = NULL;
  fseed = fopen(fname, "rb");
  if (fseed == NULL) PFATAL("Cannot open seed file %s", fname);

  klist_t(lms) *kl_messages = kl_init(lms);
  u32 i;

  for (i = 0; i < region_count; i++) {

    u32 len = regions[i].end_byte - regions[i].start_byte + 1;

    message_t *m = (message_t *) ck_alloc(sizeof(message_t));
    m->mdata = (char *) ck_alloc(len);
    m->msize = len;
    if (m->mdata == NULL) PFATAL("Unable to allocate memory region to store new message");
    fread(m->mdata, 1, len, fseed);

    *kl_pushp(lms, kl_messages) = m;
  }

  if (fseed != NULL) fclose(fseed);
  return kl_messages;
}

void delete_kl_messages(klist_t(lms) *kl_messages)
{

  message_t *m;

  int ret = kl_shift(lms, kl_messages, &m);
  while (ret == 0) {
    if (m) {
      ck_free(m->mdata);
      ck_free(m);
    }
    ret = kl_shift(lms, kl_messages, &m);
  }

	kl_destroy(lms, kl_messages);
}

kliter_t(lms) *get_last_message(klist_t(lms) *kl_messages)
{
  kliter_t(lms) *it;
  it = kl_begin(kl_messages);
  while (kl_next(it) != kl_end(kl_messages)) {
    it = kl_next(it);
  }
  return it;
}

u32 save_kl_messages_to_file(klist_t(lms) *kl_messages, u8 *fname, u8 replay_enabled, u32 max_count)
{
  u8 *mem = NULL;
  u32 len = 0, message_size = 0;
  kliter_t(lms) *it;

  s32 fd = open(fname, O_WRONLY | O_CREAT, 0600);
  if (fd < 0) PFATAL("Unable to create file '%s'", fname);

  u32 message_count = 0;

  for (it = kl_begin(kl_messages); it != kl_end(kl_messages) && message_count < max_count; it = kl_next(it)) {
    message_size = kl_val(it)->msize;
    if (replay_enabled) {
		  mem = (u8 *)ck_realloc(mem, 4 + len + message_size);

      u32 *psize = (u32*)&mem[len];
      *psize = message_size;

      memcpy(&mem[len + 4], kl_val(it)->mdata, message_size);
      len = 4 + len + message_size;
    } else {
      mem = (u8 *)ck_realloc(mem, len + message_size);

      memcpy(&mem[len], kl_val(it)->mdata, message_size);
      len = len + message_size;
    }
    message_count++;
  }

  ck_write(fd, mem, len, fname);
  close(fd);

  ck_free(mem);

  return len;
}
region_t* convert_kl_messages_to_regions(klist_t(lms) *kl_messages, u32* region_count_ref, u32 max_count) {
  static int total_offset_delta = 0;

  region_t *regions = NULL;
  kliter_t(lms) *it;

  u32 region_count = 1;
  s32 cur_start = total_offset_delta;
  s32 cur_end = 0;

  for (it = kl_begin(kl_messages); it != kl_end(kl_messages) && region_count <= max_count ; it = kl_next(it)) {
    regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));

   	s32 temp_size = (s32)kl_val(it)->msize + region_offset_diff;
	u32 actual_msize;

	if (temp_size <= 0) {
	    fprintf(stderr, "[CRITICAL] Size underflow detected! msize=%u, offset=%d\n",
		    kl_val(it)->msize, region_offset_diff);
	    actual_msize = kl_val(it)->msize;
	    region_offset_diff = 0;
	} else if (temp_size > MAX_MESSAGE_SIZE) {
	    fprintf(stderr, "[CRITICAL] Size overflow detected! temp_size=%d\n", temp_size);
	    actual_msize = kl_val(it)->msize;
	    region_offset_diff = 0;
	} else {
	    actual_msize = (u32)temp_size;
	}

    cur_end = cur_start + actual_msize - 1;
    regions[region_count - 1].start_byte = cur_start;
    regions[region_count - 1].end_byte = cur_end;
    regions[region_count - 1].state_sequence = NULL;
    regions[region_count - 1].state_count = 0;

    cur_start = cur_end + 1;
    region_count++;

    region_offset_diff = 0;
  }

  *region_count_ref = region_count - 1;
  return regions;
}

int net_recv(int sockfd, struct timeval timeout, int poll_timeout_ms,
             char **response_buf, unsigned int *len) {
    char temp_buf[1000];
    int n;
    struct pollfd pfd[1] = {{ sockfd, POLLIN, 0 }};

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                   (char *)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed");

        likely_crash = 1;
        return -1;
    }

    int rv = poll(pfd, 1, poll_timeout_ms);
    if (rv == 0){

            if (!is_connection_alive(sockfd)) {
                fprintf(stderr, "WARNING: Server closed connection\n");
                likely_crash=1;
            }
	        return 0;
        }
    else if(rv<0){
            perror("ERROR: poll failed");
            return 0;
    }

    if (pfd[0].revents & POLLIN) {
        n = recv(sockfd, temp_buf, sizeof(temp_buf), 0);



        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recv error");
            fprintf(stderr, "[net_recv] recv1 returned <0\n");
            likely_crash = 1;
            return -1;
        }
        while (n > 0) {

            if (*len + n > MAX_RECV_BUFFER_SIZE) {
                fprintf(stderr, "ERROR: Receive buffer size limit exceeded (%u + %d > %d)\n",
                        *len, n, MAX_RECV_BUFFER_SIZE);
                return -1;
            }


            extract_ngap_id((uint8_t*)temp_buf, n);


		size_t new_size = (size_t)*len + (size_t)n + 1;
		void *tmp = ck_realloc(*response_buf, new_size);

            if (!tmp) {
                fprintf(stderr, "ck_realloc failed\n");
                ck_free(*response_buf);
                *response_buf = NULL;
                *len = 0;
                likely_crash = 1;
                return -1;
            }
            *response_buf = tmp;
            memcpy(*response_buf + *len, temp_buf, n);
            *len += n;
            (*response_buf)[*len] = '\0';

            extract_challenge((uint8_t*)*response_buf, *len);

            extract_autn_from_auth_request(*response_buf, *len);

            n = recv(sockfd, temp_buf, sizeof(temp_buf), 0);



            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("recv error");
                fprintf(stderr, "[net_recv] recv2 returned <0\n");
                likely_crash = 1;
                return -1;
            }
        }
    }
    return 0;
}

int apply_first_matching_rule(uint8_t* buf, size_t len) {
  if (!g_knowledge_on || !g_in_fuzzing || g_rule_count == 0) return 0;

  for (int i = 0; i < g_rule_count; i++) {
    rule_t* r = &g_rules[i];
    if (!selector_match(&r->sel, buf, (unsigned int)len)) continue;


    int applied = 0;
    for (int k = 0; k < r->n_actions; k++) {
      action_t* a = &r->actions[k];
      unsigned char* ptr = kn_resolve_loc_ptr(buf, (unsigned int)len, a->loc);
      if (!ptr) continue;

      unsigned char old_val = *ptr;


      apply_action_on_ptr(ptr, a);


      if (*ptr != old_val) applied = 1;
    }

    if (applied) {

      return 1;
    }
  }

  return 0;
}

static int read_file_all(const char* path, char** out_buf, size_t* out_len) {
  FILE* f = fopen(path, "rb");
  if (!f) return -1;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz <= 0 || sz > 1<<26) { fclose(f); return -2; }
  char* buf = (char*)malloc(sz+1);
  if (!buf) { fclose(f); return -3; }
  if ((long)fread(buf,1,sz,f)!=sz) { fclose(f); free(buf); return -4; }
  fclose(f);
  buf[sz] = 0;
  *out_buf = buf; *out_len = (size_t)sz;
  return 0;
}

static int parse_hex_byte(const char* s) {
  int v = -1;
  if (!s) return -1;
  if (!strncasecmp(s, "0x", 2)) sscanf(s+2, "%x", &v);
  else sscanf(s, "%x", &v);
  if (v < 0 || v > 255) return -1;
  return v;
}

static inline int rnd(int n) {
  if (n <= 1) return 0;
  int result = rand() % n;

  return result;
}

static const char* json_find(const char* js, const char* key) {
  return strstr(js, key);
}
static int json_bool_at(const char* p, int defv) {
  if (!p) return defv;
  if (strstr(p, "true")) return 1;
  if (strstr(p, "false")) return 0;
  return defv;
}

static void parse_single_condition(void* condition_ptr, const char* obj_start, const char* obj_end) {
  struct {
    char field[64];
    int values[8];
    int n_values;
  } *cond = (typeof(cond))condition_ptr;

  memset(cond, 0, sizeof(*cond));

  const char* has_pos = strstr(obj_start, "\"has_loc\"");
  const char* proc_pos = strstr(obj_start, "\"ngap.procedure_code\"");
  const char* nas_pos = strstr(obj_start, "\"nas.message_type\"");

  if (has_pos && has_pos < obj_end) {
    strcpy(cond->field, "has_loc:");

    const char* colon = strchr(has_pos, ':');
    if (colon && colon < obj_end) {
      const char* quote1 = strchr(colon, '"');
      if (quote1 && quote1 < obj_end) {
        const char* quote2 = strchr(quote1 + 1, '"');
        if (quote2 && quote2 < obj_end) {
          size_t loc_len = quote2 - (quote1 + 1);
          if (loc_len < 56) {
            strncat(cond->field, quote1 + 1, loc_len);

          }
        }
      }
    }

    cond->n_values = 0;
  }
  else if (proc_pos && proc_pos < obj_end) {
    strcpy(cond->field, "ngap.procedure_code");

    const char* colon = strchr(proc_pos, ':');
    if (colon && colon < obj_end) {
      const char* value_start = colon + 1;
      while (value_start < obj_end && (*value_start == ' ' || *value_start == '\t')) {
        value_start++;
      }

      if (*value_start == '[') {

        const char* bracket_end = strchr(value_start, ']');
        if (bracket_end && bracket_end < obj_end) {
          const char* scan = value_start + 1;
          while (scan < bracket_end && cond->n_values < 8) {
            while (scan < bracket_end && (*scan < '0' || *scan > '9')) scan++;
            if (scan >= bracket_end) break;

            int val;
            if (sscanf(scan, "%d", &val) == 1) {
              cond->values[cond->n_values++] = val;

            }

            while (scan < bracket_end && (*scan >= '0' && *scan <= '9')) scan++;
          }
        }
      } else {
        int val;
        if (sscanf(value_start, "%d", &val) == 1) {
          cond->values[0] = val;
          cond->n_values = 1;
        }
      }
    }
  }
  else if (nas_pos && nas_pos < obj_end) {
    strcpy(cond->field, "nas.message_type");

    const char* colon = strchr(nas_pos, ':');
    if (colon && colon < obj_end) {
      const char* value_start = colon + 1;
      while (value_start < obj_end && (*value_start == ' ' || *value_start == '\t')) {
        value_start++;
      }

      if (*value_start == '[') {
        const char* bracket_end = strchr(value_start, ']');
        if (bracket_end && bracket_end < obj_end) {
          const char* scan = value_start + 1;
          while (scan < bracket_end && cond->n_values < 8) {
            const char* quote1 = strchr(scan, '"');
            if (!quote1 || quote1 >= bracket_end) break;

            const char* quote2 = strchr(quote1 + 1, '"');
            if (!quote2 || quote2 >= bracket_end) break;

            char hex_str[16] = {0};
            size_t hex_len = quote2 - (quote1 + 1);
            if (hex_len < 16) {
              strncpy(hex_str, quote1 + 1, hex_len);
              int val = parse_hex_byte(hex_str);
              if (val >= 0) {
                cond->values[cond->n_values++] = val;

              }
            }

            scan = quote2 + 1;
          }
        }
      } else {
        const char* quote1 = strchr(value_start, '"');
        if (quote1 && quote1 < obj_end) {
          const char* quote2 = strchr(quote1 + 1, '"');
          if (quote2 && quote2 < obj_end) {
            char hex_str[16] = {0};
            size_t hex_len = quote2 - (quote1 + 1);
            if (hex_len < 16) {
              strncpy(hex_str, quote1 + 1, hex_len);
              int val = parse_hex_byte(hex_str);
              if (val >= 0) {
                cond->values[0] = val;
                cond->n_values = 1;
              }
            }
          }
        }
      }
    }
  }
}

static void parse_logic_conditions(selector_t* sel, const char* logic_start, const char* block_end, const char* logic_type) {
  sel->n_conditions = 0;



  const char* array_start = strchr(logic_start, '[');
  if (!array_start || array_start >= block_end) {
    return;
  }

  const char* array_end = NULL;
  int bracket_depth = 0;
  for (const char* scan = array_start; scan < block_end; scan++) {
    if (*scan == '[') bracket_depth++;
    else if (*scan == ']') {
      bracket_depth--;
      if (bracket_depth == 0) {
        array_end = scan;
        break;
      }
    }
  }

  if (!array_end || array_end >= block_end) {
    return;
  }



  const char* scan = array_start + 1;

  while (scan < array_end && sel->n_conditions < 8) {

    while (scan < array_end && (*scan == ' ' || *scan == '\t' || *scan == '\n' || *scan == ',')) {
      scan++;
    }

    if (scan >= array_end) break;

    if (*scan != '{') {
      scan++;
      continue;
    }

    const char* obj_begin = scan;

    int brace_depth = 0;
    const char* obj_finish = NULL;

    for (const char* obj_scan = obj_begin; obj_scan < array_end; obj_scan++) {
      if (*obj_scan == '{') brace_depth++;
      else if (*obj_scan == '}') {
        brace_depth--;
        if (brace_depth == 0) {
          obj_finish = obj_scan;
          break;
        }
      }
    }

    if (!obj_finish || obj_finish >= array_end) {
      break;
    }



    parse_single_condition(&sel->conditions[sel->n_conditions], obj_begin, obj_finish + 1);

    if (sel->conditions[sel->n_conditions].field[0] != '\0') {
      sel->n_conditions++;
    }

    scan = obj_finish + 1;
  }

}

static void parse_selector_block(selector_t* sel, const char* block, const char* block_end) {

  memset(sel, 0, sizeof(*sel));
  sel->ngap_proc = -1;
  sel->nas_outer_sht = -1;
  sel->nas_inner_mt = -1;
  for (int i=0; i<8; i++) sel->ie_present[i] = -1;

  const char* any_of_p = strstr(block, "\"any_of\"");
  const char* all_of_p = strstr(block, "\"all_of\"");

  if (any_of_p && any_of_p < block_end) {
    sel->logic_type = 1;
    parse_logic_conditions(sel, any_of_p, block_end, "any_of");
    return;
  }

  if (all_of_p && all_of_p < block_end) {
    sel->logic_type = 2;
    parse_logic_conditions(sel, all_of_p, block_end, "all_of");
    return;
  }

  sel->logic_type = 0;

  const char* p;
  if ((p = strstr(block, "ngap.procedureCode")) && p < block_end) {
    int v=-1; sscanf(p, "ngap.procedureCode\"%*[^0-9]%d", &v);
    if (v>=0) sel->ngap_proc = v;
  }

  if ((p = strstr(block, "\"nas.inner.mt\"")) && p < block_end) {
    char hv[16]={0};
    if (sscanf(p, "\"nas.inner.mt\"%*[^\"\"]\"%15[^\"]", hv)==1) {
      int v = parse_hex_byte(hv);
      if (v>=0) sel->nas_inner_mt = v;
    } else {
      int v=-1; if (sscanf(p, "\"nas.inner.mt\"%*[^0-9]%d", &v)==1 && v>=0) sel->nas_inner_mt = v;
    }
  }

  if ((p = strstr(block, "\"nas.outer.sht\"")) && p < block_end) {
    int v=-1; if (sscanf(p, "\"nas.outer.sht\"%*[^0-9]%d", &v)==1 && v>=0) sel->nas_outer_sht = v;
  }

  if ((p = strstr(block, "ngap.ie_present")) && p < block_end) {
    int idx=0, v;
    const char* q = strchr(p, '['); const char* qe = strchr(p, ']');
    if (q && qe && q<qe) {
      const char* cur = q+1;
      while (cur<qe && idx<8) {
        while (cur<qe && (*cur<'0' || *cur>'9')) cur++;
        if (cur>=qe) break;
        if (sscanf(cur, "%d", &v)==1) sel->ie_present[idx++] = v;
        while (cur<qe && *cur!=',' && *cur!=']') cur++;
      }
    }
  }

  const char* hp = strstr(block, "\"has_loc\"");
  if (hp && hp < block_end) {
    const char* q1 = strchr(hp, '"');
    if (q1) q1 = strchr(q1+1, '"');
    const char* q2 = q1 ? strchr(q1+1, '"') : NULL;
    const char* q3 = q2 ? strchr(q2+1, '"') : NULL;

    if (q2 && q3 && q3 < block_end) {
      size_t L = (size_t)(q3 - (q2+1));
      if (L >= sizeof(sel->has_loc)) L = sizeof(sel->has_loc)-1;

      memcpy(sel->has_loc, q2+1, L);
      sel->has_loc[L] = 0;
    }
  }
}

static int parse_actions(action_t* out, int maxn, const char* block, const char* block_end) {
  int cnt=0;
  const char* p = block;
  while (p && p<block_end && cnt<maxn) {
    const char* a = strstr(p, "{"); if (!a || a>=block_end) break;
    const char* z = strstr(a, "}"); if (!z || z>=block_end) break;

    action_t ac; memset(&ac, 0, sizeof(ac)); ac.op=0; ac.prob=0.0;

    const char* lp = strstr(a, "\"loc\"");
    if (lp && lp<z) {
      char lv[120]={0};
      if (sscanf(lp, " \"loc\" %*[^\"\"] \" %119[^\"]", lv)==1) strncpy(ac.loc, lv, sizeof(ac.loc)-1);
    }

    const char* op = strstr(a, "\"op\"");
    if (op && op<z) {
      char ov[32]={0};
      if (sscanf(op, " \"op\" %*[^\"\"] \" %31[^\"]", ov)==1) {
        if      (!strcmp(ov,"bit_flip"))  ac.op = OP_BIT_FLIP;
        else if (!strcmp(ov,"enum_set"))  ac.op = OP_ENUM_SET;
        else if (!strcmp(ov,"set_byte"))  ac.op = OP_SET_BYTE;
        else if (!strcmp(ov,"set_bytes")) ac.op = OP_SET_BYTES;
      }
    }

	const char* pp = strstr(a, "\"prob\"");
	if (pp && pp<z) {

	  const char* colon = strchr(pp, ':');
	  if (colon && colon < z) {
	    double pv = 0.0;
	    if (sscanf(colon + 1, "%lf", &pv) == 1) {
	      ac.prob = pv;

	    }
	  }
	}

const char* vp = strstr(a, "\"values\"");
if (vp && vp<z) {

  int n=0;
  const char* q = strchr(vp,'[');
  const char* qe = strchr(vp,']');

  if (q && qe && q<qe) {

    const char* cur = q+1;

    while (cur<qe && n<MAX_VALUES) {

      while (cur<qe && (*cur==' ' || *cur=='\t' || *cur=='\n' || *cur==',')) {
        cur++;
      }
      if (cur>=qe) break;

      if (*cur=='"') {

        char hv[16]={0};
        if (sscanf(cur, "\"%15[^\"]\"", hv)==1) {
          int b = parse_hex_byte(hv);
          if (b>=0) {
            ac.values[n++] = (unsigned char)b;

          }
        }

        cur = strchr(cur+1,'"');
        if (cur) cur++;
      }
      else if (*cur >= '0' && *cur <= '9') {

        int v = 0;
        char* endptr;
        v = (int)strtol(cur, &endptr, 10);

        if (endptr > cur && v >= 0 && v <= 255) {
          ac.values[n++] = (unsigned char)v;

          cur = endptr;
        } else {

          cur++;
        }
      }
      else {

        cur++;
      }
    }
  }
  ac.n_values = n;

}

    if (ac.op && ac.loc[0]) {

    out[cnt++] = ac; }
    p = z+1;
  }
  return cnt;
}

static void knowledge_load_rules(void) {
  if (!g_knowledge_on || !g_knowledge_path[0]) return;
  char* js=NULL; size_t jl=0;
  if (read_file_all(g_knowledge_path, &js, &jl)!=0) {

    return;
  }
  g_rule_count = 0;
  const char* p = strstr(js, "\"rules\"");
  if (!p) {

    free(js);
    return;
  }

  const char* arr = strchr(p, '[');
  const char* arr_end = strrchr(js, ']');
  if (!arr || !arr_end || arr>=arr_end) {

    free(js);
    return;
  }

  int depth = 0;
  const char* obj_start = NULL;

  for (const char* scan = arr + 1; scan < arr_end && g_rule_count < MAX_RULES; scan++) {
    if (*scan == '{') {
      if (depth == 0) obj_start = scan;
      depth++;
    }
    else if (*scan == '}') {
      depth--;
      if (depth == 0 && obj_start) {

        const char* rb = obj_start;
        const char* re = scan + 1;

        rule_t r;
        memset(&r, 0, sizeof(r));

        const char* idp = strstr(rb, "\"id\"");
        if (idp && idp < re) {
          char idv[60]={0};
          if (sscanf(idp, " \"id\" %*[^\"\"] \" %59[^\"]", idv)==1) {
            strncpy(r.id, idv, sizeof(r.id)-1);
          }
        } else {
          snprintf(r.id, sizeof(r.id), "R%02d", g_rule_count);
        }

        const char* wp = strstr(rb, "\"when\"");
        if (wp && wp < re) {
          const char* wpe = strstr(wp, "}");
          if (wpe && wpe <= re) {
            const char* ph = strstr(wp, "phase");
            if (ph && ph < wpe) {
              char pv[16]={0};
              if (sscanf(ph, " phase\"%*[^\"\"]\" %15[^\"]", pv)==1) {
                if (strcmp(pv, "fuzz") != 0) {
                  obj_start = NULL;
                  continue;
                }
              }
            }
          }
        }

        const char* sp = strstr(rb, "\"selector\"");
        if (sp && sp < re) {

          const char* sel_start = strchr(sp, '{');
          if (sel_start && sel_start < re) {

            int brace_depth = 0;
            const char* sel_end = NULL;
            for (const char* brace_scan = sel_start; brace_scan < re; brace_scan++) {
              if (*brace_scan == '{') brace_depth++;
              else if (*brace_scan == '}') {
                brace_depth--;
                if (brace_depth == 0) {
                  sel_end = brace_scan + 1;
                  break;
                }
              }
            }

            if (sel_end && sel_end <= re) {
              parse_selector_block(&r.sel, sel_start, sel_end);
            }
          }
        }

        const char* ap = strstr(rb, "\"actions\"");
        if (ap && ap < re) {
          const char* q = strchr(ap, '[');
          const char* abe = NULL;
          if (q && q < re) {
            int depth = 0;
            const char* action_scan = q;
            while (action_scan && action_scan < re) {
              char c = *action_scan;
              if (c == '[') depth++;
              else if (c == ']') {
                depth--;
                if (depth == 0) {
                  abe = action_scan;
                  break;
                }
              }
              action_scan++;
            }
          }
          if (abe) {
            r.n_actions = parse_actions(r.actions, MAX_ACTIONS, q, abe);
          }
        }

        const char* lg = strstr(rb, "\"log\"");
        r.log = (lg && lg < re) ? json_bool_at(lg, 1) : 1;

        g_rules[g_rule_count++] = r;
        obj_start = NULL;
      }
    }
  }

  free(js);

}

static int get_ngap_procedure_code(const uint8_t* b, unsigned int len) {

  unsigned int L = len < 128 ? len : 128;
  for (unsigned int i=0; i+1<L; i++) {

    if ((b[i]==0x00 || b[i]==0x20) && (b[i+1] <= 0x80)) {
      return (int)b[i+1];
    }
  }
  return -1;
}

static int ngap_has_ie38(const uint8_t* b, unsigned int len) {

  const uint8_t* p = find_nas_7e(b, len);
  return p ? 1 : 0;
}

static int nas_outer_sht(const uint8_t* p7e, const uint8_t* end) {
  if (!p7e || p7e+2>end) return -1;
  return p7e[1] & 0x0F;
}
static const uint8_t* nas_plain_start(const uint8_t* p7e, const uint8_t* end){
  if (!p7e || p7e+1 >= end) return NULL;
  uint8_t sht = p7e[1] & 0x0F;
  if (sht == 0) {
    return p7e + 2;
  } else if (sht <= 7) {
    if (p7e + 6 >= end) return NULL;
    return (p7e + 6) + 2;
  }
  return NULL;
}

static int nas_inner_mt_at(const uint8_t* b, unsigned int len) {
  const uint8_t* p7e = find_nas_7e(b, len);
  if (!p7e) return -1;
  const uint8_t* plain = nas_plain_start(p7e, b+len);
  if (!plain || plain+1>=b+len) return -1;
  return (int)plain[0];
}

static int nas_find_ie_simple(const uint8_t* b, unsigned int len, uint8_t iei, const uint8_t** out_val, unsigned int* out_len) {
  const uint8_t* p7e = find_nas_7e(b, len);
  if (!p7e) return 0;
  const uint8_t* cur = nas_plain_start(p7e, b+len);
  if (!cur) return 0;

  if (cur+1 >= b+len) return 0;
  cur = cur + 1;

  while (cur+2 <= b+len) {
    uint8_t tag = cur[0];
    if (cur+1 >= b+len) break;
    uint8_t l = cur[1];
    const uint8_t* val = cur + 2;
    if (val + l > b + len) break;
    if (tag == iei) {
      *out_val = val; *out_len = l; return 1;
    }
    cur = val + l;
  }
  return 0;
}

static int condition_match(const char* field, const int* values, int n_values,
                          const uint8_t* buf, unsigned int len) {
  if (!field) return 0;

  if (strcmp(field, "ngap.procedure_code") == 0) {
    int pc = get_ngap_procedure_code_v15(buf, len);
    if (pc < 0) return 0;
    for (int i = 0; i < n_values; i++) {
      if (pc == values[i]) {

        return 1;
      }
    }

    return 0;
  }

  if (strcmp(field, "nas.message_type") == 0) {
    int range_len;
    unsigned char* mt_ptr = find_nas_message_type_smart(buf, len, &range_len);
    if (!mt_ptr || range_len != 1) return 0;
    int mt = (int)*mt_ptr;
    for (int i = 0; i < n_values; i++) {
      if (mt == values[i]) {

        return 1;
      }
    }
    return 0;
  }

  if (strncmp(field, "has_loc:", 8) == 0) {
    const char* loc = field + 8;
    unsigned char* ptr = kn_resolve_loc_ptr((uint8_t*)buf, len, loc);
    int result = ptr ? 1 : 0;

    return result;
  }

  return 0;
}

int selector_match(const selector_t* s, const uint8_t* b, unsigned int len) {
  if (!s) return 0;

  if (s->logic_type == 1) {
    for (int i = 0; i < s->n_conditions; i++) {
      if (condition_match(s->conditions[i].field, s->conditions[i].values,
                         s->conditions[i].n_values, b, len)) {

        return 1;
      }
    }
    return 0;
  }

  if (s->logic_type == 2) {
    for (int i = 0; i < s->n_conditions; i++) {
      if (!condition_match(s->conditions[i].field, s->conditions[i].values,
                          s->conditions[i].n_values, b, len)) {

        return 0;
      }
    }

    return 1;
  }

  if (s->ngap_proc >= 0) {
    int pc = get_ngap_procedure_code(b, len);

    if (pc < 0 || pc != s->ngap_proc) return 0;
  }

  for (int i=0; i<8 && s->ie_present[i]>=0; i++) {
    if (s->ie_present[i]==38) {
      int has38 = ngap_has_ie38(b, len);

      if (!has38) return 0;
    }
  }

  if (s->nas_outer_sht >= 0) {
    const uint8_t* p7e = find_nas_7e(b, len);
    if (!p7e) return 0;
    int sht = nas_outer_sht(p7e, b+len);

    if (sht != s->nas_outer_sht) return 0;
  }

  if (s->nas_inner_mt >= 0) {
    int mt = nas_inner_mt_at(b, len);

    if (mt < 0 || mt != s->nas_inner_mt) return 0;
  }

  if (s->has_loc[0]) {

    unsigned char* p = kn_resolve_loc_ptr((uint8_t*)b, len, s->has_loc);
    if (!p) {

      return 0;
    }

  }

  return 1;
}

static int get_ngap_procedure_code_v15(const uint8_t* buf, unsigned int len) {
  if (!buf || len < 2) return -1;

  if (buf[0] == 0x00 || buf[0] == 0x20) {
    return (int)buf[1];
  }

  return -1;
}

static unsigned char* find_nas_message_type_smart(const uint8_t* buf, unsigned int len, int* range_len) {
  const uint8_t* p7e = find_nas_7e(buf, len);


  if (!p7e || p7e + 2 >= buf + len) {
    *range_len = 0;

    return NULL;
  }

  *range_len = 1;

  uint8_t sec_hdr_type = p7e[1] & 0x0F;

  if (sec_hdr_type == 0x00) {

    if (p7e + 2 < buf + len) {
      return (unsigned char*)(p7e + 2);
    }
  } else if (sec_hdr_type >= 0x01 && sec_hdr_type <= 0x04) {

    const uint8_t* inner_start = p7e + 6;

    for (const uint8_t* scan = inner_start; scan + 2 < buf + len; scan++) {
      if (scan[0] == 0x7E && (scan[1] & 0x0F) == 0x00) {

        if (scan + 2 < buf + len) {
          return (unsigned char*)(scan + 2);
        }
      }
    }
  }

  *range_len = 0;
  return NULL;
}

static unsigned char* kn_resolve_loc_ptr(uint8_t* b, unsigned int len, const char* loc) {
  if (!loc || !b) return NULL;

  if (strstr(loc, "ngap.procedure_code")) {
    if (len >= 2 && (b[0] == 0x00 || b[0] == 0x20)) {
      return b + 1;
    }
    return NULL;
  }

  if (strstr(loc, "nas.message_type")) {
    int range_len;
    return find_nas_message_type_smart(b, len, &range_len);
  }

  const uint8_t* p7e = find_nas_7e(b, len);
  if (!p7e) return NULL;

  if (strstr(loc, ".nas.inner.mt")) {
    const uint8_t* plain = nas_plain_start(p7e, b+len);
    if (!plain || plain+1>=b+len) return NULL;
    return (unsigned char*)plain;
  }

  const char* iep = strstr(loc, ".nas.ie(");
  if (iep) {
    int iei = -1; sscanf(iep, ".nas.ie(%x)", &iei);
    if (iei>=0 && iei<=255) {
      const uint8_t* val=NULL; unsigned int vlen=0;
      if (nas_find_ie_simple(b, len, (uint8_t)iei, &val, &vlen)) {
        const char* bp = strstr(loc, ".bytes[");
        if (!bp) bp = strstr(loc, ".byte[");
        int k=-1;
        if (bp && sscanf(bp, ".%*[^[][%d]", &k)==1 && k>=0 && (unsigned)k<vlen) {
          return (unsigned char*)(val + k);
        }
      }
    }
  }
  return NULL;
}

void apply_action_on_ptr(unsigned char* ptr, action_t* a) {
  if (!ptr || !a || !a->op) {

    return;
  }


  switch (a->op) {
	case OP_BIT_FLIP: {
	  double p = (a->prob > 0.0 && a->prob < 1.0) ? a->prob : 0.2;

	  for (int bit = 0; bit < 8; ++bit) {
	    if ((double)rand() / RAND_MAX < p) {
	      *ptr ^= (1u << bit);
	    }
	  }

	  break;
	}

    case OP_ENUM_SET: {

      if (a->n_values > 0) {
        int selected_idx = rnd(a->n_values);
        unsigned char new_val = a->values[selected_idx];
        *ptr = new_val;
      }
      break;
    }

    case OP_SET_BYTE: {

      if (a->n_values > 0) {
        *ptr = a->values[0];
      }
      break;
    }

    case OP_SET_BYTES: {

      if (a->n_values > 0) {
        *ptr = a->values[0];
      }
      break;
    }

    default:

      break;
  }
}

static void knowledge_rules_init_once(void) {
  static int inited = 0; if (inited) return;
  inited = 1;
  if (g_knowledge_on) knowledge_load_rules();
}

int net_send(int sockfd, struct timeval timeout, char *mem, unsigned int len) {

    if (len > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "ERROR: Message too large for sending: %u > %d\n", len, MAX_MESSAGE_SIZE);
        return -1;
    }

    uint8_t *temp_buf = ck_alloc(len + 16);
    if (!temp_buf) return -1;
    memcpy(temp_buf, mem, len);
    size_t temp_len = len;

    replace_ngap_id(&temp_buf, &temp_len);


    if (has_latest_challenge && is_auth_response_message((char *)temp_buf, temp_len)) {
        inject_res_into_auth_response((char *)temp_buf, temp_len);
    }
    if (has_latest_challenge) {
        insert_mac_into_nas(temp_buf, temp_len);
    }

    unsigned int byte_count = 0;
    struct pollfd pfd = { sockfd, POLLOUT, 0 };
    if (poll(&pfd, 1, 1) > 0 && (pfd.revents & POLLOUT)) {
        while (byte_count < temp_len) {
            int sent = send(sockfd, temp_buf + byte_count,
                            temp_len - byte_count, MSG_NOSIGNAL);
            if (sent <= 0) break;
            byte_count += sent;
        }
    }
    ck_free(temp_buf);
    return byte_count;
}

void save_regions_to_file(region_t *regions, unsigned int region_count, unsigned char *fname)
{
  int fd;
  FILE* fp;

  fd = open(fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

  if (fd < 0) return;

  fp = fdopen(fd, "w");

  if (!fp) {
    close(fd);
    return;
  }

  int i;

  for(i=0; i < region_count; i++) {
     fprintf(fp, "Region %d - Start: %d, End: %d\n", i, regions[i].start_byte, regions[i].end_byte);
  }

  fclose(fp);
}

int str_split(char* a_str, const char* a_delim, char **result, int a_count)
{
	char *token;
	int count = 0;


	char* tmp1 = strdup(a_str);
	token = strtok(tmp1, a_delim);

	while (token != NULL)
	{
		count++;
		token = strtok(NULL, a_delim);
	}

	if (count != a_count)
	{
		return 1;
	}

	count = 0;

	token = strtok(a_str, a_delim);

	while (token != NULL)
	{
		result[count] = token;
		count++;
		token = strtok(NULL, a_delim);
	}

	free(tmp1);
	return 0;
}

void str_rtrim(char* a_str)
{
	char* ptr = a_str;
	int count = 0;
	while ((*ptr != '\n') && (*ptr != '\t') && (*ptr != ' ') && (count < strlen(a_str))) {
		ptr++;
		count++;
	}
	if (count < strlen(a_str)) {
		*ptr = '\0';
	}
}

int parse_net_config(u8* net_config, u8* protocol, u8** ip_address, u32* port)
{
  char  buf[80];
  char **tokens;
  int tokenCount = 3;

  tokens = (char**)malloc(sizeof(char*) * (tokenCount));

  if (strlen(net_config) > 80) return 1;

  strncpy(buf, net_config, strlen(net_config));
   str_rtrim(buf);

  if (!str_split(buf, "/", tokens, tokenCount))
  {
      if (!strcmp(tokens[0], "tcp:")) {
	  *protocol = PRO_TCP;
	} else if (!strcmp(tokens[0], "udp:")) {
	  *protocol = PRO_UDP;
	} else if (!strcmp(tokens[0], "sctp:")) {
	  *protocol = PRO_SCTP;
	} else return 1;

      *ip_address = strdup(tokens[1]);

      *port = atoi(tokens[2]);
      if (*port == 0) return 1;
  } else return 1;
  free(tokens);
  return 0;
}

u8* state_sequence_to_string(unsigned int *stateSequence, unsigned int stateCount) {
  u32 i = 0;

  u8 *out = NULL;

  char strState[STATE_STR_LEN];
  size_t len = 0;
  for (i = 0; i < stateCount; i++) {

    if ((i >= 2) && (stateSequence[i] == stateSequence[i - 1]) && (stateSequence[i] == stateSequence[i - 2])) continue;
    unsigned int stateID = stateSequence[i];
    if (i == stateCount - 1) {
      snprintf(strState, STATE_STR_LEN, "%d", (int) stateID);
    } else {
      snprintf(strState, STATE_STR_LEN, "%d-", (int) stateID);
    }
    out = (u8 *)ck_realloc(out, len + strlen(strState) + 1);
    memcpy(&out[len], strState, strlen(strState) + 1);
    len=strlen(out);

    if (len > 150 && (i + 1 < stateCount)) {
      snprintf(strState, STATE_STR_LEN, "%s", "end-at-");
      out = (u8 *)ck_realloc(out, len + strlen(strState) + 1);
      memcpy(&out[len], strState, strlen(strState) + 1);
      len=strlen(out);

      snprintf(strState, STATE_STR_LEN, "%d", (int) stateSequence[stateCount - 1]);
      out = (u8 *)ck_realloc(out, len + strlen(strState) + 1);
      memcpy(&out[len], strState, strlen(strState) + 1);
      len=strlen(out);
      break;
    }
  }
  return out;
}

void hexdump(unsigned char *msg, unsigned char * buf, int start, int end) {
  printf("%s : ", msg);
  for (int i=start; i<=end; i++) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}

u32 read_bytes_to_uint32(unsigned char* buf, unsigned int offset, int num_bytes) {
  u32 val = 0;
  for (int i=0; i<num_bytes; i++) {
    val = (val << 8) + buf[i+offset];
  }
  return val;
}
