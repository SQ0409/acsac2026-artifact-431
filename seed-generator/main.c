#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ASN_NGAP_NGSetupRequest.h"
#include "ASN_NGAP_ProtocolIE-Container.h"
#include "ASN_NGAP_ProtocolIE-Field.h"
#include "ASN_NGAP_ProtocolIE-ID.h"
#include "ASN_NGAP_Criticality.h"

#include "ASN_NGAP_GlobalRANNodeID.h"
#include "ASN_NGAP_GlobalGNB-ID.h"
#include "ASN_NGAP_RANNodeName.h"
#include "ASN_NGAP_SupportedTAList.h"
#include "ASN_NGAP_SupportedTAItem.h"
#include "ASN_NGAP_BroadcastPLMNItem.h"
#include "ASN_NGAP_PagingDRX.h"

// 切片相关
#include "ASN_NGAP_SliceSupportItem.h"
#include "ASN_NGAP_S-NSSAI.h"
#include "ASN_NGAP_SST.h"

// 外层 PDU（影响前导 0015....：00=initiating, 0x15=procedureCode）
#include "ASN_NGAP_NGAP-PDU.h"
#include "ASN_NGAP_InitiatingMessage.h"

#include <OCTET_STRING.h>
#include <BIT_STRING.h>
#include <asn_application.h>
#include <per_encoder.h>

static void bytes_to_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02X", buf[i]);
    printf("\n");
}

int main(void) {
    // ============ NGSetupRequest 主体 ============
    ASN_NGAP_NGSetupRequest_t msg; 
    memset(&msg, 0, sizeof(msg));

    /* ---------- IE #1: GlobalRANNodeID ---------- */
    struct ASN_NGAP_NGSetupRequestIEs *ie1 = calloc(1, sizeof(*ie1));
    if (!ie1) { perror("calloc ie1"); return 1; }

    ie1->id = ASN_NGAP_ProtocolIE_ID_id_GlobalRANNodeID;  /* 固定: 27 */
    ie1->criticality = ASN_NGAP_Criticality_reject;
    ie1->value.present = ASN_NGAP_NGSetupRequestIEs__value_PR_GlobalRANNodeID;

    ASN_NGAP_GlobalRANNodeID_t *grnid = &ie1->value.choice.GlobalRANNodeID;
    grnid->present = ASN_NGAP_GlobalRANNodeID_PR_globalGNB_ID;
    grnid->choice.globalGNB_ID = calloc(1, sizeof(*grnid->choice.globalGNB_ID));
    if (!grnid->choice.globalGNB_ID) { perror("calloc globalGNB_ID"); return 1; }
    ASN_NGAP_GlobalGNB_ID_t *gnb = grnid->choice.globalGNB_ID;

    /* 🔧 可改 1：PLMN（影响 hex 中 globalGNB-ID 下的 3 字节，如默认 00 F1 10）
       - 必须 3 字节 BCD（MCC/MNC）
       - 同时也别忘了 IE#3 的 BroadcastPLMNItem 里还有一个 PLMN（可相同/不同）
    */
    /* Public Open5GS example PLMN (MCC 999 / MNC 70). Replace all three BCD
       bytes with the PLMN configured in the reviewer's Open5GS instance. */
    const uint8_t plmn[3] = {0x99, 0xF9, 0x07};
    if (OCTET_STRING_fromBuf(&gnb->pLMNIdentity, (const char*)plmn, sizeof(plmn)) != 0) {
        fprintf(stderr, "set PLMNIdentity failed\n");
        return 1;
    }

    /* 🔧 可改 2：gNB-ID（影响 globalGNB-ID 里的 BIT STRING）
       - 32bit 示例（bits_unused=0，buf 4 字节）
       - 想改位长：22/24/28/32 都行；非 8 的倍数要设置 bits_unused
         例：22bit -> size=3, bits_unused=2；buf 需高位对齐，右侧留 unused 位
    */
    /* Public example gNB ID. Replace with the local test gNB identifier. */
    const uint8_t gnbid_bytes[4] = {0x00, 0x00, 0x00, 0x01};
    gnb->gNB_ID.present = ASN_NGAP_GNB_ID_PR_gNB_ID;
    gnb->gNB_ID.choice.gNB_ID.size = 4;                       // 🔧 改位长请同步改 size
    gnb->gNB_ID.choice.gNB_ID.buf  = malloc(4);
    if (!gnb->gNB_ID.choice.gNB_ID.buf) { perror("malloc gnbid"); return 1; }
    memcpy(gnb->gNB_ID.choice.gNB_ID.buf, gnbid_bytes, 4);
    gnb->gNB_ID.choice.gNB_ID.bits_unused = 0;                // 🔧 非8倍数位长时改 0..7

    if (ASN_SEQUENCE_ADD(&msg.protocolIEs.list, ie1) != 0) {
        fprintf(stderr, "ASN_SEQUENCE_ADD ie1 failed\n");
        return 1;
    }

    /* ---------- IE #2: RANNodeName ---------- */
    struct ASN_NGAP_NGSetupRequestIEs *ie2 = calloc(1, sizeof(*ie2));
    if(!ie2) { perror("calloc ie2"); return 1; }

    ie2->id = ASN_NGAP_ProtocolIE_ID_id_RANNodeName;  /* 固定: 82 */
    ie2->criticality = ASN_NGAP_Criticality_ignore;
    ie2->value.present = ASN_NGAP_NGSetupRequestIEs__value_PR_RANNodeName;
    ASN_NGAP_RANNodeName_t *ran_node_name = &ie2->value.choice.RANNodeName;

    /* 🔧 可改 3：RANNodeName 文本（影响中间那串 ASCII）
       - 任意 UTF-8/ASCII，建议几十字节内
    */
    /* Descriptive label only; keep it consistent with the local setup. */
    const char *node_name = "artifact-gnb";
    if (OCTET_STRING_fromBuf(ran_node_name, node_name, (int)strlen(node_name)) != 0) {
        fprintf(stderr, "set RANNodeName failed\n");
        return 1;
    }

    if (ASN_SEQUENCE_ADD(&msg.protocolIEs.list, ie2) != 0) {
        fprintf(stderr, "ASN_SEQUENCE_ADD ie2 failed\n");
        return 1;
    }

    /* ---------- IE #3: SupportedTAList（含切片） ---------- */
    struct ASN_NGAP_NGSetupRequestIEs *ie3 = calloc(1, sizeof(*ie3));
    if(!ie3) { perror("calloc ie3"); return 1; }

    ie3->id = ASN_NGAP_ProtocolIE_ID_id_SupportedTAList;  /* 固定: 102 */
    ie3->criticality = ASN_NGAP_Criticality_reject;
    ie3->value.present = ASN_NGAP_NGSetupRequestIEs__value_PR_SupportedTAList;
    ASN_NGAP_SupportedTAList_t *supported_ta_list = &ie3->value.choice.SupportedTAList;

    /* ── 一个 TAItem（可复制此段生成多个 TAItem） */
    struct ASN_NGAP_SupportedTAItem *ta_item = calloc(1, sizeof(*ta_item));
    if (!ta_item) { perror("calloc ta_item"); return 1; }

    /* 🔧 可改 4：TAC（3 字节 OCTET STRING，影响 00 00 01）
       - 必须正好 3 字节
    */
    /* Public example TAC. Replace all three bytes for the local test TA. */
    const uint8_t tac3[3] = {0x00, 0x00, 0x01};
    if (OCTET_STRING_fromBuf(&ta_item->tAC, (const char *)tac3, (int)sizeof(tac3)) != 0) {
        fprintf(stderr, "set TAC failed\n");
        return 1;
    }

    /* 🔧 可改 5：broadcastPLMNList 的个数和各项内容
       - 这里演示 1 个 BroadcastPLMNItem；要多个就循环新建 bitem 并 ADD
    */
    /* Broadcast PLMN; normally the same public test PLMN as above. */
    const uint8_t plmn2[3] = {0x99, 0xF9, 0x07};
    struct ASN_NGAP_BroadcastPLMNItem *bitem = calloc(1, sizeof(*bitem));
    if (!bitem) { perror("calloc BroadcastPLMNItem"); return 1; }

    if (OCTET_STRING_fromBuf(&bitem->pLMNIdentity, (const char*)plmn2, (int)sizeof(plmn2)) != 0) {
        fprintf(stderr, "set BroadcastPLMNItem.pLMNIdentity failed\n");
        return 1;
    }

    /* 🔧 可改 6：tAISliceSupportList（切片个数/内容）
       - 至少 1 个；每个切片设置 sST(必需,1字节)；可选 sD(3字节)
       - 想要多个切片：重复 new slice_item + ADD
    */
    ASN_NGAP_SliceSupportItem_t *slice_item = calloc(1, sizeof(*slice_item));
    if(!slice_item) { perror("calloc SliceSupportItem"); return 1; }

    // sST = 0x01（eMBB 之类，按你网络定义）
    /* Public example slice. Replace SST/SD with the Open5GS slice values. */
    const uint8_t sst_val[1] = {0x01};
    if(OCTET_STRING_fromBuf(&slice_item->s_NSSAI.sST, (const char*)sst_val, 1) != 0) {
        fprintf(stderr, "set S-NSSAI.sST failed\n");
        return 1;
    }

    /* SD is optional. Keep it absent for compatibility with the default
       Open5GS profile (which advertises SST=1 without an SD). To use an SD,
       allocate sD and set its three bytes to the AMF's configured value. */
    /*
    slice_item->s_NSSAI.sD = calloc(1, sizeof(OCTET_STRING_t));
    if (!slice_item->s_NSSAI.sD) { perror("calloc sD"); return 1; }
    const uint8_t sd_val[3] = {0x00, 0x00, 0x01};
    if (OCTET_STRING_fromBuf(slice_item->s_NSSAI.sD, (const char*)sd_val, 3) != 0) {
        fprintf(stderr, "set S-NSSAI.sD failed\n");
        return 1;
    }
    */

    if(ASN_SEQUENCE_ADD(&bitem->tAISliceSupportList.list, slice_item) != 0) {
        fprintf(stderr, "ASN_SEQUENCE_ADD SliceSupportItem failed\n");
        return 1;
    }

    if (ASN_SEQUENCE_ADD(&ta_item->broadcastPLMNList.list, bitem) != 0) {
        fprintf(stderr, "ASN_SEQUENCE_ADD BroadcastPLMNItem failed\n");
        return 1;
    }

    // 若需要多个 TAItem：复制从"// ── 一个 TAItem"开始这段，再 ADD
    if (ASN_SEQUENCE_ADD(&supported_ta_list->list, ta_item) != 0) {
        fprintf(stderr, "ASN_SEQUENCE_ADD SupportedTAItem failed\n");
        return 1;
    }

    if (ASN_SEQUENCE_ADD(&msg.protocolIEs.list, ie3) != 0) {
        fprintf(stderr, "ASN_SEQUENCE_ADD ie3 failed\n");
        return 1;
    }

    /* ---------- IE #4: DefaultPagingDRX（枚举） ---------- */
    struct ASN_NGAP_NGSetupRequestIEs *ie4 = calloc(1, sizeof(*ie4));
    if (!ie4) { perror("calloc ie4"); return 1; }

    ie4->id = ASN_NGAP_ProtocolIE_ID_id_DefaultPagingDRX;  /* 固定: 21 */
    ie4->criticality = ASN_NGAP_Criticality_ignore;
    ie4->value.present = ASN_NGAP_NGSetupRequestIEs__value_PR_PagingDRX;

    /* 🔧 可改 7：PagingDRX（影响末尾的那个枚举值编码）
       - 取值：ASN_NGAP_PagingDRX_v32 / v64 / v128 / v256
    */
    ie4->value.choice.PagingDRX = ASN_NGAP_PagingDRX_v128;

    if (ASN_SEQUENCE_ADD(&msg.protocolIEs.list, ie4) != 0) {
        fprintf(stderr, "ASN_SEQUENCE_ADD ie4 failed\n");
        return 1;
    }

    // ============ 最外层 NGAP-PDU/initiatingMessage ============
    ASN_NGAP_NGAP_PDU_t pdu;
    memset(&pdu, 0, sizeof(pdu));
    pdu.present = ASN_NGAP_NGAP_PDU_PR_initiatingMessage;  // 固定：00（CHOICE=initiating）

    pdu.choice.initiatingMessage = calloc(1, sizeof(*pdu.choice.initiatingMessage));
    if(!pdu.choice.initiatingMessage) { perror("calloc initiatingMessage"); return 1; }

    struct ASN_NGAP_InitiatingMessage *im = pdu.choice.initiatingMessage;

    /* 🔐 一般不改：procedureCode=21 表示 NGSetup
       - 这两项决定最前面 "00 15 ..." 中的 0x15（procedureCode）
       - 改了就不是 NGSetupRequest 了
    */
    im->procedureCode = 21;  // id-NGSetup（影响前导 0x15）
    im->criticality   = ASN_NGAP_Criticality_reject;

    im->value.present = ASN_NGAP_InitiatingMessage__value_PR_NGSetupRequest;
    im->value.choice.NGSetupRequest = msg;  // 把上面构好的 NGSetupRequest 塞进去

    // ============ 编码最外层 PDU 并输出 HEX ============
    uint8_t buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    asn_enc_rval_t ec = aper_encode_to_buffer(
        &asn_DEF_ASN_NGAP_NGAP_PDU, NULL, &pdu, buffer, sizeof(buffer)
    );
    if (ec.encoded < 0) {
        fprintf(stderr, "PER encoding failed: %s\n",
                ec.failed_type ? ec.failed_type->name : "unknown");
        return 1;
    }

    size_t nbytes = (ec.encoded + 7) / 8;
    bytes_to_hex(buffer, nbytes);
    return 0;
}
