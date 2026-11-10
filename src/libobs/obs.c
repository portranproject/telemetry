/**
 * obs.c
 * : 관측 엔진 - SCTP 메시지에서 단말 상태를 따라가며 관측 이벤트를 냄. 카운팅은 하지 않음
 *
 * [1] 파이프라인에서의 위치.
 *
 *     libcap --패킷--> libsctp --SCTP 메시지--> [libobs] --관측 이벤트--> libtelemetry --> libsink
 *                                                  |
 *                                 libap / librrc / libnas (PDU 해석)
 *
 *     libobs 는 "무슨 일이 일어났나" 만 냄. "몇 번 일어났나" 는 libtelemetry 몫임(TS 28.552 규칙 반영).
 *     추론 규칙도 여기 두지 않음 - 이 계층은 한 메시지만 보고, 추론은 주기와 짝을 봐야 하기 때문임.
 *
 * [2] 표와 키. 이 파일 앞부분이 네 표를 만들고 찾고 지움.
 *
 *                     키                                    언제 사라지나
 *     ue_states       (SCTP 연결, gNB-DU UE F1AP ID)        RELEASE COMPLETE, 유예 만료, TTL, 축출
 *     n2_states       (SCTP 연결, RAN-UE-NGAP-ID)           같음. SCTP 연결이 AMF 를 대리함
 *     assoc_records   (SCTP 연결)                           연결 종료. gNB-DU ID 와 셀 목록을 들고 있음
 *     corr_keys       (셀, 수립 원인, NAS 길이, NAS 해시)    짝 시간창 만료
 *
 *     참조는 N2 에서 F1 한 방향뿐임. 되찾을 때 키만 쓰지 않고 레코드 번호까지 맞춰 보는 이유는,
 *     슬롯이 재사용돼 다른 단말이 그 자리에 들어온 경우를 가려내기 위함임.
 *
 *       n2_states --has_f1_pair--> (연결, du_ue_id, record_id) --ue_find_record_id--> ue_states
 *
 * [3] 단말 표의 상태.
 *
 *     (없음) --INITIAL UL RRC--> [열림] --RELEASE COMMAND--> [해제중] --COMPLETE--> (없음)
 *                                   |                            |
 *                                   |                      유예 만료 ----------> (없음)
 *                                   +--같은 키 재등장--> 옛 레코드 버리고 새로 (UE_REPLACED)
 *                                   +--표 꽉 참------> 가장 오래된 것 축출 (UE_EVICTED)
 *
 *     RELEASE COMMAND 에서 바로 지우지 않는 이유: 그 시점에 지우면 아직 안 끝난 해제를
 *     끝난 것으로 세게 됨. COMPLETE 를 못 보면 유예 뒤에 정리함.
 *
 * [4] 가시성 관문. AS 보안이 켜진 뒤의 SRB1 은 암호문이므로 해석하지 않음.
 *
 *     암호문을 평문으로 읽으면 내용이 '그럴듯하게' 풀릴 때가 있음. 우리는 참여자가 아니라
 *     수동 관측자라 다시 달라고 할 수 없으므로, 못 읽는 것은 못 읽었다고 세는 쪽이 맞음.
 *     그래서 두 걸음임 - (1) 값을 담지 않음, (2) 담지 않은 이유마다 계수기를 올림.
 *
 * [5] F1 과 N2 짝짓기. 같은 단말이 두 인터페이스에서 다른 번호를 쓰므로 내용으로 맞춤.
 *
 *     F1 쪽 RRCSetupComplete 가 먼저 와서 대기열에 들어가고, N2 쪽 INITIAL UE MESSAGE 가
 *     그 키를 찾아감. 대기열에 둘 이상이면 고르지 않고 모호로 셈 - 절반이 오귀속이 되기 때문임.
 *
 * [6] 계약. 스레드 하나. 콜백으로 넘기는 이벤트와 그 안의 바이트는 콜백이 돌아올 때까지만 유효함.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "obs.h"
#include <libap/ap.h>
#include <librrc/rrc.h>
#include <libnas/nas.h>

// 이벤트 종류 -> 점 표기 이름. 출력과 시험에서 이벤트를 글자로 가리킬 때 씀 (types.h 선언)
const char *tr_event_name(enum tr_event_kind kind)
{
	static const char *const names[TR_EVENT__COUNT] = {
		[TR_EVENT_RRC_SETUP_REQUEST]="E.RRC.SETUP_REQUEST", [TR_EVENT_RRC_REEST_REQUEST]="E.RRC.REEST_REQUEST",
		[TR_EVENT_RRC_RESUME_REQUEST]="E.RRC.RESUME_REQUEST", [TR_EVENT_RRC_SETUP]="E.RRC.SETUP", [TR_EVENT_RRC_REJECT]="E.RRC.REJECT",
		[TR_EVENT_RRC_SETUP_COMPLETE]="E.RRC.SETUP_COMPLETE", [TR_EVENT_RRC_SMC]="E.RRC.SMC", [TR_EVENT_RRC_SMC_COMPLETE]="E.RRC.SMC_COMPLETE",
		[TR_EVENT_RRC_SMC_FAILURE]="E.RRC.SMC_FAILURE", [TR_EVENT_RRC_REEST]="E.RRC.REEST", [TR_EVENT_RRC_REEST_COMPLETE]="E.RRC.REEST_COMPLETE",
		[TR_EVENT_RRC_RESUME]="E.RRC.RESUME", [TR_EVENT_RRC_RESUME_COMPLETE]="E.RRC.RESUME_COMPLETE", [TR_EVENT_RRC_RELEASE]="E.RRC.RELEASE",
		[TR_EVENT_RRC_DCCH_OPAQUE]="E.RRC.DCCH_OPAQUE", [TR_EVENT_RRC_OTHER]="E.RRC.OTHER", [TR_EVENT_NAS_F1]="E.NAS.F1",
		[TR_EVENT_F1_UE_CTX_SETUP]="E.F1.UE_CTX_SETUP", [TR_EVENT_F1_UE_CTX_RELEASE_REQ]="E.F1.UE_CTX_RELEASE_REQ",
		[TR_EVENT_F1_UE_CTX_RELEASE_CMD]="E.F1.UE_CTX_RELEASE_CMD", [TR_EVENT_F1_UE_CTX_RELEASE_COMPLETE]="E.F1.UE_CTX_RELEASE_COMPLETE",
		[TR_EVENT_F1_RESET]="E.F1.RESET", [TR_EVENT_SCTP_ASSOC_END]="E.SCTP.ASSOC_END", [TR_EVENT_NG_INITIAL_UE_MESSAGE]="E.NG.INITIAL_UE_MESSAGE",
		[TR_EVENT_NG_AMF_DL_UE_MSG]="E.NG.AMF_DL_UE_MSG", [TR_EVENT_NG_NAS]="E.NG.NAS", [TR_EVENT_NG_UE_CTX_RELEASE_CMD]="E.NG.UE_CTX_RELEASE_CMD", [TR_EVENT_NG_UE_CTX_RELEASE_COMPLETE]="E.NG.UE_CTX_RELEASE_COMPLETE",
		[TR_EVENT_NG_OVERLOAD_START]="E.NG.OVERLOAD_START", [TR_EVENT_NG_OVERLOAD_STOP]="E.NG.OVERLOAD_STOP",
		[TR_EVENT_NG_RRC_STATE_REPORT]="E.NG.RRC_STATE_REPORT", [TR_EVENT_F1_UE_TRANSFER]="E.F1.UE_TRANSFER",
		[TR_EVENT_RRC_RECONFIG_SEC]="E.RRC.RECONFIG_SEC",
		[TR_EVENT_F1_ALG_CHANGE_OPPORTUNITY]="E.F1.ALG_CHANGE_OPPORTUNITY", [TR_EVENT_F1_CELL_CONFIG]="E.F1.CELL_CONFIG",
		[TR_EVENT_NG_SETUP]="E.NG.SETUP", [TR_EVENT_OBS_UE_EVICTED]="E.OBS.UE_EVICTED",
		[TR_EVENT_OBS_UE_REPLACED]="E.OBS.UE_REPLACED",
		[TR_EVENT_RRC_MALFORMED]="E.RRC.MALFORMED", [TR_EVENT_AP_DECODE_FAIL]="E.AP.DECODE_FAIL",
		[TR_EVENT_F1_INITIAL_UL]="E.F1.INITIAL_UL", [TR_EVENT_F1_SETUP]="E.F1.SETUP",
	};
	if (kind <= 0 || kind >= TR_EVENT__COUNT) return "?";
	return names[kind] ? names[kind] : "?";
}

// ---- 기본값 -----------------------------------------------------------------------------
#define DEF_UE_CAPACITY        131072u
#define DEF_ASSOC_CAPACITY     1024u
#define DEF_UE_TTL_S       600u
#define DEF_N2_GRACE_S     5u

/* F1AP 절차 코드 — 값은 1차 출처 asn1/f1ap-18.8.0.asn:17762-17775 (ProcedureCode ::= n) 에서 확인.
 * 이벤트를 내는 절차 9개에 P_UE_CTX_MOD_REQUIRED 를 더해 둠. 이 절차는 이벤트를 내지 않지만 방향 판정에
 * 필요함 - UEContextModificationConfirm 은 RRCContainer 를 담는 유일한 successfulOutcome 이라(위 ASN.1
 * 전수 확인) 목록에 없으면 기본 분기로 떨어져 CU->DU 메시지가 UP 으로 실림. */
enum { P_RESET=0, P_F1_SETUP=1, P_ERROR_INDICATION=2, P_GNBDU_CFG_UPD=3, P_UE_CTX_SETUP=5, P_UE_CTX_RELEASE=6,
	   P_UE_CTX_MOD=7, P_UE_CTX_MOD_REQUIRED=8, P_UE_CTX_REL_REQ=10, P_INITIAL_UL=11,
	   P_DL_RRC=12, P_UL_RRC=13 };

/* SCTP 목적지 포트가 IANA 지정 포트인 방향이 UP. 절차로 방향이 안 정해질 때 쓰는 보조 규칙임.
 * 근거: TS 38.472 §7 "The SCTP Destination Port number value assigned by IANA to be used for F1AP is 38472",
 *       TS 38.412 §7 "… for NGAP is 38412". 두 표준 모두 연결을 여는 쪽(F1=DU, N2=NG-RAN 노드=CU)을 정함. */
#define IANA_PORT_F1AP 38472
#define IANA_PORT_NGAP 38412

/* f1ap_proc_direction: F1AP 절차 코드 + PDU 종류로 방향을 정함. 절차가 방향을 정하지 못하면 TR_DIRECTION_UNKNOWN.
 *   이유: 절차 코드만 보면 응답의 방향을 반대로 싣게 됨. SETUP, MOD, RELEASE 를 전부 DOWN 으로 두면
 *     그 절차의 successfulOutcome(RESPONSE, COMPLETE = DU->CU)까지 DOWN 이 됨. PDU 종류를 같이 봐야
 *     개시와 응답이 갈림.
 *   근거(1차 출처): asn1/f1ap-18.8.0.asn 의 F1AP-ELEMENTARY-PROCEDURE 가 어느 메시지가 INITIATING /
 *     SUCCESSFUL OUTCOME 인지 정함(:506-533, :565-578). 개시 노드는 TS 38.473 §8.2.3(F1 Setup),
 *     §8.3.1(UE Context Setup), §8.3.3(UE Context Release), §8.3.4(UE Context Modification),
 *     §8.3.5(UE Context Modification Required), §8.4.1-3(RRC Transfer)과
 *     TS 38.472 §7("The gNB-DU shall establish the SCTP association").
 *   반환: TR_DIRECTION_DOWN(CU→DU) / TR_DIRECTION_UP(DU→CU) / TR_DIRECTION_UNKNOWN(절차로 안 정해짐 → 와이어 규칙으로).
 *     INITIATING 만 있는 절차에 successfulOutcome 이 오면(문법상 불가, 깨진 PDU) UP/DOWN 을 추측하지 않고 UNKNOWN. */
static enum tr_direction f1ap_proc_direction(long proc_code, enum f1ap_pdu_type pdu_type)
{
	bool initiating = pdu_type == F1AP_PDU_INITIATING;
	switch (proc_code) {
	// CU 가 개시: initiating = CU->DU(DOWN), 응답(successful/unsuccessful) = DU->CU(UP)
	case P_UE_CTX_SETUP:        // Request CU->DU / Response, Failure DU->CU
	case P_UE_CTX_RELEASE:      // Command CU->DU / Complete DU->CU
	case P_UE_CTX_MOD:          // Request CU->DU / Response, Failure DU->CU
		return initiating ? TR_DIRECTION_DOWN : TR_DIRECTION_UP;
	// DU 가 개시: initiating = DU->CU(UP), 응답 = CU->DU(DOWN)
	case P_F1_SETUP:            // Request DU->CU / Response, Failure CU->DU
	case P_GNBDU_CFG_UPD:       // Update DU->CU / Acknowledge, Failure CU->DU
	case P_UE_CTX_MOD_REQUIRED: // Required DU->CU / Confirm, Refuse CU->DU (Confirm 은 RRCContainer 보유)
		return initiating ? TR_DIRECTION_UP : TR_DIRECTION_DOWN;
	// INITIATING 만 있는 절차(ASN.1 에 SUCCESSFUL OUTCOME 이 없음)
	case P_DL_RRC:
		return initiating ? TR_DIRECTION_DOWN : TR_DIRECTION_UNKNOWN;
	case P_UL_RRC: case P_INITIAL_UL: case P_UE_CTX_REL_REQ:
		return initiating ? TR_DIRECTION_UP : TR_DIRECTION_UNKNOWN;
	default:
		/* Reset(0)은 CU 와 DU 가 모두 개시할 수 있어(TS 38.473 §8.2.1) 절차로는 안 정해짐.
		 * 그 밖의 절차는 개시 노드를 1차 출처로 확인하지 않았음 -> 추측하지 않고 미상으로 두고
		 * 와이어 규칙에 넘김. UP 을 돌려주면 확인하지 않은 것을 사실처럼 싣게 됨. */
		return TR_DIRECTION_UNKNOWN;
	}
}

/* wire_rule_direction: 와이어만 보고 방향을 정함.
 *   규칙: 목적지 포트가 그 인터페이스의 IANA 포트인 방향이 UP. F1 은 DU->CU(38472 가 CU), N2 는 CU->AMF(38412 가 AMF).
 *   이유: 절차로 방향이 안 정해질 때(Reset 등) 추측하지 않고 와이어에서 근거를 얻음. 상태가 필요 없어
 *     연결 중간부터 관측해도 쓸 수 있음 - SCTP INIT 을 보낸 쪽으로 가리는 방법은 그 INIT 을 봐야 함.
 *   반환: 양쪽 다 IANA 포트가 아니거나(동적 포트 쌍) 양쪽 다 IANA 포트면 TR_DIRECTION_UNKNOWN(판정 불가, 추측 금지). */
/* direction_pick: 절차 판정과 와이어 판정을 합치는 순수 규칙 — 절차가 정했으면 그것, 아니면 와이어.
 *   이유: 절차가 방향을 정하는 메시지는 정의상 정확하므로 와이어보다 앞섬. 이 세 줄을 따로 둔 까닭은
 *     시험 창(obs_direction_for_test)이 프로덕션과 같은 코드를 쓰게 하려는 것임 - 창이 판정을 복제하면
 *     창은 통과하면서 프로덕션만 틀릴 수 있음. */
static enum tr_direction direction_pick(enum tr_direction proc_direction, enum tr_direction wire_direction)
{
	return (proc_direction != TR_DIRECTION_UNKNOWN) ? proc_direction : wire_direction;
}

static enum tr_direction wire_rule_direction(const struct cap_record *record, enum tr_iface iface)
{
	if (!record) return TR_DIRECTION_UNKNOWN;
	uint16_t iana_port = (iface == TR_IFACE_N2) ? IANA_PORT_NGAP : IANA_PORT_F1AP;
	bool to_iana_port   = record->dst_port == iana_port;
	bool from_iana_port = record->src_port == iana_port;
	if (to_iana_port == from_iana_port) return TR_DIRECTION_UNKNOWN;   // 둘 다 또는 둘 다 아님 -> 가릴 수 없음
	return to_iana_port ? TR_DIRECTION_UP : TR_DIRECTION_DOWN;
}


/* NGAP 절차 코드(TS 38.413 V15.8.0 §9.4.7 Constant Definitions) — N2 이벤트 몫.
 *   값은 1차 출처 asn1/ngap-15.8.0.asn1 의 `id-<절차> ProcedureCode ::= n` 에서 확인했음. */
enum { NP_DL_NAS=4, NP_INITIAL_CONTEXT_SETUP=14, NP_INITIAL_UE_MESSAGE=15, NP_NAS_NON_DELIVERY=19, NP_NG_RESET=20,
	   NP_NG_SETUP=21, NP_OVERLOAD_START=22, NP_OVERLOAD_STOP=23, NP_PAGING=24, NP_PATH_SWITCH=25,
	   NP_PDU_SESSION_SETUP=29, NP_REROUTE_NAS=36, NP_RRC_INACTIVE_TRANSITION=37, NP_UE_CONTEXT_MODIFICATION=40,
	   NP_UE_CONTEXT_RELEASE=41, NP_UPLINK_NAS=46 };

// ---- F1 단말 레코드 ---------------------------------------------------------------------
struct obs_ue_state {
	// 키
	uint32_t assoc_id;
	uint32_t du_ue_id;      bool has_du_ue_id;
	uint32_t cu_ue_id;      bool has_cu_ue_id;   // 하행 메시지에서 학습
	uint64_t du_id;         bool du_id_is_temp;
	uint32_t crnti;         bool has_crnti;
	struct tr_nr_cgi cell;
	enum tr_prior_req prior_req;   // 재수립이나 재개 요청으로 들어왔으면 fallback 수립으로 봄
	int est_cause;                 // RRCSetupRequest 의 establishmentCause. 짝짓기 키에 들어감. -1 모름
	/* 전역에서 단조 증가하는 레코드 번호. 슬롯이 재사용돼도 번호는 재사용되지 않으므로,
	   짝을 되찾을 때 다른 단말이 우연히 같은 슬롯에 들어온 것을 가려냄 */
	uint64_t record_id;

	// 가시성 관문이 보는 보안 상태
	enum tr_sec_state rrc_sec_state;
	int ciph_alg;           // -1 모름, 0 = NEA0
	int nas_ciph_alg;       // -1 모름, 0 = 5G-EA0
	// 수명
	uint64_t created_ns, last_ns;
	bool connected;         // RRCSetupComplete 또는 RRCReestablishmentComplete 이후
	bool late_join;         // INITIAL UL 을 못 보고 등장 -> AS 보안 상태를 모름. 가시성 관문을 닫음
	/* 저장된 AS 보안 컨텍스트를 되살리는 두 경로. 둘 다 우리가 수립 때의 SECURITY MODE COMMAND 를
	   보지 못했으므로 알고리즘을 모름 -> 평문으로 가정하지 않고 암호화된 DCCH 는 해석하지 않음.
	     resumed            RRCResumeRequest 를 봄
	     reest_reactivated  RRCReestablishmentRequest 를 봄. TS 38.331 §5.3.7.4 step 9 가 Complete 를
	                        보내기 전에 SRB1 암호를 재개하게 정함
	   NEA0 로 재개한 경우에는 가시성을 잃지만, 암호문을 평문으로 오해석해 정확한 값이나 기형을
	   지어내는 것보다 나음. 둘 다 요청 메시지에서 세움 - 응답이 유실된 입력에서도 걸리게 하려는 것임 */
	bool resumed;
	bool reest_reactivated;
	/* 재수립 재활성 창에서 첫 하행 DCCH 를 이미 시험해 봤나. 그 자리의 RRCReestablishment 는
	   TS 38.331 §5.3.7.4 상 완전성 보호만 걸려 평문이라, 그 한 자리만 시험 디코드함. 뒤따르는
	   하행(암호화된 Reconfiguration 등)은 그대로 불가시로 둠. 재수립 사이클마다 한 번 */
	bool reest_grant_seen;
	/* 거짓 가독 상한. SECURITY MODE COMMAND 나 COMPLETE 를 놓치면 보안 상태가 실제보다 낮게 보이는데,
	   그 상태에서 암호문을 평문으로 읽는 것을 무한정 하지 않도록 상한을 둠. 상한을 넘으면 관문을 닫음.
	     dl_dcch_sec_none_count       하행, 보안 상태 NONE 에서 디코드한 DCCH 수
	     dl_dlinfo_exempt_count        그중 면제한 DLInformationTransfer 수(보안 전 평문 NAS 운반)
	     ul_dcch_sec_cmd_sent_count   상행, COMMAND 는 봤고 COMPLETE 는 못 본 상태에서 본 DCCH 수
	     ul_dcch_sec_none_count       상행, 보안 상태 NONE 에서 본 DCCH 수
	     ul_dlinfo_exempt_count        그중 면제한 ULInformationTransfer 수 */
	uint8_t dl_dcch_sec_none_count;
	uint8_t dl_dlinfo_exempt_count;
	uint8_t ul_dcch_sec_cmd_sent_count;
	uint8_t ul_dcch_sec_none_count, ul_dlinfo_exempt_count;
	bool releasing;         uint64_t release_cmd_ns;   // RELEASE COMMAND 를 봤고 유예 대기 중
	// 해시 체인과 LRU
	int hash_next;
	int lru_prev, lru_next;
	bool used;
};

/* ASSOC_CELL_MAX: 한 연결(= 한 DU)에서 기억해 두는 셀 수.
 *   RESET 메시지에는 셀이 실리지 않으므로, 재시작 알림의 `cells` 를 채우려면 F1 SETUP 때 본 것을
 *   들고 있어야 함. TS 38.473 의 maxCellingNBDU 는 512 지만 연결 1024개에 그만큼 두면 12MB 임.
 *   넘치면 목록 대신 '모름'(= 모든 셀)으로 떨어뜨리므로, 이 상한은 정확한 목록을 줄 수 있는 범위만
 *   정함. 8 은 테스트베드(셀 1개)와 3섹터 DU(3개)를 덮음. */
#define ASSOC_CELL_MAX 8

/* AMF_KEY_MAX: 한 센서가 구별하는 AMF 수. 한 gNB 는 자기 AMF Set 안의 AMF 들에만 붙으므로 수가 작음.
 *   넘치면 번호를 주지 않고(0 = 모름) 세며, 집계 쪽은 그 판에서만 연결 번호로 대리함. */
#define AMF_KEY_MAX 32

struct obs_assoc_record {
	uint32_t assoc_id;
	uint64_t du_id;   bool has_du_id;   // F1 SETUP 또는 DU CONFIG UPDATE 의 gNB-DU ID
	uint32_t amf_id;                   // N2 연결이면 NG SETUP RESPONSE 의 AMF Name 으로 매긴 번호. 0 = 모름
	struct tr_nr_cgi cells[ASSOC_CELL_MAX];
	int cell_count;
	bool cell_overflow;   // 상한을 넘겨 목록이 불완전함 -> 알림에 '모름' 을 실음
	bool used; int hash_next;
};

// ---- N2 단말 레코드 ---------------------------------------------------------------------
/* 키 = (AMF 엔티티, RAN-UE-NGAP-ID). RAN-UE-NGAP-ID 는 AMF 마다 따로 할당되므로 AMF 성분이 없으면
 * 다른 AMF 의 단말이 한 레코드로 합쳐짐. 구현은 AMF 를 NG-C SCTP 연결로 대리함 - 한 AMF 에 연결이
 * 하나일 때 정확하고, 한 AMF 가 연결을 여럿 쓰면 그만큼 레코드가 갈림 */
struct obs_n2_state {
	uint32_t assoc_id;                       // AMF 를 대리하는 키
	uint64_t ran_ue_ngap_id;                   // 키. RAN-UE-NGAP-ID(IE 85)
	uint64_t amf_ue_ngap_id;   bool has_amf_ue_ngap_id;   // 첫 AMF 하행 메시지에서 학습
	int nas_ciph_alg;                     // SECURITY MODE COMMAND 에서 학습. -1 모름, 0 = 5G-EA0. 가시성 관문이 봄
	int nas_ciph_alg_before_smc;          /* SMC 직전 값. 거절되면 여기로 되돌림 - TS 24.501 §5.4.2.5 :
										   * "Both the UE and the AMF shall apply the 5G NAS security context
										   * in use before the initiation of the security mode control procedure" */
	struct tr_nr_cgi cell;                // User Location Information(IE 121)
	uint64_t record_id;                         // F1 쪽과 같은 뜻. 전역 단조라 슬롯이 재사용돼도 번호는 겹치지 않음
	uint64_t created_ns, last_ns;
	bool releasing; uint64_t release_cmd_ns;    // RELEASE COMMAND 를 봤고 유예 대기 중
	/* 이 단말의 N2 연결 수립 성공을 이미 한 번 알렸나. CU 는 DL NAS TRANSPORT 나 INITIAL CONTEXT
	   SETUP 에서만 AMF 쪽 번호를 실어 주므로, 그 두 자리에서만 성공을 알 수 있고 한 번만 알림 */
	bool uecntx_succ_sent;
	bool has_f1_pair; uint32_t f1_pair_assoc; uint32_t f1_pair_du_ue_id; uint64_t f1_pair_record_id;
	bool used; int hash_next; int lru_prev, lru_next;
};

// ---- F1 RRCSetupComplete 와 N2 INITIAL UE MESSAGE 짝짓기 --------------------------------

// 대기 중인 F1 항목 하나. (assoc_id, du_ue_id, f1_record_id)가 ue_find_record_id 로 되찾을 때의 키임
struct corr_item { uint64_t wallclock_ns; uint64_t f1_record_id; uint32_t assoc_id; uint32_t du_ue_id; int next_index; bool used; };
struct corr_key {
	uint32_t plmn_packed; uint64_t cell_id; int est_cause; uint32_t nas_ie_len; uint64_t hash_lo, hash_hi;   // PLMN 과 셀 번호를 합쳐 NR CGI
	uint64_t ambiguous_until_ns;        // 모호 표지 만료 시각. 그때까지 같은 키는 모두 모호로 셈
	int item_head; int pending_count;      // 대기 F1 항목 단일 연결 리스트의 머리와 그 수
	bool used; int hash_next;
};

struct obs {
	struct obs_cfg obs_cfg;
	obs_event_cb on_event; void *user_ctx;
	struct obs_stats stats;
	uint64_t now_ns;
	uint64_t last_sweep_ns;   // 만료 훑기를 메시지마다 하지 않고 최소 간격을 둠. 훑기 비용이 표 크기에 비례해서임

	// AMF 신원에서 키 번호로. 자세한 것은 amf_id_for 주석
	struct { uint64_t name_hash; uint32_t amf_id; bool used; } amf_keys[AMF_KEY_MAX];
	uint32_t amf_key_count;

	// F1 단말 표. 배열 + 해시 체인 + 빈 칸 목록 + LRU
	struct obs_ue_state *ue_states; uint32_t ue_capacity;
	int *ue_hash_buckets; uint32_t ue_hash_bucket_count;
	int ue_free;                 // 빈 칸 목록의 머리. -1 이면 없음
	int lru_head, lru_tail;      // head 가 가장 오래된 것, tail 이 가장 최근
	uint32_t ue_count;

	// SCTP 연결 표
	struct obs_assoc_record *assoc_records; uint32_t assoc_capacity; int *assoc_hash_buckets; uint32_t assoc_hash_bucket_count; int assoc_free;

	// N2 단말 표. F1 표와 같은 구조
	struct obs_n2_state *n2_states; uint32_t n2_capacity; int *n2_hash_buckets; uint32_t n2_hash_bucket_count;
	int n2_free, n2_lru_head, n2_lru_tail; uint32_t n2_count;

	// 짝짓기. 키 버킷 해시와 대기 F1 항목 풀
	struct corr_key *corr_keys; uint32_t corr_key_capacity; int *corr_key_hash_buckets; uint32_t corr_key_hash_bucket_count; int corr_key_free;
	struct corr_item *corr_items; uint32_t corr_item_capacity; int corr_item_free;
	uint64_t correlation_window_ns;

	uint64_t next_record_id;   // 레코드 번호 발급기. 0 은 무효라 첫 발급이 1
};

/* decide_direction: 절차 -> 와이어 -> 미상 순서로 방향을 정하고, 둘이 어긋나면 셈.
 *   이유: 절차가 방향을 정하는 메시지(DL RRC MESSAGE TRANSFER 등)는 절차 쪽이 정의상 정확하므로 먼저 씀.
 *     와이어 규칙은 절차가 못 정하는 경우(Reset)를 메우고, 둘 다 알 때는 서로 대조가 됨. 어긋남은
 *     관측 지점이나 상대가 비정상이라는 신호이므로 세어 보고함.
 *   부작용: obs->stats.direction_conflict_count 와 direction_unknown_count 를 갱신함. 미상과 불일치를
 *     조용히 넘기면 '그런 일이 없었음' 과 같은 모양이 됨. */
static enum tr_direction decide_direction(struct obs *obs, const struct cap_record *record,
									enum tr_iface iface, enum tr_direction proc_direction)
{
	enum tr_direction wire_direction = wire_rule_direction(record, iface);
	if (proc_direction != TR_DIRECTION_UNKNOWN && wire_direction != TR_DIRECTION_UNKNOWN && proc_direction != wire_direction)
		obs->stats.direction_conflict_count++;
	enum tr_direction direction = direction_pick(proc_direction, wire_direction);
	if (direction == TR_DIRECTION_UNKNOWN) obs->stats.direction_unknown_count++;
	return direction;
}

// ---- 작은 해시 --------------------------------------------------------------------------
static uint32_t ue_bucket(uint32_t assoc_id, uint32_t du_ue_id, uint32_t bucket_count)
{
	uint64_t hash_key = ((uint64_t)assoc_id << 32) | du_ue_id;
	hash_key = (hash_key ^ (hash_key >> 30)) * 0xbf58476d1ce4e5b9ULL; hash_key ^= hash_key >> 27;
	return (uint32_t)(hash_key % bucket_count);
}
static uint32_t assoc_bucket(uint32_t assoc_id, uint32_t bucket_count) { return (assoc_id * 2654435761u) % bucket_count; }

// ---- 이벤트 헤더 채우기 -----------------------------------------------------------------
static void fill_event_header(struct obs_event *event, const struct obs *obs, const struct sctp_message *sctp_message,
				 enum tr_event_kind kind, enum tr_direction direction)
{
	memset(event, 0, sizeof *event);
	event->kind = kind;
	event->wallclock_ns = sctp_message->record ? sctp_message->record->capture_time_ns : obs->now_ns;
	event->iface = TR_IFACE_F1;
	event->direction = direction;
	event->assoc_id = sctp_message->assoc_id;
	event->quality = TR_QUALITY_EXACT;
}
// f1ue_key_of: 단말 상태에서 F1 키만 꺼냄. 셀은 담지 않음 - RESET 목록처럼 키만 필요한 자리가 있음
static struct tr_f1ue f1ue_key_of(const struct obs_ue_state *ue_state)
{
	struct tr_f1ue f1ue = {
		.valid        = true,
		.du_id        = ue_state->du_id,
		.du_id_is_temp = ue_state->du_id_is_temp,
		.du_ue_id     = ue_state->du_ue_id,
	};
	if (ue_state->has_cu_ue_id) { f1ue.has_cu_ue_id = true; f1ue.cu_ue_id = ue_state->cu_ue_id; }
	if (ue_state->has_crnti)    { f1ue.has_crnti = true;    f1ue.crnti = ue_state->crnti; }
	return f1ue;
}
static void fill_f1ue(struct obs_event *event, const struct obs_ue_state *ue_state)
{
	event->f1ue = f1ue_key_of(ue_state);
	event->cell = ue_state->cell;
}
// emit: 이벤트 하나를 위로 올림. 이벤트가 나가는 자리가 여기뿐이라 여기서 세면 빠뜨릴 수 없음
static void emit(struct obs *obs, const struct obs_event *event)
{
	obs->stats.event_emitted_count++;
	if (obs->on_event)
		obs->on_event(obs->user_ctx, event);
}

// ---- LRU --------------------------------------------------------------------------------
static void lru_unlink(struct obs *obs, int i)
{
	struct obs_ue_state *ue_state = &obs->ue_states[i];
	if (ue_state->lru_prev >= 0) obs->ue_states[ue_state->lru_prev].lru_next = ue_state->lru_next; else obs->lru_head = ue_state->lru_next;
	if (ue_state->lru_next >= 0) obs->ue_states[ue_state->lru_next].lru_prev = ue_state->lru_prev; else obs->lru_tail = ue_state->lru_prev;
	ue_state->lru_prev = ue_state->lru_next = -1;
}
static void lru_push_tail(struct obs *obs, int i)
{
	struct obs_ue_state *ue_state = &obs->ue_states[i];
	ue_state->lru_prev = obs->lru_tail; ue_state->lru_next = -1;
	if (obs->lru_tail >= 0) obs->ue_states[obs->lru_tail].lru_next = i; else obs->lru_head = i;
	obs->lru_tail = i;
}
static void lru_touch(struct obs *obs, int i) { lru_unlink(obs, i); lru_push_tail(obs, i); }

// ---- F1 단말 표 조회, 생성, 제거 --------------------------------------------------------
static int ue_find(struct obs *obs, uint32_t assoc_id, uint32_t du_ue_id)
{
	for (int i = obs->ue_hash_buckets[ue_bucket(assoc_id, du_ue_id, obs->ue_hash_bucket_count)]; i >= 0; i = obs->ue_states[i].hash_next)
		if (obs->ue_states[i].used && obs->ue_states[i].assoc_id == assoc_id && obs->ue_states[i].has_du_ue_id && obs->ue_states[i].du_ue_id == du_ue_id)
			return i;
	return -1;
}
/* ue_find_record_id: 키로 슬롯을 찾되 레코드 번호가 다르면 없는 것으로 봄.
 *   이유: 키만 맞춰 보면 그 사이에 슬롯이 재사용돼 다른 단말이 들어온 경우를 가릴 수 없어, 짝을
 *     엉뚱한 단말에 붙이게 됨. 레코드 번호는 전역 단조라 슬롯마다 세대를 두는 방법과 달리
 *     '다른 슬롯이 우연히 같은 세대' 인 경우까지 막음. */
static int ue_find_record_id(struct obs *obs, uint32_t assoc_id, uint32_t du_ue_id, uint64_t record_id)
{
	int i = ue_find(obs, assoc_id, du_ue_id);
	return (i >= 0 && obs->ue_states[i].record_id == record_id) ? i : -1;
}
static void ue_hash_remove(struct obs *obs, int idx)
{
	uint32_t bucket = ue_bucket(obs->ue_states[idx].assoc_id, obs->ue_states[idx].du_ue_id, obs->ue_hash_bucket_count);
	int *hash_link = &obs->ue_hash_buckets[bucket];
	while (*hash_link >= 0) { if (*hash_link == idx) { *hash_link = obs->ue_states[idx].hash_next; return; } hash_link = &obs->ue_states[*hash_link].hash_next; }
}
// ue_remove: 표에서만 지움. 이벤트는 호출자가 냄
static void ue_remove(struct obs *obs, int idx)
{
	ue_hash_remove(obs, idx);
	lru_unlink(obs, idx);
	obs->ue_states[idx].used = false;
	obs->ue_states[idx].hash_next = obs->ue_free; obs->ue_free = idx;
	obs->ue_count--;
}
// ue_evict_one: 표가 꽉 찼을 때 가장 오래된 레코드를 지우고 그 사실을 이벤트로 알림
static void ue_evict_one(struct obs *obs)
{
	int i = obs->lru_head; if (i < 0) return;
	struct obs_event event; memset(&event, 0, sizeof event);
	event.kind = TR_EVENT_OBS_UE_EVICTED; event.wallclock_ns = obs->now_ns; event.iface = TR_IFACE_F1; event.assoc_id = obs->ue_states[i].assoc_id;
	fill_f1ue(&event, &obs->ue_states[i]);
	emit(obs, &event);
	obs->stats.ue_evicted_count++;
	ue_remove(obs, i);
}
static int ue_create(struct obs *obs, uint32_t assoc_id, uint32_t du_ue_id)
{
	if (obs->ue_count >= obs->obs_cfg.ue_capacity) ue_evict_one(obs);
	if (obs->ue_free < 0) return -1;
	int i = obs->ue_free; obs->ue_free = obs->ue_states[i].hash_next;
	struct obs_ue_state *ue_state = &obs->ue_states[i];
	memset(ue_state, 0, sizeof *ue_state);
	ue_state->record_id = ++obs->next_record_id;
	ue_state->used = true; ue_state->assoc_id = assoc_id; ue_state->du_ue_id = du_ue_id; ue_state->has_du_ue_id = true;
	ue_state->ciph_alg = -1; ue_state->nas_ciph_alg = -1; ue_state->rrc_sec_state = TR_SEC_NONE; ue_state->est_cause = -1;
	ue_state->created_ns = ue_state->last_ns = obs->now_ns;
	ue_state->lru_prev = ue_state->lru_next = -1;
	uint32_t bucket = ue_bucket(assoc_id, du_ue_id, obs->ue_hash_bucket_count);
	ue_state->hash_next = obs->ue_hash_buckets[bucket]; obs->ue_hash_buckets[bucket] = i;
	lru_push_tail(obs, i);
	obs->ue_count++;
	return i;
}

// ---- SCTP 연결에서 DU 로 가는 매핑 ------------------------------------------------------
static struct obs_assoc_record *assoc_get(struct obs *obs, uint32_t assoc_id)
{
	uint32_t bucket = assoc_bucket(assoc_id, obs->assoc_hash_bucket_count);
	for (int i = obs->assoc_hash_buckets[bucket]; i >= 0; i = obs->assoc_records[i].hash_next)
		if (obs->assoc_records[i].used && obs->assoc_records[i].assoc_id == assoc_id) return &obs->assoc_records[i];
	/* 상한 도달: 새 연결의 DU 매핑을 만들지 않음. 그 연결의 단말은 임시 DU 키로 떨어짐.
	 * 조용히 버리면 "DU 를 못 봤음" 과 "표가 꽉 찼음" 을 구분할 수 없어 세어 둠 */
	if (obs->assoc_free < 0) { obs->stats.assoc_table_full_count++; return NULL; }
	int i = obs->assoc_free; obs->assoc_free = obs->assoc_records[i].hash_next;
	memset(&obs->assoc_records[i], 0, sizeof obs->assoc_records[i]);
	obs->assoc_records[i].used = true; obs->assoc_records[i].assoc_id = assoc_id;
	obs->assoc_records[i].hash_next = obs->assoc_hash_buckets[bucket]; obs->assoc_hash_buckets[bucket] = i;
	return &obs->assoc_records[i];
}
/* assoc_remove: 연결이 끝나면 그 레코드를 돌려줌.
 *   이유: 안 지우면 재접속과 vtag 재시작이 쌓여 표가 소진되고, 그 뒤 모든 단말이 임시 DU 키로 떨어짐. */
static void assoc_remove(struct obs *obs, uint32_t assoc_id)
{
	uint32_t bucket = assoc_bucket(assoc_id, obs->assoc_hash_bucket_count);
	int *hash_link = &obs->assoc_hash_buckets[bucket];
	while (*hash_link >= 0) {
		int i = *hash_link;
		if (obs->assoc_records[i].used && obs->assoc_records[i].assoc_id == assoc_id) {
			*hash_link = obs->assoc_records[i].hash_next; obs->assoc_records[i].used = false;
			obs->assoc_records[i].hash_next = obs->assoc_free; obs->assoc_free = i; return;
		}
		hash_link = &obs->assoc_records[i].hash_next;
	}
}

// set_f1ue_keys: gNB-DU ID 를 아직 못 봤으면 연결 번호를 임시 키로 씀
static void set_f1ue_keys(struct obs *obs, struct obs_ue_state *ue_state)
{
	struct obs_assoc_record *assoc_record = assoc_get(obs, ue_state->assoc_id);
	if (assoc_record && assoc_record->has_du_id) { ue_state->du_id = assoc_record->du_id; ue_state->du_id_is_temp = false; }
	else { ue_state->du_id = ue_state->assoc_id; ue_state->du_id_is_temp = true; }
}

