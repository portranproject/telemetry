/**
 * tr.c
 * : 집계 엔진 - 관측 이벤트를 받아 주기마다 표 II(셀 카운터)와 표 I(단말 줄)을 냄
 *
 * [1] 입력과 출력. 패킷도 ASN.1 도 모름 - 아는 것은 관측 이벤트뿐임.
 *
 *     libobs --관측 이벤트--> [libtelemetry] --주기 보고--> libsink --> 탐지 엔진
 *
 *     소유 구분: 단말 레코드는 libobs 것, 셀 표와 보고 주기는 여기 것임.
 *     TS 28.552 의 카운팅 규칙은 전부 이 파일에만 있음.
 *
 * [2] 시간이 먼저임. 이벤트를 적용하기 전에 주기 경계, 표본, 무응답 마감을 먼저 넘김.
 *
 *     tr_advance(t) --> 주기 닫기 --> 표본 뜨기 --> 무응답 마감 처리 --> 그 다음 이벤트 적용
 *
 *     순서를 바꾸면 늦게 온 이벤트가 이미 닫힌 주기에 들어가거나, 마감이 지난 시도가
 *     성공으로 뒤집힘.
 *
 * [3] 한 카운터에는 원천 이벤트가 하나임.
 *
 *     RRC.ConnEstabAtt <- RRCSetupRequest 하나뿐. 두 곳에서 올리면 같은 일이 두 번 세어지고,
 *     어느 쪽이 올렸는지 되짚을 수 없음.
 *
 * [4] 값의 등급. 내보내는 값은 본 것과 추론한 것의 합이고, 모르는 것은 섞지 않음.
 *
 *     value = exact + inferred      <- 내보냄
 *     unknown, excluded             <- 따로 셈. value 에 넣지 않음
 *
 *     모르는 것을 0 으로 섞으면 "세어서 0" 과 "못 봐서 0" 이 같은 모양이 됨. 우리는 수동
 *     관측자라 다시 물을 수 없으므로, 못 센 것을 못 셌다고 남기는 것이 이 계층의 일임.
 *
 * [5] 수립 결과는 한 번만 확정됨. 성공으로 닫힌 시도는 나중에 실패로 바뀌지 않고, 반대도 같음.
 *     이 규칙이 없으면 늦게 온 메시지 하나로 한 시도가 실패이면서 성공이 됨.
 */
#include "tr.h"
#include <libnas/nas.h>   // 5GMM 메시지 타입을 이름으로 읽으려고 씀. 숫자를 여기 다시 적지 않음

#include <stdlib.h>
#include <string.h>
#include <stdio.h>   // 자기-불변식이 깨졌을 때 stderr 로 어디서 깨졌는지 찍으려고 씀

// ---- 상수와 기본값 ----
#define DEF_GP_MS                     TR_DEF_GP_MS   // 단일 출처는 tr.h. 출력 쪽이 광고하는 주기도 같은 값이어야 함
#define DEF_CONN_SAMPLE_PERIOD_MS     100u
#define DEF_INACTIVE_SAMPLE_PERIOD_MS 100u
#define DEF_LATE_SLACK_MS             50u
#define DEF_MAX_CELL_COUNT            4096u
// 기본 무응답 대기는 tr.h 가 공개함. 출력 쪽이 같은 값을 광고해야 하므로 단일 출처여야 함

/* 한 번의 시간 전진 상한 1일. 실제 캡처 간격은 이보다 훨씬 짧으므로 정상 입력에는 걸리지 않음.
 * 손상된 타임스탬프가 먼 미래를 가리킬 때 주기 닫기 루프가 폭주하는 것을 막음 */
#define ADVANCE_MAX_NS (86400ull * 1000000000ull)

/* 연결 게이지에서 이 UE 를 빼는 지점은 RELEASE COMMAND 가 아니라 COMPLETE 임(libobs 가 대기
 * 시간이 지나 합성한 COMPLETE 도 같음). COMMAND 는 CU 가 보낸 것이고 단말이 받았는지는 모르므로,
 * COMMAND 에서 빼면 아직 살아 있는 연결이 게이지에서 사라짐 */

#define MAX_CAUSE 16   // 원인 칸 배열 길이. EstablishmentCause/ResumeCause 16, RRCEstablishmentCause 11, FailCause 3 중 최대

// 내부 RRC 상태. 번호 순서는 tr.h 가 공개한 rrc_state 값 코드북과 같음
enum tr_rrc_state { RS_UNKNOWN = 0, RS_IDLE_PENDING, RS_CONNECTED, RS_INACTIVE, RS_RELEASED };

// 수립 실패 원인 칸. 순서는 metrics.h 의 TR_CAUSE_FAIL3 와 같아야 함
enum tr_fail_cause_slot { FC_NETWORK_REJECT = 0, FC_NOREPLY = 1, FC_OTHER = 2 };

// 수립 결과. 한 번 정해지면 뒤집지 않음
enum tr_setup_result { SR_OPEN = 0, SR_SUCCESS, SR_NETWORK_REJECT, SR_NOREPLY, SR_OTHER, SR_UNKNOWN };

// 게이지를 값 등급별로 따로 둠. 등급이 다른 것을 한 수에 섞지 않으려고
enum tr_gauge_level { LV_EXACT = 0, LV_INFERRED, LV_UNKNOWN };

/* AMF 과부하 상태. AMF_UNKNOWN 과 AMF_DETACHED 는 지금 어느 지점에서도 대입하지 않음 -
 * assoc 가 끊기면 레코드를 미상으로 두지 않고 지우기 때문임. 그래도 두는 이유는 과부하
 * 판정이 두 분기를 들고 있어서임. assoc 를 지우지 않는 경로가 생기면 그때 쓰는 값임 */
enum tr_amf_state { AMF_NONE = 0, AMF_OVERLOAD, AMF_UNKNOWN, AMF_DETACHED };

/* 과부하 판정 결과. 이름 있는 열거를 쓰는 이유: 판정을 받는 변수가 int 면 엉뚱한 이름이
 * 붙어도 컴파일됨(실제로 그랬음). 접두사를 OVL_ 이 아니라 OVERLOAD_ 로 둔 이유: enum
 * tr_overlap 의 배열 길이 TR_OVERLAP__COUNT 와 밑줄 하나 차이가 되어, 오타 하나가 판정과
 * 배열 경계를 조용히 맞바꿈 */
enum overload_decision { OVERLOAD_COUNT = 0, OVERLOAD_EXCLUDE, OVERLOAD_UNKNOWN };

/* NGAP Cause 의 정규화값. ngap.c 가 group = CHOICE 번호 - 1, value = 열거 원값으로 맞춰 줌
 * (TS 38.413 §9.3.1.2). 값 확인: NGAP_Cause.h 의 nas 는 present 3 이라 group 2,
 * NGAP_CauseNas.h 의 deregister 는 2. 여기서 쓰는 것은 "NAS 쪽 원인이고 deregister 인가" 하나임 */
enum { TR_NGAP_CAUSE_GRP_NAS = 2, TR_NGAP_CAUSE_NAS_DEREGISTER = 2 };

/* NGAP RRCState(IE 92) 값. 1차 출처는 asn1/ngap-15.8.0.asn1 의
 *   `RRCState ::= ENUMERATED { inactive, connected, ... }` -> inactive=0, connected=1.
 *   obs 가 asn1c 열거값을 그대로 싣고, IE 가 없으면 -1 을 줌.
 *   이름으로 쓰는 이유: 0 이 '없음' 이 아니라 inactive 라서 숫자로 비교하면 미상으로 오독됨.
 *   connected(1) 는 상수를 두지 않음 - 이 층이 보는 것은 "inactive 인가" 하나뿐이고,
 *   나머지(connected 와 확장값)는 한 갈래로 묶어 전이를 만들지 않음 */
enum { TR_NGAP_RRC_STATE_INACTIVE = 0 };

// ---- 지표 이름, 원인표, 개수, CC/SI (전부 metrics.h 의 TR_METRIC_LIST 에서 파생) ----
static const char *const MNAME[TR_METRIC__COUNT] = {
#define X(id, name, kind, ct) [id] = name,
	TR_METRIC_LIST(X)
#undef X
};
/* 원인 이름 배열 두 벌. metrics.h 의 목록 하나를 철자별로 두 번 전개함
 *   ARR      28.552 하위카운터 철자. 하이픈 없음(TS 28.552 §4.1a). 표 II 가 씀
 *   ASN1_ARR ASN.1 값 이름 철자. 탐지 엔진으로 나가는 줄이 씀 - 읽는 쪽이 대소문자까지 비교함 */
#define Y(name_28552, name_asn1) name_28552,
static const char *const TR_CAUSE_ARR_EST16[] = { TR_CAUSE_EST16(Y) };
static const char *const TR_CAUSE_ARR_UEC11[] = { TR_CAUSE_UEC11(Y) };
static const char *const TR_CAUSE_ARR_RES16[] = { TR_CAUSE_RES16(Y) };
static const char *const TR_CAUSE_ARR_FAIL3[] = { TR_CAUSE_FAIL3(Y) };
#undef Y
#define Y(name_28552, name_asn1) name_asn1,
static const char *const TR_CAUSE_ASN1_ARR_EST16[] = { TR_CAUSE_EST16(Y) };
static const char *const TR_CAUSE_ASN1_ARR_UEC11[] = { TR_CAUSE_UEC11(Y) };
static const char *const TR_CAUSE_ASN1_ARR_RES16[] = { TR_CAUSE_RES16(Y) };
static const char *const TR_CAUSE_ASN1_ARR_FAIL3[] = { TR_CAUSE_FAIL3(Y) };
#undef Y
/* 두 가지를 컴파일 때 못박음. 어기면 컴파일 에러임
 *   (1) 배열 길이 == 유도 개수. 이름표 한쪽만 고쳐도 둘이 함께 바뀜을 보증
 *   (2) 모든 개수 <= MAX_CAUSE. 저장과 읽기 루프의 배열 밖 접근 차단 */
#define TR_ARRAY_LENGTH(a) (int)(sizeof(a)/sizeof((a)[0]))
_Static_assert(TR_ARRAY_LENGTH(TR_CAUSE_ARR_EST16) == TR_CAUSE_TABLE_COUNT_EST16, "EST16 이름표/개수 불일치");
_Static_assert(TR_ARRAY_LENGTH(TR_CAUSE_ARR_UEC11) == TR_CAUSE_TABLE_COUNT_UEC11, "UEC11 이름표/개수 불일치");
_Static_assert(TR_ARRAY_LENGTH(TR_CAUSE_ARR_RES16) == TR_CAUSE_TABLE_COUNT_RES16, "RES16 이름표/개수 불일치");
_Static_assert(TR_ARRAY_LENGTH(TR_CAUSE_ARR_FAIL3) == TR_CAUSE_TABLE_COUNT_FAIL3, "FAIL3 이름표/개수 불일치");
_Static_assert(TR_ARRAY_LENGTH(TR_CAUSE_ASN1_ARR_EST16) == TR_CAUSE_TABLE_COUNT_EST16 &&
			   TR_ARRAY_LENGTH(TR_CAUSE_ASN1_ARR_UEC11) == TR_CAUSE_TABLE_COUNT_UEC11 &&
			   TR_ARRAY_LENGTH(TR_CAUSE_ASN1_ARR_RES16) == TR_CAUSE_TABLE_COUNT_RES16 &&
			   TR_ARRAY_LENGTH(TR_CAUSE_ASN1_ARR_FAIL3) == TR_CAUSE_TABLE_COUNT_FAIL3,
			   "ASN.1 이름표/개수 불일치(두 철자 중 한쪽만 고쳤음)");
_Static_assert(TR_CAUSE_TABLE_COUNT_EST16 <= MAX_CAUSE && TR_CAUSE_TABLE_COUNT_UEC11 <= MAX_CAUSE &&
			   TR_CAUSE_TABLE_COUNT_RES16 <= MAX_CAUSE && TR_CAUSE_TABLE_COUNT_FAIL3 <= MAX_CAUSE &&
			   TR_CAUSE_TABLE_COUNT_NONE1 <= MAX_CAUSE, "원인 개수가 MAX_CAUSE 초과(저장 배열/루프 OOB)");
#undef TR_ARRAY_LENGTH
// 지표에서 (원인표, 개수, CC/SI) 로 가는 매핑. 이것도 metrics.h 파생임
static const char *const *const METRIC_CAUSE[TR_METRIC__COUNT] = {
#define X(id, name, kind, ct) [id] = TR_CAUSE_TABLE_ARR_##ct,
	TR_METRIC_LIST(X)
#undef X
};
static const char *const *const METRIC_CAUSE_ASN1[TR_METRIC__COUNT] = {
#define X(id, name, kind, ct) [id] = TR_CAUSE_TABLE_ASN1_ARR_##ct,
	TR_METRIC_LIST(X)
#undef X
};
static const int METRIC_CAUSE_CNT[TR_METRIC__COUNT] = {
#define X(id, name, kind, ct) [id] = TR_CAUSE_TABLE_COUNT_##ct,
	TR_METRIC_LIST(X)
#undef X
};
static const int METRIC_IS_SI_[TR_METRIC__COUNT] = {
#define X(id, name, kind, ct) [id] = TR_KIND_##kind,
	TR_METRIC_LIST(X)
#undef X
};

int tr_cause_count(enum tr_metric metric)
{
	return ((unsigned)metric < (unsigned)TR_METRIC__COUNT) ? METRIC_CAUSE_CNT[metric] : 0;
}

// 지표가 CC 인지 SI 인지 공개함. 출력 쪽이 지표 이름으로 다시 분류하면 목록이 둘이 되어 어긋남
int tr_metric_is_si(enum tr_metric metric)
{
	return ((unsigned)metric < (unsigned)TR_METRIC__COUNT) ? METRIC_IS_SI_[metric] : 0;
}

const char *tr_metric_name(enum tr_metric metric)
{
	return ((unsigned)metric < (unsigned)TR_METRIC__COUNT) ? MNAME[metric] : NULL;
}

const char *tr_cause_subname(enum tr_metric metric, int cause_index)
{
	if ((unsigned)metric >= (unsigned)TR_METRIC__COUNT) return NULL;
	if (cause_index < 0 || cause_index >= METRIC_CAUSE_CNT[metric]) return NULL;   // 범위 밖이면 NULL
	const char *const *subnames = METRIC_CAUSE[metric];
	return subnames ? subnames[cause_index] : "";                              // 원인 분할이 없는 지표는 ""
}

/* tr_cause_asn1_name: 원인 칸의 ASN.1 값 이름. 범위 밖이면 NULL, 원인 분할이 없으면 "".
 *   이유: 탐지 엔진으로 나가는 줄의 est_cause 는 ASN.1 철자로 대소문자까지 비교되므로, 표 II 가
 *         쓰는 28.552 하위카운터 철자(tr_cause_subname, 하이픈 금지)와 같은 칸에 철자가 둘임.
 *   반환한 포인터는 정적 문자열이라 수명 제약 없음 */
const char *tr_cause_asn1_name(enum tr_metric metric, int cause_index)
{
	if ((unsigned)metric >= (unsigned)TR_METRIC__COUNT) return NULL;
	if (cause_index < 0 || cause_index >= METRIC_CAUSE_CNT[metric]) return NULL;
	const char *const *asn1_names = METRIC_CAUSE_ASN1[metric];
	return asn1_names ? asn1_names[cause_index] : "";
}

// CC 는 SI 가 아닌 것. tr_metric_is_si 하나만 거쳐 판정해 분류가 두 곳에 생기지 않게 함
static int metric_is_cc(enum tr_metric metric)
{
	return !tr_metric_is_si(metric);
}
static int metric_has_path(enum tr_metric metric)
{
	return (metric == TR_METRIC_RRC_CONN_ESTAB_SUCC) || (metric == TR_METRIC_RRC_CONN_ESTAB_FAIL_CAUSE);
}

// ---- 해시맵 (open addressing, 키 비교는 콜백) ----
struct tr_hash_slot { uint8_t state; uint64_t hash; uint32_t idx; };   // state: 0 빈 칸, 1 사용 중, 2 tombstone
struct hash_map { struct tr_hash_slot *slots; uint32_t slot_capacity, entry_count, tombstone_count; };

typedef int (*key_eq_fn)(void *ctx, uint32_t idx, const void *key_ptr);

static int hash_map_init(struct hash_map *hash_map, uint32_t slot_capacity)
{
	if (slot_capacity < 16) slot_capacity = 16;
	uint32_t rounded_slot_capacity = 16; while (rounded_slot_capacity < slot_capacity) rounded_slot_capacity <<= 1;
	hash_map->slots = calloc(rounded_slot_capacity, sizeof *hash_map->slots);
	if (!hash_map->slots) return -1;
	hash_map->slot_capacity = rounded_slot_capacity; hash_map->entry_count = 0; hash_map->tombstone_count = 0;
	return 0;
}
static void hash_map_free(struct hash_map *hash_map)
{
	free(hash_map->slots);
	hash_map->slots = NULL;
	hash_map->slot_capacity = hash_map->entry_count = hash_map->tombstone_count = 0;
}

static uint32_t hash_map_find_slot(struct hash_map *hash_map, uint64_t hash, key_eq_fn key_eq,
				   void *ctx, const void *key_ptr)
{
	uint32_t mask = hash_map->slot_capacity - 1, i = (uint32_t)hash & mask, first_tombstone = hash_map->slot_capacity;
	for (;;) {
		struct tr_hash_slot *hash_slot = &hash_map->slots[i];
		// 빈 칸을 만나면 없는 것임. 지나온 tombstone 이 있으면 그 칸을 삽입 위치로 돌려줌
		if (hash_slot->state == 0) return (first_tombstone != hash_map->slot_capacity) ? first_tombstone : i;
		if (hash_slot->state == 2) { if (first_tombstone == hash_map->slot_capacity) first_tombstone = i; }
		else if (hash_slot->hash == hash && key_eq(ctx, hash_slot->idx, key_ptr)) return i;   // 찾음
		i = (i + 1) & mask;
	}
}
// 찾으면 레코드 색인, 없으면 UINT32_MAX
static uint32_t hash_map_get(struct hash_map *hash_map, uint64_t hash, key_eq_fn key_eq, void *ctx, const void *key_ptr)
{
	uint32_t i = hash_map_find_slot(hash_map, hash, key_eq, ctx, key_ptr);
	return (hash_map->slots[i].state == 1) ? hash_map->slots[i].idx : UINT32_MAX;
}
static int hash_map_grow(struct hash_map *hash_map)
{
	uint32_t old_slot_capacity = hash_map->slot_capacity; struct tr_hash_slot *old_slots = hash_map->slots;
	uint32_t new_slot_capacity = old_slot_capacity << 1;
	struct tr_hash_slot *new_slots = calloc(new_slot_capacity, sizeof *new_slots);
	if (!new_slots) return -1;
	uint32_t mask = new_slot_capacity - 1;
	for (uint32_t hash_slot_index = 0; hash_slot_index < old_slot_capacity; hash_slot_index++) {
		if (old_slots[hash_slot_index].state != 1) continue;
		uint32_t i = (uint32_t)old_slots[hash_slot_index].hash & mask;
		while (new_slots[i].state == 1) i = (i + 1) & mask;
		new_slots[i] = old_slots[hash_slot_index]; new_slots[i].state = 1;
	}
	free(old_slots);
	hash_map->slots = new_slots; hash_map->slot_capacity = new_slot_capacity; hash_map->tombstone_count = 0;
	return 0;
}
static int hash_map_put(struct hash_map *hash_map, uint64_t hash, key_eq_fn key_eq, void *ctx,
			const void *key_ptr, uint32_t idx)
{
	// 사용 중 + tombstone 이 칸의 70% 를 넘으면 늘림. 탐색 길이를 상수로 묶어 두려고
	if ((hash_map->entry_count + hash_map->tombstone_count) * 10u >= hash_map->slot_capacity * 7u) {
		if (hash_map_grow(hash_map) < 0) return -1;
	}
	uint32_t i = hash_map_find_slot(hash_map, hash, key_eq, ctx, key_ptr);
	struct tr_hash_slot *hash_slot = &hash_map->slots[i];
	if (hash_slot->state == 1) { hash_slot->idx = idx; return 0; }     // 이미 있으면 교체
	if (hash_slot->state == 2 && hash_map->tombstone_count) hash_map->tombstone_count--;
	hash_slot->state = 1; hash_slot->hash = hash; hash_slot->idx = idx; hash_map->entry_count++;
	return 0;
}
static void hash_map_del(struct hash_map *hash_map, uint64_t hash, key_eq_fn key_eq, void *ctx, const void *key_ptr)
{
	uint32_t i = hash_map_find_slot(hash_map, hash, key_eq, ctx, key_ptr);
	if (hash_map->slots[i].state == 1) {
		hash_map->slots[i].state = 2; hash_map->entry_count--; hash_map->tombstone_count++;
	}
}

static uint64_t mix64(uint64_t value)
{
	value ^= value >> 33; value *= 0xff51afd7ed558ccdULL;
	value ^= value >> 33; value *= 0xc4ceb9fe1a85ec53ULL;
	value ^= value >> 33; return value;
}

// ---- 레코드 ----
struct tr_cell_record {
	struct tr_nr_cgi cell;
	int overflow;                 // 셀 수 상한을 넘겨 한 칸에 모은 셀임
	int late_join;

	// 주기 CC 누적. 주기를 닫을 때 0 으로 돌림
	uint32_t cc_value[TR_METRIC__COUNT][MAX_CAUSE];
	uint32_t cc_inferred[TR_METRIC__COUNT][MAX_CAUSE];
	uint32_t cc_unknown[TR_METRIC__COUNT][MAX_CAUSE];
	uint32_t cc_unknown_nocause[TR_METRIC__COUNT];
	uint32_t cc_excluded[TR_METRIC__COUNT][TR_EXCLUDED__COUNT][MAX_CAUSE];
	uint32_t cc_overlap[TR_METRIC__COUNT][MAX_CAUSE][TR_OVERLAP__COUNT];
	uint32_t path_value[TR_METRIC__COUNT][PATH__COUNT];

	// 게이지. 주기를 닫아도 값을 그대로 들고 감
	int32_t conn_gauge[3];        // 칸 번호는 enum tr_gauge_level
	int32_t half_open_gauge;      // 반쯤 열린 연결
	int32_t inactive_gauge[3];

	// SI 누적. 주기를 닫을 때 0 으로 돌림
	uint64_t conn_sum[3]; uint32_t conn_sample_count; uint32_t conn_max[3];
	uint64_t inactive_sum[3]; uint32_t inactive_sample_count; uint32_t inactive_max[3];
	uint64_t half_open_sum; uint32_t half_open_max;

	/* UE 컨텍스트 수를 28.552 게이지와 따로 두는 이유: 28.552 의 Max 는 표본을 뜬 시점의
	 * 최댓값인데 이 지표는 칸 안 실제 수의 최댓값임. 표본 주기가 칸(100ms)보다 길면 봉우리를 놓침 */
	int32_t  ue_context_gauge;    // INITIAL UL 에서 +1, UEContextReleaseComplete 에서 -1 인 누적 상태
	uint32_t ue_context_max;      // 주기 안 ue_context_gauge 최댓값. 주기 시작값(이월분)을 포함
	uint32_t initial_ul_count;    // 주기 안 INITIAL UL 건수
	uint32_t no_du_to_cu_count;   // 그중 DU to CU RRC Container 가 없던 건수
	int evicted_this_period;      // 이 주기에 레코드를 밀어냄. 그 주기 SI 의 상한을 믿을 수 없다는 표시
};

// UE 레코드. 진행 중인 수립 상태를 하위 칸으로 들고 있음. 키는 (du_id, du_ue_id)
struct tr_ue_record {
	// 키
	uint64_t du_id; uint32_t du_ue_id; uint8_t du_id_is_temp;
	uint32_t assoc_id;
	uint8_t  used;

	// 수립 하위상태
	uint8_t  path;                 // enum tr_path
	uint8_t  setup_state;          // enum tr_setup_result
	int      est_cause;            // 요청의 establishmentCause
	int      req_cell_index;       // 요청 셀(RRCSetupRequest 를 받은 셀) 레코드 번호, -1=모름
	uint64_t request_time_ns, setup_sent_time_ns;
	uint8_t  saw_setup_sent;       // RRCSetup 을 봤나. NoReply 와 결과 미관측을 가르는 값
	uint64_t deadline_ns;          // 무응답 마감 시각
	uint8_t  open_in_list;         // 마감 대기 heap 에 있나
	uint32_t open_pos;             // open_list(마감 min-heap) 안 위치. 제거와 키 변경을 O(log n) 으로 하려고 둠
	uint64_t ue_identity39;        // 진행 중 수립 색인 키

	/* 게이지 소속. 플래그가 서면 그 셀 레코드의 게이지에 이 UE 가 한 칸 올라가 있음
	 *   in_conn       -> conn_cell_index 의 conn_gauge[conn_level]
	 *   in_ue_context -> ue_context_cell_index 의 ue_context_gauge
	 *   in_inactive   -> inactive_cell_index 의 inactive_gauge[inactive_level]
	 *   half_open     -> half_open_cell_index 의 half_open_gauge
	 * in_ue_context 는 나머지와 상호배타가 아님. UE 컨텍스트는 그 셋의 수명 전체에 걸쳐 있음 */
	uint8_t  in_conn; int conn_level; int conn_cell_index;
	uint8_t  in_ue_context; int ue_context_cell_index;
	uint8_t  in_inactive; int inactive_level; int inactive_cell_index;
	uint8_t  half_open; int half_open_cell_index;

	uint8_t  suspend_resolved;   // 평문 또는 NEA0 RRCRelease 에서 suspendConfig 를 보고 suspend 로 판정함
	uint8_t  n2_released;        // 매칭된 N2 쪽에서 NG 해제(41)를 봄. 완전 해제 신호로 씀
	/* obs 가 F1 과 N2 를 하나로 매칭해 이 UE 에 N2 이벤트를 교차 귀속한 적 있음.
	 * 매칭이 있으면 INACTIVE 가 사라지는 것(매칭된 N2 의 NG 해제)을 관측할 수 있으므로 진입
	 * 등급을 LV_EXACT 로 둠. 매칭이 없으면 소멸을 볼 수 없어 LV_UNKNOWN(상한)임 */
	uint8_t  has_n2_pair;
	uint8_t  rel_had_container;   // F1 해제 COMMAND 에 RRC 컨테이너(SRB1)가 있었음

	/* rrc_state 를 대입하는 모든 지점은 그 상태의 등급 플래그를 같이 대입해야 함. 등급 판정이
	 * 현 rrc_state 로 플래그를 골라 읽기 때문임 - CONNECTED 면 conn_inferred, RELEASED 나
	 * INACTIVE 면 rel_inferred. 같이 대입하지 않으면 이전 에피소드의 값이 남아 등급이 틀어짐.
	 *   RS_CONNECTED               -> conn_inferred = (complete 를 직접 봤으면 0, 아니면 1)
	 *   RS_RELEASED / RS_INACTIVE  -> rel_inferred  = (평문으로 직접 봤으면 0, 추론이면 1)
	 *   RS_IDLE_PENDING / RS_UNKNOWN -> 등급 판정이 두 플래그를 읽지 않음. 레코드 리셋에서 둘 다 0
	 * 상태 전이를 새로 넣을 때도 같이 넣을 것 */
	uint8_t  rel_inferred;        // 현 RELEASED/INACTIVE 를 추론으로 정했음. 등급을 교차 귀속으로 내림
	uint8_t  conn_inferred;       // 현 CONNECTED 를 추론으로 정했음(grant, 불투명, 암호 complete)
	int      est_cell_index;      // 수립이 일어난 셀, -1=모름
	/* Att 를 센 셀. 절차 도중에 바뀌지 않으므로 succ CC 는 여기에 귀속함.
	 * req_cell_index 는 전사(UE transfer)와 UE Context Setup 의 SpCell IE 로 절차 도중에 바뀌므로
	 * 게이지 이동에만 씀 - 그 바뀐 셀에 succ 를 세면 교차 셀에서 succ > att 가 되어 불변식이
	 * 깨짐(att 는 요청 셀, succ 는 전사 셀). -1 = 시도를 못 봄 */
	int      att_cell_index;

	// 재수립 완료를 기다리는 중
	uint8_t  wait_reest;
	uint8_t  reest_succ_counted;   // 재수립 성공을 grant 와 Complete 중 먼저 본 것에서 한 번만 셈. 요청에서 리셋
	uint8_t  resume_succ_counted;  // 재개 성공을 한 번만 셈. 중복 Complete 로 두 번 세지 않으려고. 요청에서 리셋

	// 재개 요청의 원인. 성공을 셀 때까지 들고 있음
	int      resume_cause_pending;

	// 표 I 칸. 관측 이벤트에서 유도할 수 있는 것만 둠
	uint32_t crnti; int has_crnti;
	/* free_list_next: 이 칸이 비었을 때(used=0)만 뜻이 있는 다음 빈 칸 색인+1(0=끝).
	 *   이유: 종전엔 crnti 필드를 재활용해 이 링크를 담았음 - 한 이름이 C-RNTI 와 free-list
	 *   링크 두 개념을 가리켜 읽는 위치에서 거짓이고, 둘 다 uint32_t 라 기계 검출도 불가능했음.
	 *   칸당 4바이트를 더 쓰는 대신 그 거짓이 사라짐 */
	uint32_t free_list_next;
	uint64_t stmsi48; int has_stmsi48; uint64_t stmsi_part1; int has_stmsi_part1;
	int ciph_alg, integ_alg, ciph_alg_now, integ_alg_now; int has_alg;
	int alg_changed_after_smc; uint32_t alg_change_opportunity_count;
	int rrc_state;
	int last_rrc_chan; const char *last_rrc_msg_name; int has_last_rrc;
	int last_nas_epd, last_nas_sht, last_nas_msg_type; int has_last_nas; enum tr_quality nas_msg_quality;
	int rrc_sec_state; enum tr_quality rrc_sec_quality;   // AS 보안 상태. F1 의 SMC/Complete/Failure 에서 유도. 기본 NONE
	int nas_sec_state; enum tr_quality nas_sec_quality;   // NAS 보안 상태. SHT 에서 유도. 기본 UNKNOWN
	int nas_ciph_alg;                                     // NAS SMC 가 고른 값(obs 가 하행 SHT 3 에서만 학습). 기본 -1=모름
	int nas_reg_state; int nas_conn_mode; int nas_reg_state_origin; enum tr_quality nas_state_quality;
	int late_join;
	uint8_t closed;
};

// N2 쪽 UE 레코드. 키는 (assoc_id, ran_ue_ngap_id)
struct tr_n2_record {
	uint32_t assoc_id; uint64_t ran_ue_ngap_id; uint8_t used;
	int est_cause;        // RRCEstablishmentCause(IE 90)
	int uli_cell_index;   // INITIAL UE MESSAGE 의 ULI NR CGI
	uint8_t amf_id_seen;  // UECNTX 성공을 이 레코드당 한 번만 세려는 가드
};

// AMF 과부하 상태. 키는 amf_id, 없으면 assoc_id
struct tr_amf_record {
	uint64_t amf_key; uint32_t last_assoc; uint8_t used;
	int state; uint32_t action_mask;
	uint8_t has_action; uint8_t nssai_list_present;
	int traffic_load_reduction_pct;   // 과부하 판정 입력. 감축 지시가 없으면 -1
};

// ---- 엔진 ----
struct tr {
	struct tr_cfg tr_cfg;
	struct tr_sink_ops sink_ops;   // 출력 콜백 표. tr_new 가 복사해 둠. 칸이 비어 있으면 그 보고를 버림
	void *user_ctx;                // 출력 쪽이 준 문맥. 빌려 쓰는 포인터(tr 보다 오래 살아야 함)

	uint64_t now_ns;
	int started;
	int self_check;                // 자기-불변식 검사를 켜나. 0 이면 검사를 돌지 않아 오버헤드가 없음
	uint64_t cur_start_ns, cur_end_ns;   // 현재 주기 [시작, 끝)
	uint64_t gp_ns;
	uint64_t next_conn_sample_ns, next_inactive_sample_ns;
	int first_period;              // 첫 주기는 부분 주기로 표시함
	/* 이 주기에 뜬 conn/inactive 표본 수. 주기 도중에 처음 나타난 셀의 앞쪽 0 표본을 채우는 데 씀 -
	 * 한 주기의 모든 셀이 표본 수가 같아야 평균을 비교할 수 있음 */
	uint32_t conn_sample_count, inactive_sample_count;

	// 주기 헤더 누적
	uint32_t late_event_count;
	int n2_observed;
	uint64_t lost_evicted_count;
	/* INACTIVE 를 쓰지 않는 망이라고 설정했는데 평문 suspendConfig 를 본 횟수. 망이 INACTIVE 를
	 * 설정한다는 뜻이므로 그 설정이 틀렸다는 경보임 */
	uint32_t inactive_alarm_count;
	// RelWithoutSuspendConfig 를 센 근거 수. 평문으로 본 것과 추론한 것을 따로 둠
	uint32_t release_basis_observed_count, release_basis_assumed_count;

	// 캡처 커버리지와 유실. 누적값(tr_set_coverage)과 주기 시작 스냅샷을 같이 둬 주기 델타를 냄
	uint64_t coverage_tsn_gap_count, coverage_ringbuf_full_count, coverage_esp_seen_count;
	uint64_t coverage_ip_frag_skipped_count, coverage_obs_lost_count;
	uint64_t capture_alive_until_ns;   // 호출자가 알려 준 생존 워터마크. 0 = 한 번도 안 알려 줌 = 확인되지 않음
	uint32_t reset_unresolved_count;   // 일부 RESET 이 가리켰지만 못 닫은 UE(그 주기 델타). 보고 뒤 0 으로 돌림
	uint64_t coverage_snapshot_tsn_gap_count, coverage_snapshot_ringbuf_full_count;
	uint64_t coverage_snapshot_esp_seen_count, coverage_snapshot_ip_frag_skipped_count;
	uint64_t coverage_snapshot_obs_lost_count;

	// 셀 표
	struct tr_cell_record *cell_records; uint32_t cell_count, cell_capacity;
	struct hash_map cell_map;
	int overflow_cell_index;     // 넘침 셀 색인, -1 이면 없음
	int warned_overflow;
	int warned_coverage_reset;   // 커버리지 누적 카운터가 역행했음(탭 재부착이나 리셋). 한 번만 경고

	// UE 표
	struct tr_ue_record *ue_records; uint32_t ue_count, ue_capacity;
	uint32_t ue_free;   // free-list 의 첫 빈 칸 색인+1, 0=빈 칸 없음
	struct hash_map ue_map;

	// 진행 중인 수립 색인. (assoc_id, ue_identity39) -> ue 색인
	struct hash_map setup_idx;

	// N2 표
	struct tr_n2_record *n2_records; uint32_t n2_count, n2_capacity;
	struct hash_map n2_map;

	// AMF 표
	struct tr_amf_record *amf_records; uint32_t amf_count, amf_capacity;
	struct hash_map amf_map;

	// 마감을 기다리는 수립들(ue 색인). tr_advance 가 시간순으로 처리함
	uint32_t *open_list; uint32_t open_count, open_capacity;

	// 출력 스크래치(콜백 동안만 유효)
	struct tr_cc_cell scratch_cc[TR_METRIC__COUNT][MAX_CAUSE];
};

// ---- 키 비교 ----
struct cell_key { const uint8_t *plmn_bytes; uint64_t cell_id; };
static int cell_eq(void *ctx, uint32_t idx, const void *key_ptr)
{
	struct tr *tr = ctx;
	const struct cell_key *cell_key_probe = key_ptr;
	struct tr_cell_record *cell_record = &tr->cell_records[idx];
	return !cell_record->overflow
		&& cell_record->cell.cell_id == cell_key_probe->cell_id
		&& memcmp(cell_record->cell.plmn_bytes, cell_key_probe->plmn_bytes, 3) == 0;
}
static uint64_t cell_hash(const uint8_t *plmn_bytes, uint64_t cell_id)
{
	uint64_t hash = ((uint64_t)plmn_bytes[0] << 56) | ((uint64_t)plmn_bytes[1] << 48) | ((uint64_t)plmn_bytes[2] << 40)
			   | (cell_id & 0xFFFFFFFFFFull);
	return mix64(hash);
}

struct ue_key { uint64_t du_id; uint32_t du_ue_id; uint8_t du_id_is_temp; };
static int ue_eq(void *ctx, uint32_t idx, const void *key_ptr)
{
	struct tr *tr = ctx;
	const struct ue_key *ue_key_probe = key_ptr;
	struct tr_ue_record *ue_record = &tr->ue_records[idx];
	return ue_record->used
		&& ue_record->du_id == ue_key_probe->du_id
		&& ue_record->du_ue_id == ue_key_probe->du_ue_id
		&& ue_record->du_id_is_temp == ue_key_probe->du_id_is_temp;
}
static uint64_t ue_hash(uint64_t du_id, uint32_t du_ue_id, uint8_t du_id_is_temp)
{
	return mix64(du_id * 0x9E3779B97F4A7C15ull + du_ue_id * 2654435761u + du_id_is_temp);
}

struct sx_key { uint32_t assoc_id; uint64_t ue_identity39; };
static int sx_eq(void *ctx, uint32_t idx, const void *key_ptr)
{
	struct tr *tr = ctx;
	const struct sx_key *sx_key_probe = key_ptr;
	struct tr_ue_record *ue_record = &tr->ue_records[idx];
	return ue_record->used
		&& ue_record->assoc_id == sx_key_probe->assoc_id
		&& ue_record->ue_identity39 == sx_key_probe->ue_identity39;
}
static uint64_t sx_hash(uint32_t assoc_id, uint64_t ue_identity39)
{
	return mix64(((uint64_t)assoc_id << 40) ^ mix64(ue_identity39));
}

struct n2_key { uint32_t assoc_id; uint64_t ran_ue_ngap_id; };
static int n2_eq(void *ctx, uint32_t idx, const void *key_ptr)
{
	struct tr *tr = ctx;
	const struct n2_key *n2_key_probe = key_ptr;
	struct tr_n2_record *n2_record = &tr->n2_records[idx];
	return n2_record->used
		&& n2_record->assoc_id == n2_key_probe->assoc_id
		&& n2_record->ran_ue_ngap_id == n2_key_probe->ran_ue_ngap_id;
}
static uint64_t n2_hash(uint32_t assoc_id, uint64_t ran_ue_ngap_id)
{
	return mix64(((uint64_t)assoc_id << 40) ^ mix64(ran_ue_ngap_id));
}

struct amf_key { uint64_t amf_key; };
static int amf_eq(void *ctx, uint32_t idx, const void *key_ptr)
{
	struct tr *tr = ctx;
	const struct amf_key *amf_key_probe = key_ptr;
	return tr->amf_records[idx].used && tr->amf_records[idx].amf_key == amf_key_probe->amf_key;
}

// ---- 경고 ----
static void warn(struct tr *tr, const char *warning_code, const char *detail)
{
	if (tr->sink_ops.on_warning) tr->sink_ops.on_warning(tr->user_ctx, warning_code, detail);
}

// ---- 셀 조회와 생성 ----
static struct tr_cell_record *cell_grow(struct tr *tr)
{
	if (tr->cell_count == tr->cell_capacity) {
		uint32_t new_cell_capacity = tr->cell_capacity ? tr->cell_capacity * 2 : 16;
		struct tr_cell_record *new_cell_records =
			realloc(tr->cell_records, (size_t)new_cell_capacity * sizeof *new_cell_records);
		if (!new_cell_records) return NULL;
		memset(new_cell_records + tr->cell_capacity, 0,
			   (size_t)(new_cell_capacity - tr->cell_capacity) * sizeof *new_cell_records);
		tr->cell_records = new_cell_records; tr->cell_capacity = new_cell_capacity;
	}
	return &tr->cell_records[tr->cell_count++];
}
static int overflow_cell(struct tr *tr)
{
	if (tr->overflow_cell_index < 0) {
		struct tr_cell_record *cell_record = cell_grow(tr);
		if (!cell_record) return -1;
		cell_record->overflow = 1; cell_record->cell.valid = 0;
		// 넘침 셀도 주기 도중에 생기므로 앞쪽 0 표본을 채워 다른 셀과 표본 수를 맞춤
		cell_record->conn_sample_count = tr->conn_sample_count;
		cell_record->inactive_sample_count = tr->inactive_sample_count;
		tr->overflow_cell_index = (int)(cell_record - tr->cell_records);
	}
	if (!tr->warned_overflow) {
		warn(tr, "overflow_cell", "DEF_MAX_CELL_COUNT exceeded; new cells merged");
		tr->warned_overflow = 1;
	}
	return tr->overflow_cell_index;
}
// valid 셀만 받음. 모르면 -1
static int cell_lookup(struct tr *tr, const struct tr_nr_cgi *cell, int create_if_missing)
{
	if (!cell || !cell->valid) return -1;
	struct cell_key cell_key_probe = { cell->plmn_bytes, cell->cell_id };
	uint64_t hash = cell_hash(cell->plmn_bytes, cell->cell_id);
	uint32_t idx = hash_map_get(&tr->cell_map, hash, cell_eq, tr, &cell_key_probe);
	if (idx != UINT32_MAX) return (int)idx;
	if (!create_if_missing) return -1;
	uint32_t limit = DEF_MAX_CELL_COUNT;
	// 넘침 셀을 빼고 센 유효 셀 수
	uint32_t valid_cells = tr->cell_count - (tr->overflow_cell_index >= 0 ? 1u : 0u);
	if (valid_cells >= limit) return overflow_cell(tr);
	struct tr_cell_record *cell_record = cell_grow(tr);
	if (!cell_record) return -1;
	uint32_t new_index = (uint32_t)(cell_record - tr->cell_records);
	cell_record->cell = *cell;
	cell_record->late_join = 1;   // 새로 보인 셀. 그 주기 헤더에 표시하고 주기를 닫을 때 0 으로 돌림
	/* 주기 도중에 나타난 셀이므로 앞쪽 0 표본을 채움(합과 최댓값은 0 유지 = 그 전에는 연결이 0).
	 * 그래야 한 주기의 모든 셀이 표본 수가 같고 ConnMean 의 분모가 주기 전체가 됨(평균 과대 방지) */
	cell_record->conn_sample_count = tr->conn_sample_count;
	cell_record->inactive_sample_count = tr->inactive_sample_count;
	if (hash_map_put(&tr->cell_map, hash, cell_eq, tr, &cell_key_probe, new_index) < 0) return -1;
	return (int)new_index;
}

// ---- UE 조회와 생성 ----
static uint32_t ue_alloc(struct tr *tr)
{
	if (tr->ue_free) {
		uint32_t i = tr->ue_free - 1;
		tr->ue_free = tr->ue_records[i].free_list_next;
		memset(&tr->ue_records[i], 0, sizeof tr->ue_records[i]);
		return i;
	}
	if (tr->ue_count == tr->ue_capacity) {
		uint32_t new_ue_capacity = tr->ue_capacity ? tr->ue_capacity * 2 : 64;
		struct tr_ue_record *ue_record = realloc(tr->ue_records, (size_t)new_ue_capacity * sizeof *ue_record);
		if (!ue_record) return UINT32_MAX;
		memset(ue_record + tr->ue_capacity, 0, (size_t)(new_ue_capacity - tr->ue_capacity) * sizeof *ue_record);
		tr->ue_records = ue_record; tr->ue_capacity = new_ue_capacity;
	}
	return tr->ue_count++;
}
static struct tr_ue_record *ue_lookup(struct tr *tr, const struct tr_f1ue *f1ue,
				      int create_if_missing, uint32_t assoc_id)
{
	if (!f1ue || !f1ue->valid) return NULL;
	struct ue_key ue_key_probe = { f1ue->du_id, f1ue->du_ue_id, f1ue->du_id_is_temp };
	uint64_t hash = ue_hash(f1ue->du_id, f1ue->du_ue_id, f1ue->du_id_is_temp);
	uint32_t idx = hash_map_get(&tr->ue_map, hash, ue_eq, tr, &ue_key_probe);
	if (idx != UINT32_MAX) return &tr->ue_records[idx];
	if (!create_if_missing) return NULL;
	uint32_t new_index = ue_alloc(tr);
	if (new_index == UINT32_MAX) return NULL;
	struct tr_ue_record *ue_record = &tr->ue_records[new_index];
	ue_record->used = 1; ue_record->du_id = f1ue->du_id;
	ue_record->du_ue_id = f1ue->du_ue_id; ue_record->du_id_is_temp = f1ue->du_id_is_temp;
	ue_record->assoc_id = assoc_id;
	ue_record->req_cell_index = -1; ue_record->est_cell_index = -1; ue_record->att_cell_index = -1;
	ue_record->conn_cell_index = -1; ue_record->half_open_cell_index = -1; ue_record->ue_context_cell_index = -1;
	ue_record->resume_cause_pending = -1;
	ue_record->ciph_alg = ue_record->integ_alg = ue_record->ciph_alg_now = ue_record->integ_alg_now = -1;
	ue_record->setup_state = SR_OPEN; ue_record->path = PATH_SETUP;
	ue_record->est_cause = -1; ue_record->rrc_state = RS_UNKNOWN;
	/* 보안 상태 기본값은 둘 다 미상임. AS 쪽에 NONE 을 바로 넣지 않는 이유: 보안 이전이라고
	 * 증명되는 것은 수립 절차에서뿐이고, 늦게 합류하면 이미 보안이 걸렸는지 알 수 없음 */
	ue_record->rrc_sec_state = TR_SEC_UNKNOWN; ue_record->rrc_sec_quality = TR_QUALITY_UNKNOWN;
	ue_record->nas_sec_state = TR_SEC_UNKNOWN; ue_record->nas_sec_quality = TR_QUALITY_UNKNOWN;
	ue_record->nas_ciph_alg = -1;
	// 5GMM 상태도 미상에서 시작함. 늦게 합류했거나 암호가 걸린 뒤면 읽을 수 없기 때문임
	ue_record->nas_reg_state = TR_5GMM_UNKNOWN; ue_record->nas_conn_mode = TR_CM_MODE_UNKNOWN;
	ue_record->nas_reg_state_origin = TR_5GMM_UNKNOWN; ue_record->nas_state_quality = TR_QUALITY_UNKNOWN;
	if (hash_map_put(&tr->ue_map, hash, ue_eq, tr, &ue_key_probe, new_index) < 0) {
		// 색인에 넣지 못했으면 칸을 free-list 로 돌려놓음. 안 돌려놓으면 배열 안에서 영구히 새어 나감
		ue_record->used = 0;
		ue_record->free_list_next = tr->ue_free;
		tr->ue_free = new_index + 1;
		return NULL;
	}
	return ue_record;
}
/* open_list 는 마감 시각을 키로 하는 min-heap 임. 평면 배열이면 시간을 전진시킬 때마다 전체를
 * 선형으로 훑어야 하고 제거도 선형이라, 연결 수립이 몰리는 상황에서 센서가 멈춤. heap 이면 최소
 * 마감 읽기가 O(1), 넣기와 빼기와 키 변경이 O(log n) 임.
 *   open_list[i]      = ue 색인
 *   키                = ue_records[open_list[i]].deadline_ns
 *   ue.open_pos       = heap 안 위치. UE 를 쥐고 제거하거나 키를 고치려고 들고 있음 */
static void heap_swap(struct tr *tr, uint32_t i, uint32_t j)
{
	uint32_t index_a = tr->open_list[i], index_b = tr->open_list[j];
	tr->open_list[i] = index_b; tr->open_list[j] = index_a;
	tr->ue_records[index_b].open_pos = i; tr->ue_records[index_a].open_pos = j;
}
static void heap_sift_up(struct tr *tr, uint32_t i)
{
	while (i > 0) {
		uint32_t parent = (i - 1) / 2;
		if (tr->ue_records[tr->open_list[parent]].deadline_ns <= tr->ue_records[tr->open_list[i]].deadline_ns) break;
		heap_swap(tr, i, parent); i = parent;
	}
}
static void heap_sift_down(struct tr *tr, uint32_t i)
{
	for (;;) {
		uint32_t left = 2 * i + 1, right = 2 * i + 2, smallest = i;
		if (left < tr->open_count
				&& tr->ue_records[tr->open_list[left]].deadline_ns < tr->ue_records[tr->open_list[smallest]].deadline_ns)
			smallest = left;
		if (right < tr->open_count
				&& tr->ue_records[tr->open_list[right]].deadline_ns < tr->ue_records[tr->open_list[smallest]].deadline_ns)
			smallest = right;
		if (smallest == i) break;
		heap_swap(tr, i, smallest); i = smallest;
	}
}
// 위치 i 의 키가 바뀐 뒤 원래 위치로 보냄. 부모보다 작으면 위로, 아니면 아래로(둘 중 하나만 동작함)
static void heap_fix(struct tr *tr, uint32_t i)
{
	if (i > 0 && tr->ue_records[tr->open_list[(i - 1) / 2]].deadline_ns > tr->ue_records[tr->open_list[i]].deadline_ns)
		heap_sift_up(tr, i);
	else
		heap_sift_down(tr, i);
}
static void open_list_add(struct tr *tr, struct tr_ue_record *ue_record)
{
	uint32_t idx = (uint32_t)(ue_record - tr->ue_records);
	if (ue_record->open_in_list) return;
	if (tr->open_count == tr->open_capacity) {
		uint32_t new_open_capacity = tr->open_capacity ? tr->open_capacity * 2 : 32;
		uint32_t *new_list = realloc(tr->open_list, (size_t)new_open_capacity * sizeof *new_list);
		if (!new_list) return;   // 늘리지 못하면 이 UE 의 마감만 추적되지 않음. 메모리 안전에는 영향 없음
		tr->open_list = new_list; tr->open_capacity = new_open_capacity;
	}
	uint32_t i = tr->open_count++;
	tr->open_list[i] = idx; ue_record->open_pos = i; ue_record->open_in_list = 1;
	heap_sift_up(tr, i);
}
static void open_list_remove(struct tr *tr, struct tr_ue_record *ue_record)
{
	if (!ue_record->open_in_list) return;
	uint32_t i = ue_record->open_pos, last = --tr->open_count;
	ue_record->open_in_list = 0;
	if (i != last) {   // 마지막 원소를 빈 위치로 옮기고 다시 정렬
		uint32_t moved_index = tr->open_list[last];
		tr->open_list[i] = moved_index; tr->ue_records[moved_index].open_pos = i;
		heap_fix(tr, i);
	}
}
// 전방 선언. 모든 종료 경로가 ue_record_free 한 곳을 지나며 두 게이지를 비우게 하려고 둠
static void gauge_leave_inactive(struct tr *tr, struct tr_ue_record *ue_record);
static void ue_context_leave(struct tr *tr, struct tr_ue_record *ue_record);
static void ue_record_free(struct tr *tr, struct tr_ue_record *ue_record)
{
	/* 이미 해제된 칸을 다시 해제하는 것을 막음. 막지 않으면 아래 free-list 가 자기를 가리켜
	 * 순환하고, INACTIVE 게이지가 두 번 빠짐 */
	if (!ue_record->used) return;
	gauge_leave_inactive(tr, ue_record);
	/* UE 컨텍스트 이탈도 이 한 곳으로 모음. UEContextReleaseComplete 처리가 이 함수로 끝나고,
	 * 축출, DU ID 재사용, RESET, assoc 종료도 모두 여기를 지남. 그래서 이탈을 빠뜨려 게이지가
	 * 영구히 새는 것이 구조적으로 불가능함 */
	ue_context_leave(tr, ue_record);
	// 색인과 맵에서 제거
	struct ue_key ue_key_probe = { ue_record->du_id, ue_record->du_ue_id, ue_record->du_id_is_temp };
	hash_map_del(&tr->ue_map, ue_hash(ue_record->du_id, ue_record->du_ue_id, ue_record->du_id_is_temp),
			 ue_eq, tr, &ue_key_probe);
	struct sx_key sx_key_probe = { ue_record->assoc_id, ue_record->ue_identity39 };
	// 수립 색인이 이 UE 를 가리킬 때만 지움
	uint32_t setup_index = hash_map_get(&tr->setup_idx, sx_hash(ue_record->assoc_id, ue_record->ue_identity39),
						sx_eq, tr, &sx_key_probe);
	if (setup_index != UINT32_MAX && &tr->ue_records[setup_index] == ue_record)
		hash_map_del(&tr->setup_idx, sx_hash(ue_record->assoc_id, ue_record->ue_identity39),
				 sx_eq, tr, &sx_key_probe);
	open_list_remove(tr, ue_record);
	uint32_t idx = (uint32_t)(ue_record - tr->ue_records);
	ue_record->used = 0;
	ue_record->free_list_next = tr->ue_free;   // 이 칸을 free-list 의 첫 칸으로 넣음
	tr->ue_free = idx + 1;
}

// ---- 게이지 ----
static void gauge_enter_conn(struct tr *tr, struct tr_ue_record *ue_record, int cell_index, int level)
{
	if (ue_record->in_conn || cell_index < 0) return;
	tr->cell_records[cell_index].conn_gauge[level]++;
	ue_record->in_conn = 1; ue_record->conn_level = level; ue_record->conn_cell_index = cell_index;
}
static void gauge_leave_conn(struct tr *tr, struct tr_ue_record *ue_record)
{
	if (!ue_record->in_conn) return;
	// 더한 칸에서만 뺌. 그 사이 셀이 바뀌었어도 올린 곳에서 내려야 게이지가 맞음
	if (ue_record->conn_cell_index >= 0)
		tr->cell_records[ue_record->conn_cell_index].conn_gauge[ue_record->conn_level]--;
	ue_record->in_conn = 0;
}
/* 연결 게이지를 다른 셀로 옮김. 진입도 이탈도 아니라서 모집단과 등급이 보존되고 합이 변하지 않음.
 * 교차 셀 재수립(옛 셀에서 -1, 새 셀에서 +1)과 UE Context Setup 의 SpCell IE 변경에서 씀.
 * 새 셀이 없거나 같은 셀이면 아무것도 하지 않음 */
static void conn_move_cell(struct tr *tr, struct tr_ue_record *ue_record, int new_cell_index)
{
	if (!ue_record->in_conn || new_cell_index < 0 || new_cell_index == ue_record->conn_cell_index) return;
	if (ue_record->conn_cell_index >= 0)
		tr->cell_records[ue_record->conn_cell_index].conn_gauge[ue_record->conn_level]--;
	tr->cell_records[new_cell_index].conn_gauge[ue_record->conn_level]++;
	ue_record->conn_cell_index = new_cell_index;
}
// INACTIVE 게이지. 연결 게이지와 같은 구조임(더한 칸에서만 뺌). suspend 에서 들어가고 resume 이나 해제에서 빠짐
static void gauge_enter_inactive(struct tr *tr, struct tr_ue_record *ue_record, int cell_index, int level)
{
	if (ue_record->in_inactive || cell_index < 0) return;
	tr->cell_records[cell_index].inactive_gauge[level]++;
	ue_record->in_inactive = 1; ue_record->inactive_level = level; ue_record->inactive_cell_index = cell_index;
}
static void gauge_leave_inactive(struct tr *tr, struct tr_ue_record *ue_record)
{
	if (!ue_record->in_inactive) return;
	if (ue_record->inactive_cell_index >= 0)
		tr->cell_records[ue_record->inactive_cell_index].inactive_gauge[ue_record->inactive_level]--;
	ue_record->in_inactive = 0;
}
/* UE 컨텍스트 게이지. 연결 게이지와 같은 형태로 더한 칸에서만 뺌.
 * 최댓값을 진입할 때마다 갱신하는 이유: 이탈은 최댓값을 올릴 수 없으므로 이 한 곳으로 정확함 */
static void ue_context_enter(struct tr *tr, struct tr_ue_record *ue_record, int cell_index)
{
	if (ue_record->in_ue_context || cell_index < 0) return;
	struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
	cell_record->ue_context_gauge++;
	if ((uint32_t)cell_record->ue_context_gauge > cell_record->ue_context_max)
		cell_record->ue_context_max = (uint32_t)cell_record->ue_context_gauge;
	ue_record->in_ue_context = 1; ue_record->ue_context_cell_index = cell_index;
}
static void ue_context_leave(struct tr *tr, struct tr_ue_record *ue_record)
{
	if (!ue_record->in_ue_context) return;
	if (ue_record->ue_context_cell_index >= 0) tr->cell_records[ue_record->ue_context_cell_index].ue_context_gauge--;
	ue_record->in_ue_context = 0;
}
static void half_open_enter(struct tr *tr, struct tr_ue_record *ue_record, int cell_index)
{
	if (ue_record->half_open || cell_index < 0) return;
	tr->cell_records[cell_index].half_open_gauge++;
	ue_record->half_open = 1; ue_record->half_open_cell_index = cell_index;
}
static void half_open_leave(struct tr *tr, struct tr_ue_record *ue_record)
{
	if (!ue_record->half_open) return;
	if (ue_record->half_open_cell_index >= 0) tr->cell_records[ue_record->half_open_cell_index].half_open_gauge--;
	ue_record->half_open = 0;
}

/* ---- 단일 종결 관문 ----
 * 열린 수립 시도를 종결 상태로 옮기는 유일한 경로임. 이미 종결됐으면 아무것도 하지 않음.
 * 열린 수립을 닫는 모든 형제 핸들러가 이 하나를 부르므로, 어느 핸들러가 open_list 제거나
 * half_open 이탈을 빠뜨리는 비대칭이 구조적으로 불가능함.
 * 실패 원인 카운팅은 한 번만 해야 하므로 이 관문 밖, 핸들러의 SR_OPEN 가드 안에 둠 */
static void settle_open_setup(struct tr *tr, struct tr_ue_record *ue_record, int terminal)
{
	if (ue_record->setup_state != SR_OPEN) return;
	ue_record->setup_state = terminal;
	open_list_remove(tr, ue_record);
	half_open_leave(tr, ue_record);
}
/* 연결, 반열림, INACTIVE 게이지에서 UE 를 완전히 빼는 공통 관문(종료, 전사, 축출에서 부름).
 * 셋 다 들지 않은 게이지에 대해서는 아무것도 하지 않으므로 동작이 보존되고, INACTIVE 이탈을
 * 빠뜨려 게이지가 새는 것이 구조적으로 사라짐 */
static void teardown_all_gauges(struct tr *tr, struct tr_ue_record *ue_record)
{
	gauge_leave_conn(tr, ue_record);
	gauge_leave_inactive(tr, ue_record);
	half_open_leave(tr, ue_record);
}

/* ---- 자기-불변식 ----
 * 구조상 항상 참인 사실만 단언으로 둠. self_check 를 켠 빌드(시험, 새니타이저)에서만 부르고,
 * 위반하면 경고를 올린 뒤 중단함. self_check 가 0 이면 호출 자체가 걸려 오버헤드와 동작 변화가 없음 */
static void inv_fail(struct tr *tr, const char *detail, uint32_t value_a, uint32_t value_b)
{
	warn(tr, "INVARIANT", detail);
	fprintf(stderr, "tr self-invariant violated: %s (a=%u b=%u)\n", detail, value_a, value_b);
	abort();
}

/* 전체 검사. 비용은 O(ue_count + cell_count) 임. 보는 것 다섯 가지
 *   게이지 비음수 / 상호배타 / 필드 범위 / 멤버십 합 == 게이지 / open_list 정합
 * 멤버십 대조는 UE 를 한 번 돌며 셀별로 세어 게이지와 맞춰 봄. 대조표는 heap 에 잡아 스택이 안전함 */
static void tr_self_check(struct tr *tr)
{
	if (!tr->self_check) return;
	uint32_t cell_count = tr->cell_count;
	// 게이지 비음수
	for (uint32_t cell_index = 0; cell_index < cell_count; cell_index++) {
		struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
		for (int level = 0; level < 3; level++) {
			if (cell_record->conn_gauge[level]  < 0) inv_fail(tr, "conn_gauge<0",  cell_index, (uint32_t)level);
			if (cell_record->inactive_gauge[level] < 0) inv_fail(tr, "inactive_gauge<0", cell_index, (uint32_t)level);
		}
		if (cell_record->half_open_gauge < 0) inv_fail(tr, "half_open_gauge<0", cell_index, 0);
		if (cell_record->ue_context_gauge < 0) inv_fail(tr, "ue_context_gauge<0", cell_index, 0);
	}
	// 멤버십 대조표
	size_t tally_count = cell_count ? cell_count : 1;
	int32_t (*conn_gauges)[3] = calloc(tally_count, sizeof *conn_gauges);
	int32_t (*inactive_gauges)[3] = calloc(tally_count, sizeof *inactive_gauges);
	int32_t  *half_open_gauges     = calloc(tally_count, sizeof *half_open_gauges);
	int32_t  *ue_context_gauges    = calloc(tally_count, sizeof *ue_context_gauges);
	if (!conn_gauges || !inactive_gauges || !half_open_gauges || !ue_context_gauges) {
		// 대조표를 못 잡으면 검사를 건너뜀. 검사 자체가 진단이므로 여기서 중단하지 않음
		free(conn_gauges); free(inactive_gauges); free(half_open_gauges); free(ue_context_gauges);
		return;
	}
	uint32_t counted_open = 0;
	for (uint32_t i = 0; i < tr->ue_count; i++) {
		struct tr_ue_record *ue_record = &tr->ue_records[i];
		if (!ue_record->used) continue;
		// 상호배타
		int membership_count = (ue_record->in_conn ? 1 : 0) + (ue_record->in_inactive ? 1 : 0)
					 + (ue_record->half_open ? 1 : 0);
		if (membership_count > 1) inv_fail(tr, "UE in >1 gauge (conn/inactive/half_open)", i, (uint32_t)membership_count);
		// 필드 범위와 멤버십 세기
		if (ue_record->in_conn) {
			if (ue_record->conn_cell_index < 0 || (uint32_t)ue_record->conn_cell_index >= cell_count
					|| ue_record->conn_level < 0 || ue_record->conn_level >= 3)
				inv_fail(tr, "conn field range", i, (uint32_t)ue_record->conn_cell_index);
			else conn_gauges[ue_record->conn_cell_index][ue_record->conn_level]++;
		}
		if (ue_record->in_inactive) {
			if (ue_record->inactive_cell_index < 0 || (uint32_t)ue_record->inactive_cell_index >= cell_count
					|| ue_record->inactive_level < 0 || ue_record->inactive_level >= 3)
				inv_fail(tr, "inactive field range", i, (uint32_t)ue_record->inactive_cell_index);
			else inactive_gauges[ue_record->inactive_cell_index][ue_record->inactive_level]++;
		}
		if (ue_record->half_open) {
			if (ue_record->half_open_cell_index < 0 || (uint32_t)ue_record->half_open_cell_index >= cell_count)
				inv_fail(tr, "half_open field range", i, (uint32_t)ue_record->half_open_cell_index);
			else half_open_gauges[ue_record->half_open_cell_index]++;
		}
		// UE 컨텍스트는 상호배타에 넣지 않음. 위 셋과 동시에 성립하는 것이 정상임
		if (ue_record->in_ue_context) {
			if (ue_record->ue_context_cell_index < 0 || (uint32_t)ue_record->ue_context_cell_index >= cell_count)
				inv_fail(tr, "ue_context field range", i, (uint32_t)ue_record->ue_context_cell_index);
			else ue_context_gauges[ue_record->ue_context_cell_index]++;
		}
		// open_list 정합
		if (ue_record->open_in_list) {
			counted_open++;
			if (ue_record->open_pos >= tr->open_count || tr->open_list[ue_record->open_pos] != i)
				inv_fail(tr, "open_list pos mismatch", i, ue_record->open_pos);
			if (ue_record->setup_state != SR_OPEN)
				inv_fail(tr, "open_in_list but !SR_OPEN", i, ue_record->setup_state);
		}
	}
	// 멤버십 합을 게이지와 맞춰 봄
	for (uint32_t cell_index = 0; cell_index < cell_count; cell_index++) {
		struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
		for (int level = 0; level < 3; level++) {
			if (conn_gauges[cell_index][level] != cell_record->conn_gauge[level])
				inv_fail(tr, "conn_gauge != Sum(membership)",  cell_index, (uint32_t)level);
			if (inactive_gauges[cell_index][level] != cell_record->inactive_gauge[level])
				inv_fail(tr, "inactive_gauge != Sum(membership)", cell_index, (uint32_t)level);
		}
		if (half_open_gauges[cell_index] != cell_record->half_open_gauge)
			inv_fail(tr, "half_open_gauge != Sum(membership)", cell_index, 0);
		if (ue_context_gauges[cell_index] != cell_record->ue_context_gauge)
			inv_fail(tr, "ue_context_gauge != Sum(membership)", cell_index, 0);
	}
	// open_in_list 를 센 수와 open_count 가 같아야 함
	if (counted_open != tr->open_count) inv_fail(tr, "open_in_list count != open_count", counted_open, tr->open_count);
	free(conn_gauges); free(inactive_gauges); free(half_open_gauges); free(ue_context_gauges);
}

/* 경고만 하고 절대 중단하지 않는 진단. 셀마다 succ <= att 를 네 묶음에 대해 봄. 관측 유실이
 * 합법적으로 이 관계를 깨뜨릴 수 있어 단언으로 걸지 않고, 교차 셀 오귀속을 신호로만 드러냄.
 * succ > att 가 설계상 합법인 경우: 진행 중인 중복으로 세지 않고 뺀 재요청의 F1 UE 가 완료하면
 * att != succ + fail 이 됨. 이 경고를 없애려고 수립 요청에서 앞선 수립을 강제 종결하지 말 것 -
 * 그렇게 하면 시도와 실패를 겹쳐 세는 결함이 돌아옴 */
static void inv_soft_succ_le_att(struct tr *tr, const struct tr_cell_record *cell_record)
{
	if (!tr->self_check) return;
	static const int PAIR[4][2] = {
		{ TR_METRIC_RRC_CONN_ESTAB_ATT,   TR_METRIC_RRC_CONN_ESTAB_SUCC },
		{ TR_METRIC_UECNTX_CONN_ESTAB_ATT,TR_METRIC_UECNTX_CONN_ESTAB_SUCC },
		{ TR_METRIC_RRC_REESTAB_ATT,      TR_METRIC_RRC_REESTAB_SUCC_WITH_CTX },
		{ TR_METRIC_RRC_RESUME_ATT,       TR_METRIC_RRC_RESUME_SUCC },
	};
	for (int path_index = 0; path_index < 4; path_index++) {
		int att_metric = PAIR[path_index][0], succ_metric = PAIR[path_index][1];
		int cause_count = tr_cause_count((enum tr_metric)att_metric);
		uint64_t attempt_count = cell_record->cc_unknown_nocause[att_metric];
		uint64_t success_count = cell_record->cc_unknown_nocause[succ_metric];
		for (int cause_index = 0; cause_index < cause_count; cause_index++) {
			attempt_count  += cell_record->cc_value[att_metric][cause_index] + cell_record->cc_unknown[att_metric][cause_index];
			success_count += cell_record->cc_value[succ_metric][cause_index] + cell_record->cc_unknown[succ_metric][cause_index];
			for (int excl_index = 0; excl_index < TR_EXCLUDED__COUNT; excl_index++) {
				attempt_count += cell_record->cc_excluded[att_metric][excl_index][cause_index];
				success_count += cell_record->cc_excluded[succ_metric][excl_index][cause_index];
			}
		}
		if (success_count > attempt_count) warn(tr, "SUCC_GT_ATT", tr_metric_name((enum tr_metric)succ_metric));
	}
}

// ---- 마감(대기 시간) ----
/* 무응답 대기는 이 세션 전체에 한 값임. 셀마다 다르게 두지 않는 이유: 출력 쪽이 임계를 광고하는
 * 지점은 접속마다 한 번뿐이라 셀별 값을 실을 곳이 없고, 광고값과 실제 임계가 어긋나면 읽는 쪽이
 * 시도 창을 틀린 칸 수만큼 밀어 무응답과 매칭함.
 * 함수 이름을 설정 필드 이름과 같게 두지 않는 이유: 같으면 지역 변수가 자기 초기화식에서 같은
 * 이름의 함수를 가리고 그래도 컴파일되는 위치가 생김. 역할을 앞에 붙여 가름 */
static uint32_t applied_noreply_timeout_ms(const struct tr *tr)
{
	return tr->tr_cfg.noreply_timeout_ms ? tr->tr_cfg.noreply_timeout_ms : TR_DEF_NOREPLY_TIMEOUT_MS;
}
/* setup_recompute_deadline: 열린 수립 하나의 마감을 다시 잡음.
 *   구간이 둘이라 값도 둘임(tr.h 가 두 구간을 표로 적어 둠). Msg4 를 봤으면 그 시각부터 무응답
 *   대기이고, 못 봤으면 Msg3 시각부터 결과를 못 봤다고 포기하는 창임. 한 값으로 묶으면 둘 중 하나가 틀림 */
static void setup_recompute_deadline(struct tr *tr, struct tr_ue_record *ue_record)
{
	uint64_t base_ns = ue_record->saw_setup_sent ? ue_record->setup_sent_time_ns : ue_record->request_time_ns;
	uint32_t timeout_ms = ue_record->saw_setup_sent ? applied_noreply_timeout_ms(tr)
							: TR_DEF_SETUP_OUTCOME_TIMEOUT_MS;
	ue_record->deadline_ns = base_ns + (uint64_t)timeout_ms * 1000000ull;
	if (ue_record->open_in_list) heap_fix(tr, ue_record->open_pos);   // 이미 heap 에 있으면 키가 바뀐 것이라 다시 정렬
}

// ---- 주기 머신 ----
static uint64_t period_start_for(struct tr *tr, uint64_t now_ns)
{
	// 원점이 0 이면 벽시계의 주기 배수에 맞춤. 0 이 아니면 그 시각을 원점으로 삼아 다른 구현과 대조할 때 씀
	uint64_t gp_origin_ns = tr->tr_cfg.gp_origin_ns;
	// 원점이 미래면 빼기가 음수로 돌아가므로 첫 주기를 원점에서 시작함
	if (now_ns <= gp_origin_ns) return gp_origin_ns;
	return gp_origin_ns + ((now_ns - gp_origin_ns) / tr->gp_ns) * tr->gp_ns;
}
static void engine_start(struct tr *tr, uint64_t now_ns)
{
	tr->gp_ns = (uint64_t)(tr->tr_cfg.gp_ms ? tr->tr_cfg.gp_ms : DEF_GP_MS) * 1000000ull;
	tr->cur_start_ns = period_start_for(tr, now_ns);
	tr->cur_end_ns = tr->cur_start_ns + tr->gp_ns;
	uint64_t conn_period_ns = DEF_CONN_SAMPLE_PERIOD_MS * 1000000ull;
	uint64_t inactive_period_ns = (uint64_t)(tr->tr_cfg.inactive_sample_period_ms ? tr->tr_cfg.inactive_sample_period_ms
										 : DEF_INACTIVE_SAMPLE_PERIOD_MS) * 1000000ull;
	// 첫 표본은 now_ns 를 넘는 첫 경계임. 주기는 시작 시각을 빼고 끝 시각을 넣는 구간이기 때문임
	tr->next_conn_sample_ns = (now_ns / conn_period_ns + 1) * conn_period_ns;
	tr->next_inactive_sample_ns = (now_ns / inactive_period_ns + 1) * inactive_period_ns;
	tr->now_ns = now_ns; tr->started = 1; tr->first_period = 1;
}

static void sample_conn(struct tr *tr)
{
	tr->conn_sample_count++;   // 주기 도중에 생긴 셀의 앞쪽 0 표본을 채우는 기준임
	for (uint32_t i = 0; i < tr->cell_count; i++) {
		struct tr_cell_record *cell_record = &tr->cell_records[i];
		uint64_t lower = (uint64_t)(cell_record->conn_gauge[LV_EXACT] > 0 ? cell_record->conn_gauge[LV_EXACT] : 0);
		uint64_t value = lower
			+ (uint64_t)(cell_record->conn_gauge[LV_INFERRED] > 0 ? cell_record->conn_gauge[LV_INFERRED] : 0);
		uint64_t half_open = (uint64_t)(cell_record->half_open_gauge > 0 ? cell_record->half_open_gauge : 0);
		uint64_t upper = value
			+ (uint64_t)(cell_record->conn_gauge[LV_UNKNOWN] > 0 ? cell_record->conn_gauge[LV_UNKNOWN] : 0)
			+ half_open;
		cell_record->conn_sum[0] += lower; cell_record->conn_sum[1] += value; cell_record->conn_sum[2] += upper;
		cell_record->conn_sample_count++;
		if ((uint32_t)lower  > cell_record->conn_max[0]) cell_record->conn_max[0] = (uint32_t)lower;
		if ((uint32_t)value > cell_record->conn_max[1]) cell_record->conn_max[1] = (uint32_t)value;
		if ((uint32_t)upper  > cell_record->conn_max[2]) cell_record->conn_max[2] = (uint32_t)upper;
		cell_record->half_open_sum += half_open;
		if ((uint32_t)half_open > cell_record->half_open_max) cell_record->half_open_max = (uint32_t)half_open;
	}
}
static void sample_inactive(struct tr *tr)
{
	tr->inactive_sample_count++;
	for (uint32_t i = 0; i < tr->cell_count; i++) {
		struct tr_cell_record *cell_record = &tr->cell_records[i];
		uint64_t lower = (uint64_t)(cell_record->inactive_gauge[LV_EXACT] > 0
						? cell_record->inactive_gauge[LV_EXACT] : 0);
		uint64_t value = lower + (uint64_t)(cell_record->inactive_gauge[LV_INFERRED] > 0
							? cell_record->inactive_gauge[LV_INFERRED] : 0);
		uint64_t upper = value + (uint64_t)(cell_record->inactive_gauge[LV_UNKNOWN] > 0
							? cell_record->inactive_gauge[LV_UNKNOWN] : 0);
		cell_record->inactive_sum[0] += lower; cell_record->inactive_sum[1] += value;
		cell_record->inactive_sum[2] += upper; cell_record->inactive_sample_count++;
		if ((uint32_t)lower  > cell_record->inactive_max[0]) cell_record->inactive_max[0] = (uint32_t)lower;
		if ((uint32_t)value > cell_record->inactive_max[1]) cell_record->inactive_max[1] = (uint32_t)value;
		if ((uint32_t)upper  > cell_record->inactive_max[2]) cell_record->inactive_max[2] = (uint32_t)upper;
	}
}

static void fill_si_mean(struct tr_si *si_stats, const uint64_t sums[3], uint32_t sample_count,
			 int upper_invalid, int unbounded)
{
	memset(si_stats, 0, sizeof *si_stats);
	si_stats->si_sum[0] = sums[0]; si_stats->si_sum[1] = sums[1]; si_stats->si_sum[2] = sums[2];
	si_stats->sample_count = sample_count;
	si_stats->upper_valid = !upper_invalid; si_stats->upper_unbounded = unbounded;
	if (sample_count) {
		si_stats->has_value = true;
		si_stats->lower = (double)sums[0] / sample_count;
		si_stats->value = (double)sums[1] / sample_count;
		si_stats->upper = (double)sums[2] / sample_count;
		si_stats->floor_value = (int64_t)(sums[1] / sample_count);
	}
}
static void fill_si_max(struct tr_si *si_stats, const uint32_t max_values[3], const uint64_t sums[3],
			uint32_t sample_count, int upper_invalid, int unbounded)
{
	memset(si_stats, 0, sizeof *si_stats);
	si_stats->si_sum[0] = sums[0]; si_stats->si_sum[1] = sums[1]; si_stats->si_sum[2] = sums[2];
	si_stats->sample_count = sample_count;
	si_stats->upper_valid = !upper_invalid; si_stats->upper_unbounded = unbounded;
	if (sample_count) {
		si_stats->has_value = true;
		si_stats->lower = (double)max_values[0]; si_stats->value = (double)max_values[1];
		si_stats->upper = (double)max_values[2];
		si_stats->floor_value = (int64_t)max_values[1];
	}
}

static void emit_cell_period(struct tr *tr, struct tr_cell_record *cell_record, int partial)
{
	inv_soft_succ_le_att(tr, cell_record);   // 경고만 하는 진단. 셀마다 succ <= att 를 봄
	if (!tr->sink_ops.on_period) return;
	struct tr_report_header report_header;
	memset(&report_header, 0, sizeof report_header);
	report_header.cell = cell_record->cell;
	report_header.period_start_ns = tr->cur_start_ns; report_header.period_end_ns = tr->cur_end_ns;
	report_header.gp_ms = tr->tr_cfg.gp_ms ? tr->tr_cfg.gp_ms : DEF_GP_MS;
	report_header.partial = partial || tr->first_period;
	// 주기 끝까지 확인됐을 때만 참임. 중간까지만 확인된 주기는 뒷부분을 못 본 것이라 0 으로 셀 수 없음
	report_header.capture_alive = tr->capture_alive_until_ns >= report_header.period_end_ns;
	report_header.late_join = cell_record->late_join;
	report_header.n2_observed = tr->n2_observed;
	report_header.assume_no_inactive = tr->tr_cfg.assume_no_inactive;
	report_header.late_event_count = tr->late_event_count;
	report_header.lost_evicted_count = tr->lost_evicted_count;
	report_header.inactive_alarm_count = tr->inactive_alarm_count;
	report_header.release_basis_observed_count = tr->release_basis_observed_count;
	report_header.release_basis_assumed_count = tr->release_basis_assumed_count;
	/* 관측 맹점 신호는 이 주기의 델타임(누적 - 주기 시작 스냅샷). 링 버퍼 넘침과 IP 조각은 어느 셀의
	 * 것인지 가릴 수 없어 모든 셀에 같은 값을 복제함.
	 * 정상 입력은 한 번의 실행 안에서 단조증가라 누적 >= 스냅샷이 보장되지만, 줄어든 누적이 들어오면
	 * uint64 가 거꾸로 돌아가므로 0 으로 막음 */
	#define COVERAGE_DELTA(cur, snap) ((cur) >= (snap) ? (cur) - (snap) : 0)
	report_header.tsn_gap_count        = COVERAGE_DELTA(tr->coverage_tsn_gap_count,
							   tr->coverage_snapshot_tsn_gap_count);
	report_header.ringbuf_full_count    = COVERAGE_DELTA(tr->coverage_ringbuf_full_count,
							 tr->coverage_snapshot_ringbuf_full_count);
	report_header.esp_seen_count        = COVERAGE_DELTA(tr->coverage_esp_seen_count,
							 tr->coverage_snapshot_esp_seen_count);
	report_header.ip_frag_skipped_count = COVERAGE_DELTA(tr->coverage_ip_frag_skipped_count,
							 tr->coverage_snapshot_ip_frag_skipped_count);
	report_header.obs_lost_count        = COVERAGE_DELTA(tr->coverage_obs_lost_count,
							 tr->coverage_snapshot_obs_lost_count);
	#undef COVERAGE_DELTA
	// 위 다섯 칸은 탭 전체의 값을 모든 셀에 복제한 것임. 읽는 쪽은 셀 사이에 더하지 말고 최댓값이나 첫 값을 쓸 것
	report_header.coverage_tapwide     = true;
	report_header.noreply_timeout_ms = applied_noreply_timeout_ms(tr);
	/* 재개가 하나도 없었다고 증명하려면 네 조건이 모두 서야 함 - 재개 요청 0, 넘어온 미완 재개 0,
	 * 유실 0, 늦게 붙은 레코드 0. 그중 넘어온 미완 재개와 늦게 붙은 UL SRB1 레코드는 관측 층이
	 * 알려 주지 않아 추적할 수 없으므로 false 로 둠. 모르는 조건을 증명됐다고 주장하지 않음 */
	report_header.resume_none_proven = false;
	report_header.late_join_ul_srb1_count = 0;   // 관측 층이 이 수를 내보내지 않아 추적 불가
	report_header.reset_unresolved_count = tr->reset_unresolved_count;

	struct tr_period_report report;
	memset(&report, 0, sizeof report);
	report.report_header = &report_header;
	report.ue_context_max = cell_record->ue_context_max;
	report.initial_ul_count = cell_record->initial_ul_count;
	report.no_du_to_cu_count = cell_record->no_du_to_cu_count;
	report.diag_half_open.si_sum[2] = cell_record->half_open_sum;
	{
		struct tr_si *si_stats = &report.diag_half_open;
		si_stats->sample_count = cell_record->conn_sample_count;
		if (cell_record->conn_sample_count) {
			si_stats->has_value = true;
			si_stats->value = si_stats->lower =
				(double)cell_record->half_open_sum / cell_record->conn_sample_count;
			si_stats->upper = (double)cell_record->half_open_max;
			si_stats->floor_value = (int64_t)(cell_record->half_open_sum / cell_record->conn_sample_count);
		}
	}

	for (int metric_index = 0; metric_index < TR_METRIC__COUNT; metric_index++) {
		if (metric_is_cc((enum tr_metric)metric_index)) {
			int cause_count = tr_cause_count((enum tr_metric)metric_index);
			for (int cause_index = 0; cause_index < cause_count; cause_index++) {
				struct tr_cc_cell *cc_cell = &tr->scratch_cc[metric_index][cause_index];
				memset(cc_cell, 0, sizeof *cc_cell);
				cc_cell->exact = cell_record->cc_value[metric_index][cause_index]
					- cell_record->cc_inferred[metric_index][cause_index];
				cc_cell->inferred = cell_record->cc_inferred[metric_index][cause_index];
				cc_cell->value = cell_record->cc_value[metric_index][cause_index];   // value = exact + inferred
				cc_cell->unknown = cell_record->cc_unknown[metric_index][cause_index];
				for (int excl_index = 0; excl_index < TR_EXCLUDED__COUNT; excl_index++)
					cc_cell->excluded[excl_index] =
						cell_record->cc_excluded[metric_index][excl_index][cause_index];
				for (int overlap_index = 0; overlap_index < TR_OVERLAP__COUNT; overlap_index++)
					cc_cell->overlap[overlap_index] =
						cell_record->cc_overlap[metric_index][cause_index][overlap_index];
			}
			report.cc_cells[metric_index] = tr->scratch_cc[metric_index];
			report.cc_unknown_nocause[metric_index] = cell_record->cc_unknown_nocause[metric_index];
			report.path_value[metric_index] = metric_has_path((enum tr_metric)metric_index)
							 ? cell_record->path_value[metric_index] : NULL;
		} else {
			report.cc_cells[metric_index] = NULL; report.path_value[metric_index] = NULL;
		}
	}
	// SI 네 지표
	fill_si_mean(&report.si_stats[TR_METRIC_RRC_CONN_MEAN], cell_record->conn_sum,
		     cell_record->conn_sample_count, cell_record->evicted_this_period, 0);
	fill_si_max (&report.si_stats[TR_METRIC_RRC_CONN_MAX],  cell_record->conn_max, cell_record->conn_sum,
		     cell_record->conn_sample_count, cell_record->evicted_this_period, 0);
	// INACTIVE 를 쓰지 않는 망이라고 설정하지 않았으면 상한을 모름
	int inactive_unbounded = !tr->tr_cfg.assume_no_inactive;
	fill_si_mean(&report.si_stats[TR_METRIC_RRC_INACTIVE_CONN_MEAN], cell_record->inactive_sum,
		     cell_record->inactive_sample_count, cell_record->evicted_this_period, inactive_unbounded);
	fill_si_max (&report.si_stats[TR_METRIC_RRC_INACTIVE_CONN_MAX],  cell_record->inactive_max,
		     cell_record->inactive_sum, cell_record->inactive_sample_count,
		     cell_record->evicted_this_period, inactive_unbounded);
	tr->sink_ops.on_period(tr->user_ctx, &report);
}

/* 셀이 하나도 없는 주기에도 유실이 있으면 탭 전체 커버리지만 담은 보고를 냄. 제어평면이 전부
 * 암호화됐거나 첫 F1 셀이 만들어지기 전에 스톰이 오면 이 상태가 됨.
 *   종전에는 주기 보고를 셀 단위로만 냈으므로 셀이 0 개면 보고도 0 개였음. 유실이 있어도 읽는
 *   쪽에는 아무 일 없는 것과 같은 모양이 되어, 암호화된 구간에서만 돌던 시나리오의 유실 신호가
 *   통째로 사라졌음.
 * 유실이 0 이면 내지 않음. 할 일 없는 주기마다 빈 보고를 내지 않으려고임.
 * 셀 칸은 valid=false 인 빈 값이고 지표는 비움. 델타 계산식은 emit_cell_period 와 같은 식이므로
 * 커버리지 칸 집합이 바뀌면 두 곳을 같이 고칠 것 */
static void emit_coverage_only_period(struct tr *tr, int partial)
{
	if (!tr->sink_ops.on_period) return;
	#define COVERAGE_DELTA(cur, snap) ((cur) >= (snap) ? (cur) - (snap) : 0)
	uint64_t tsn_gap_count = COVERAGE_DELTA(tr->coverage_tsn_gap_count, tr->coverage_snapshot_tsn_gap_count);
	uint64_t ringbuf_full_count  = COVERAGE_DELTA(tr->coverage_ringbuf_full_count,
						      tr->coverage_snapshot_ringbuf_full_count);
	uint64_t esp_seen_count = COVERAGE_DELTA(tr->coverage_esp_seen_count, tr->coverage_snapshot_esp_seen_count);
	uint64_t ip_frag_skipped_count = COVERAGE_DELTA(tr->coverage_ip_frag_skipped_count,
							tr->coverage_snapshot_ip_frag_skipped_count);
	uint64_t obs_lost_count = COVERAGE_DELTA(tr->coverage_obs_lost_count, tr->coverage_snapshot_obs_lost_count);
	#undef COVERAGE_DELTA
	/* 유실도 경보도 근거 수도 없으면 내지 않음. 경보나 근거 수만 있는 주기는 내보내야 하므로
	 * 그 둘도 조건에 넣음 */
	if (!(tsn_gap_count || ringbuf_full_count || esp_seen_count || ip_frag_skipped_count || obs_lost_count
		  || tr->late_event_count || tr->lost_evicted_count || tr->inactive_alarm_count
		  || tr->release_basis_observed_count || tr->release_basis_assumed_count)) return;
	struct tr_report_header report_header;
	memset(&report_header, 0, sizeof report_header);   // 셀 칸은 valid=false 인 빈 값으로 남음
	report_header.period_start_ns = tr->cur_start_ns; report_header.period_end_ns = tr->cur_end_ns;
	report_header.gp_ms = tr->tr_cfg.gp_ms ? tr->tr_cfg.gp_ms : DEF_GP_MS;
	report_header.partial = partial || tr->first_period;
	// 주기 끝까지 확인됐을 때만 참임. 중간까지만 확인된 주기는 뒷부분을 못 본 것이라 0 으로 셀 수 없음
	report_header.capture_alive = tr->capture_alive_until_ns >= report_header.period_end_ns;
	report_header.n2_observed = tr->n2_observed; report_header.assume_no_inactive = tr->tr_cfg.assume_no_inactive;
	report_header.late_event_count = tr->late_event_count; report_header.lost_evicted_count = tr->lost_evicted_count;
	report_header.inactive_alarm_count = tr->inactive_alarm_count;
	report_header.release_basis_observed_count = tr->release_basis_observed_count;
	report_header.release_basis_assumed_count = tr->release_basis_assumed_count;
	report_header.tsn_gap_count = tsn_gap_count; report_header.ringbuf_full_count = ringbuf_full_count;
	report_header.esp_seen_count = esp_seen_count; report_header.ip_frag_skipped_count = ip_frag_skipped_count;
	report_header.obs_lost_count = obs_lost_count;
	report_header.coverage_tapwide = true;
	struct tr_period_report report;
	memset(&report, 0, sizeof report);
	report.report_header = &report_header;   // memset 으로 cc_cells, si_stats, path_value 가 전부 비어 커버리지만 담김
	tr->sink_ops.on_period(tr->user_ctx, &report);
}

static void close_period(struct tr *tr, int partial)
{
	for (uint32_t i = 0; i < tr->cell_count; i++)
		emit_cell_period(tr, &tr->cell_records[i], partial);
	if (tr->cell_count == 0) emit_coverage_only_period(tr, partial);
	// 주기 리셋. CC 와 SI 누적, 주기 헤더 누적을 0 으로 돌리고 게이지는 그대로 둠
	for (uint32_t i = 0; i < tr->cell_count; i++) {
		struct tr_cell_record *cell_record = &tr->cell_records[i];
		memset(cell_record->cc_value, 0, sizeof cell_record->cc_value);
		memset(cell_record->cc_inferred, 0, sizeof cell_record->cc_inferred);
		memset(cell_record->cc_unknown, 0, sizeof cell_record->cc_unknown);
		memset(cell_record->cc_unknown_nocause, 0, sizeof cell_record->cc_unknown_nocause);
		memset(cell_record->cc_excluded, 0, sizeof cell_record->cc_excluded);
		memset(cell_record->cc_overlap, 0, sizeof cell_record->cc_overlap);
		memset(cell_record->path_value, 0, sizeof cell_record->path_value);
		memset(cell_record->conn_sum, 0, sizeof cell_record->conn_sum);
		cell_record->conn_sample_count = 0;
		memset(cell_record->conn_max, 0, sizeof cell_record->conn_max);
		memset(cell_record->inactive_sum, 0, sizeof cell_record->inactive_sum);
		cell_record->inactive_sample_count = 0;
		memset(cell_record->inactive_max, 0, sizeof cell_record->inactive_max);
		cell_record->half_open_sum = 0; cell_record->half_open_max = 0;
		cell_record->evicted_this_period = 0;
		/* 계수기는 0 으로 돌리고, UE 컨텍스트 최댓값은 주기가 시작될 때 이미 있던 수에서 시작함.
		 * 그 주기에 아무 일도 없으면 그 수가 그대로 최댓값이어야 하기 때문임 */
		cell_record->initial_ul_count = 0; cell_record->no_du_to_cu_count = 0;
		cell_record->ue_context_max = (uint32_t)(cell_record->ue_context_gauge > 0
							 ? cell_record->ue_context_gauge : 0);
		cell_record->late_join = 0;
	}
	tr->late_event_count = 0; tr->n2_observed = 0; tr->lost_evicted_count = 0;
	tr->inactive_alarm_count = 0;
	tr->release_basis_observed_count = 0; tr->release_basis_assumed_count = 0;
	tr->reset_unresolved_count = 0;
	// 셀별 표본 수 리셋과 같이 돌려야 한 주기의 표본 수가 맞음
	tr->conn_sample_count = 0; tr->inactive_sample_count = 0;
	// 다음 주기 델타의 기준점은 지금 누적임. 이 주기분은 위에서 이미 헤더에 실렸음
	tr->coverage_snapshot_tsn_gap_count = tr->coverage_tsn_gap_count;
	tr->coverage_snapshot_ringbuf_full_count = tr->coverage_ringbuf_full_count;
	tr->coverage_snapshot_esp_seen_count = tr->coverage_esp_seen_count;
	tr->coverage_snapshot_ip_frag_skipped_count = tr->coverage_ip_frag_skipped_count;
	tr->coverage_snapshot_obs_lost_count = tr->coverage_obs_lost_count;
	tr->first_period = 0;
	tr_self_check(tr);   // 주기를 리셋한 뒤에도 게이지가 유지되고 멤버십과 맞는지 확인
}

// 마감이 발화해 열린 수립을 닫음
static void fire_deadline(struct tr *tr, struct tr_ue_record *ue_record)
{
	// 무응답 실패도 요청 셀에 귀속함. 시도를 센 셀과 같아야 형제 대칭이 맞음
	int cell_index = (ue_record->att_cell_index >= 0) ? ue_record->att_cell_index : ue_record->req_cell_index;
	if (cell_index >= 0) {
		struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
		if (ue_record->saw_setup_sent) {
			// RRCSetup 을 봤으므로 무응답임
			cell_record->cc_value[TR_METRIC_RRC_CONN_ESTAB_FAIL_CAUSE][FC_NOREPLY]++;
			cell_record->path_value[TR_METRIC_RRC_CONN_ESTAB_FAIL_CAUSE][ue_record->path]++;
			ue_record->setup_state = SR_NOREPLY;
		} else {
			// RRCSetup 을 못 봤으므로 원인 없는 unknown 임
			cell_record->cc_unknown_nocause[TR_METRIC_RRC_CONN_ESTAB_FAIL_CAUSE]++;
			ue_record->setup_state = SR_UNKNOWN;
		}
	} else {
		ue_record->setup_state = ue_record->saw_setup_sent ? SR_NOREPLY : SR_UNKNOWN;
	}
	/* 이 마감은 진행 중인 수립 절차의 끝이고 반쯤 열린 연결의 끝이 아님. 무응답으로 판정해도 그 UE 의
	 * 컨텍스트는 F1 해제까지 CU 에 남으므로 두 구간은 일부러 다르게 둠.
	 * 그래서 여기서 half_open_leave 를 부르지 않음. 불렀다면 마감 시각부터 실제 해제까지의 구간이
	 * ConnMean 과 ConnMax 의 상한, 반열림 진단에서 빠져 과소 집계가 됨. 형제인 연결 게이지도 해제
	 * COMPLETE 에서 빠지므로 여기서 안 빼는 것이 수명 대칭임.
	 * 반열림은 실제 끝 신호에서만 빠짐 - RRCSetupComplete 수신, 해제 명령과 완료, F1 RESET,
	 * SCTP 종료, 번호 재사용, 축출. 그 경로들은 on_setup_complete, on_reject,
	 * on_ctx_release_complete, teardown_all_gauges, on_ue_evicted 가 보장함 */
	open_list_remove(tr, ue_record);
}

/* advance_to: 시간을 target 까지 진행하며 표본, 마감, 주기 경계를 시간순으로 처리함.
 *   같은 시각에 겹치면 우선순위는 표본(conn, inactive) < 주기 끝 < 마감 임. 근거: 표본은 시작을
 *   빼고 끝을 넣는 구간이라 주기 끝에서 닫는 주기에 들고, 주기 끝 뒤에 발화한 마감은 다음 주기에 듦 */
static void advance_to(struct tr *tr, uint64_t target_ns)
{
	if (!tr->started) { engine_start(tr, target_ns); return; }
	if (target_ns <= tr->now_ns) return;
	/* 한 번의 전진이 1일을 넘으면 손상된 시각으로 보고 상한으로 자름. 정상 캡처의 이벤트 간격은
	 * 이보다 훨씬 작아 영향이 없고, 라이브는 커널 단조시계라 해당되지 않음.
	 * 캡처 쪽에서 시각을 검사하더라도 거대한 target 이 어떤 경로로든 들어오면 아래 루프가 주기를
	 * 끝없이 닫으며 멈추지 않으므로, 루프 밖에서 한 번 묶어 둠 */
	if (target_ns - tr->now_ns > ADVANCE_MAX_NS) target_ns = tr->now_ns + ADVANCE_MAX_NS;
	uint64_t conn_period_ns = DEF_CONN_SAMPLE_PERIOD_MS * 1000000ull;
	uint64_t inactive_period_ns = (uint64_t)(tr->tr_cfg.inactive_sample_period_ms ? tr->tr_cfg.inactive_sample_period_ms
										 : DEF_INACTIVE_SAMPLE_PERIOD_MS) * 1000000ull;

	for (;;) {
		// 가장 이른 마감은 heap 루트라 O(1) 로 읽음. 빼는 것은 fire_deadline 안의 open_list_remove 가 O(log n) 으로 함
		uint64_t earliest_deadline_ns = (uint64_t)-1; uint32_t deadline_ue_index = UINT32_MAX;
		if (tr->open_count > 0) {
			deadline_ue_index = tr->open_list[0];
			earliest_deadline_ns = tr->ue_records[deadline_ue_index].deadline_ns;
		}
		// 후보 시각을 우선순위 순으로 늘어놓음. conn 표본, inactive 표본, 주기 끝, 마감
		uint64_t candidate_ns[4] = { tr->next_conn_sample_ns, tr->next_inactive_sample_ns,
					     tr->cur_end_ns, earliest_deadline_ns };
		uint64_t next_ns = candidate_ns[0];
		for (int i = 1; i < 4; i++) if (candidate_ns[i] < next_ns) next_ns = candidate_ns[i];
		if (next_ns > target_ns) { tr->now_ns = target_ns; break; }
		// 같은 시각이면 앞쪽 후보가 이김
		int fired_candidate = (candidate_ns[0] == next_ns) ? 0
				    : (candidate_ns[1] == next_ns) ? 1
				    : (candidate_ns[2] == next_ns) ? 2 : 3;
		tr->now_ns = next_ns;
		switch (fired_candidate) {
		case 0:
			sample_conn(tr);
			tr->next_conn_sample_ns += conn_period_ns;
			break;
		case 1:
			sample_inactive(tr);
			tr->next_inactive_sample_ns += inactive_period_ns;
			break;
		case 2:
			close_period(tr, 0);
			tr->cur_start_ns = tr->cur_end_ns;
			tr->cur_end_ns += tr->gp_ns;
			break;
		case 3:
			fire_deadline(tr, &tr->ue_records[deadline_ue_index]);
			break;
		}
	}
}

// ---- 표 I 줄 ----
static void emit_ue_line(struct tr *tr, struct tr_ue_record *ue_record, const struct obs_event *event,
			 uint32_t changed, int closed)
{
	if (!tr->sink_ops.on_ue_line) return;
	/* 이 이벤트가 디코드된 RRC 면 그 통로와 메시지 이름으로 마지막 RRC 를 갱신함. 일찍 돌아가는
	 * 분기보다 위에 두는 이유: 바뀐 칸이 없는 RRC 이벤트도 마지막 RRC 를 남겨야 뒤따르는 줄이
	 * 올바른 값을 읽음. 메시지 이름을 핸들러마다 상수로 박으면 그 핸들러가 다루는 두어 개만 기록됨 */
	if (event->rrc_chan > 0) {
		ue_record->last_rrc_chan = event->rrc_chan;
		ue_record->last_rrc_msg_name = event->rrc_msg_name;
		ue_record->has_last_rrc = 1;
	}
	if (!changed && !closed) return;
	struct tr_ue_line ue_line; memset(&ue_line, 0, sizeof ue_line);
	ue_line.wallclock_ns = event->wallclock_ns; ue_line.trigger_event = event->kind;
	ue_line.f1ue = event->f1ue; ue_line.n2ue = event->n2ue;
	if (ue_record->req_cell_index >= 0) ue_line.cell = tr->cell_records[ue_record->req_cell_index].cell;
	else if (event->cell.valid) ue_line.cell = event->cell;
	ue_line.changed_mask = changed; ue_line.closed = closed ? true : false;
	/* 등급은 값을 실제로 관측하거나 판정했을 때만 EXACT 임. 관측하지 못했으면 UNKNOWN 으로 내림.
	 * 안 그러면 모르는 값(알고리즘 -1, C-RNTI 0, 미상 상태)에 EXACT 가 붙어 읽는 쪽이 그것을
	 * 측정값으로 받음 */
	ue_line.crnti = ue_record->crnti;
	ue_line.crnti_quality = ue_record->has_crnti ? TR_QUALITY_EXACT : TR_QUALITY_UNKNOWN;
	ue_line.has_stmsi48 = ue_record->has_stmsi48 ? true : false;
	ue_line.stmsi48 = ue_record->stmsi48;
	ue_line.stmsi48_quality = ue_record->has_stmsi48 ? TR_QUALITY_EXACT : TR_QUALITY_UNKNOWN;
	ue_line.ciph_alg = ue_record->ciph_alg; ue_line.integ_alg = ue_record->integ_alg;
	ue_line.alg_quality = ue_record->has_alg ? TR_QUALITY_EXACT : TR_QUALITY_UNKNOWN;
	ue_line.ciph_alg_now = ue_record->ciph_alg_now; ue_line.integ_alg_now = ue_record->integ_alg_now;
	ue_line.alg_changed_after_smc = ue_record->alg_changed_after_smc ? true : false;
	ue_line.alg_change_opportunity_count = ue_record->alg_change_opportunity_count;
	ue_line.rrc_state = ue_record->rrc_state;
	/* 등급을 현 rrc_state 로 걸러 읽음. 각 플래그는 그 상태에서만 뜻이 있음
	 *   CONNECTED             -> conn_inferred. 추론이면 STRUCT, 직접 본 complete 면 EXACT
	 *   RELEASED / INACTIVE   -> rel_inferred.  추론이면 CROSS, 평문으로 봤으면 EXACT
	 *   IDLE_PENDING(요청 관측) -> EXACT
	 *   UNKNOWN               -> UNKNOWN
	 * 상태로 걸러야 하는 이유: 종전에는 rel_inferred 를 상태와 무관하게 먼저 봤음. RELEASED 나
	 * INACTIVE 에서 재개나 재수립이나 전사로 CONNECTED 로 돌아오면 이전 에피소드에 남은
	 * rel_inferred 가 conn_inferred 를 가려 CONNECTED 가 CROSS 로 잘못 등급됐음(실측).
	 * 그 플래그를 지우는 곳이 레코드 리셋 한 곳뿐이라 생긴 일임 */
	ue_line.rrc_state_quality =
		(ue_record->rrc_state == RS_UNKNOWN) ? TR_QUALITY_UNKNOWN :
		(ue_record->rrc_state == RS_CONNECTED)
			? (ue_record->conn_inferred ? TR_QUALITY_STRUCT : TR_QUALITY_EXACT) :
		((ue_record->rrc_state == RS_RELEASED || ue_record->rrc_state == RS_INACTIVE)
			? (ue_record->rel_inferred ? TR_QUALITY_CROSS : TR_QUALITY_EXACT) : TR_QUALITY_EXACT);
	/* NAS 상태 세 줄은 이 계층이 유도한 값임 - 5GMM 주상태는 NAS 메시지에서, AS 보안 상태는 F1 의
	 * SMC 와 Complete 와 Failure 에서, NAS 보안 상태는 SHT 에서 유도함. NAS 암호 알고리즘만은
	 * 관측 층이 하행 SMC 에서 읽어 준 값을 그대로 실음 */
	ue_line.nas_reg_state = ue_record->nas_reg_state; ue_line.nas_conn_mode = ue_record->nas_conn_mode;
	ue_line.nas_state_quality = ue_record->nas_state_quality;
	ue_line.rrc_sec_state = ue_record->rrc_sec_state; ue_line.rrc_sec_quality = ue_record->rrc_sec_quality;
	ue_line.nas_sec_state = ue_record->nas_sec_state; ue_line.nas_sec_quality = ue_record->nas_sec_quality;
	ue_line.nas_ciph_alg = ue_record->nas_ciph_alg;
	ue_line.rrc_chan = ue_record->last_rrc_chan; ue_line.rrc_msg_name = ue_record->last_rrc_msg_name;
	ue_line.rrc_msg_quality = ue_record->has_last_rrc ? TR_QUALITY_EXACT : TR_QUALITY_UNKNOWN;
	ue_line.nas_epd = ue_record->last_nas_epd; ue_line.nas_sht = ue_record->last_nas_sht;
	ue_line.nas_msg_type = ue_record->last_nas_msg_type;
	// 교차 귀속으로 얻은 값이면 그 등급을 그대로 유지함
	ue_line.nas_msg_quality = ue_record->has_last_nas ? ue_record->nas_msg_quality : TR_QUALITY_UNKNOWN;
	tr->sink_ops.on_ue_line(tr->user_ctx, &ue_line);
}

// ---- AMF 과부하 ----
static struct tr_amf_record *amf_lookup(struct tr *tr, uint64_t amf_key, int create_if_missing)
{
	struct amf_key amf_key_probe = { amf_key };
	uint64_t hash = mix64(amf_key);
	uint32_t idx = hash_map_get(&tr->amf_map, hash, amf_eq, tr, &amf_key_probe);
	if (idx != UINT32_MAX) return &tr->amf_records[idx];
	if (!create_if_missing) return NULL;
	if (tr->amf_count == tr->amf_capacity) {
		uint32_t new_amf_capacity = tr->amf_capacity ? tr->amf_capacity * 2 : 8;
		struct tr_amf_record *amf_record =
			realloc(tr->amf_records, (size_t)new_amf_capacity * sizeof *amf_record);
		if (!amf_record) return NULL;
		memset(amf_record + tr->amf_capacity, 0,
			   (size_t)(new_amf_capacity - tr->amf_capacity) * sizeof *amf_record);
		tr->amf_records = amf_record; tr->amf_capacity = new_amf_capacity;
	}
	uint32_t new_index = tr->amf_count++;
	tr->amf_records[new_index].used = 1; tr->amf_records[new_index].amf_key = amf_key;
	tr->amf_records[new_index].state = AMF_NONE;
	tr->amf_records[new_index].traffic_load_reduction_pct = -1;   // 감축 지시 기본은 없음
	if (hash_map_put(&tr->amf_map, hash, amf_eq, tr, &amf_key_probe, new_index) < 0) {
		// 맵에 못 넣었으면 레코드도 되돌림. 안 되돌리면 레코드는 있는데 맵엔 없어 뒤에 중복 생성됨
		tr->amf_records[new_index].used = 0;
		tr->amf_count--;
		return NULL;
	}
	return &tr->amf_records[new_index];
}
/* AMF 레코드 하나를 지움. 마지막 원소를 구멍으로 옮겨 배열과 맵의 크기를 같이 줄임. N2 assoc 이
 * 끝날 때 부름(N2 레코드 제거와 대칭).
 * 지우지 않으면 두 가지가 생김
 *   (1) AMF ID 가 없을 때 키가 assoc_id 이고 assoc 번호는 단조증가하므로 표가 계속 늘어남
 *   (2) 끊긴 assoc 의 과부하 레코드가 영구히 남아, 사라진 AMF 를 계속 과부하로 세어 이후 수립을
 *       잘못 제외하거나 미상으로 떨어뜨림
 * 끊긴 AMF 는 '있지만 미상' 이 아니라 '없음' 이 맞음. 새 연결은 NG Setup 이나 Overload 에서
 * 레코드를 다시 만듦 */
static void amf_remove_at(struct tr *tr, uint32_t idx)
{
	if (idx >= tr->amf_count) return;
	struct amf_key amf_key_probe = { tr->amf_records[idx].amf_key };
	hash_map_del(&tr->amf_map, mix64(tr->amf_records[idx].amf_key), amf_eq, tr, &amf_key_probe);
	uint32_t last = tr->amf_count - 1;
	if (idx != last) {
		struct amf_key moved_amf_key_probe = { tr->amf_records[last].amf_key };
		uint64_t moved_hash = mix64(tr->amf_records[last].amf_key);
		tr->amf_records[idx] = tr->amf_records[last];   // 마지막 원소를 구멍으로 옮김
		// 옮긴 원소의 옛 매핑을 지우고 새 위치로 다시 넣음
		hash_map_del(&tr->amf_map, moved_hash, amf_eq, tr, &moved_amf_key_probe);
		hash_map_put(&tr->amf_map, moved_hash, amf_eq, tr, &moved_amf_key_probe, idx);
	}
	tr->amf_records[last].used = 0;
	tr->amf_count = last;
}
/* 이 assoc 에 딸린 AMF 레코드를 전부 회수함. AMF 레코드는 N2 의 SCTP assoc 으로 키를 매기므로
 * (AMF ID 를 못 봤으면 키가 assoc_id) 반드시 N2 쪽 assoc 종료에서 불러야 함. F1 쪽 경로에서
 * 부르면 assoc 번호가 맞지 않아 아무것도 지우지 못함.
 * 남는 경우: UE 레코드가 하나도 없던 N2 assoc 은 관측 층이 레코드별 종료를 내보내지 않아 여기
 * 도달하지 못함. 그 드문 경우의 레코드 한 건은 같은 키를 쓰는 다음 NG Setup 이나 tr_free 까지
 * 남을 수 있음. 수량은 묶여 있고, AMF ID 가 없는 한 N2 경로에 끼어든 공격자만 늘릴 수 있음 */
static void amf_drop_assoc(struct tr *tr, uint32_t assoc_id)
{
	for (uint32_t i = 0; i < tr->amf_count; )
		// 지우면 그 위치에 마지막 원소가 들어오므로 i 를 올리지 않고 다시 봄
		if (tr->amf_records[i].used && tr->amf_records[i].last_assoc == assoc_id) amf_remove_at(tr, i);
		else i++;
}
/* Overload Action 값에서 거부되는 수립 원인 집합을 냄(TS 38.413 §8.7.7.2).
 *   action_mask = 1u << overloadAction 이고, 값의 뜻은
 *     0 = 비응급 발신 데이터 거부, 1 = 신호용 연결 거부,
 *     2 = 응급과 착신만 허용,     3 = 고우선과 착신만 허용
 *   종전에는 이 값을 무시하고 모든 action 에 같은 원인 집합을 적용했음. 넷 중 하나만 우연히
 *   맞고 나머지 셋이 틀렸는데, 0 은 신호용 연결을 과잉 거부하고 '만 허용' 두 값은 대부분을
 *   과소 거부했음.
 *   원인 칸 번호: emergency 0, highPriorityAccess 1, mtAccess 2, moSignalling 3, moData 4,
 *   moVoiceCall 5, moVideoCall 6, moSMS 7, mpsPriorityAccess 8, mcsPriorityAccess 9, spare 10~15 */
static int action_covers(uint32_t mask, int est_cause)
{
	// 비응급 발신 데이터
	if (mask & (1u << 0)) return est_cause == 4 || est_cause == 5 || est_cause == 6 || est_cause == 7;
	// 위에 신호용 연결을 더함
	if (mask & (1u << 1))
		return est_cause == 3 || est_cause == 4 || est_cause == 5 || est_cause == 6 || est_cause == 7;
	// 응급과 착신만 허용이므로 그 둘 외 전부 거부
	if (mask & (1u << 2)) return !(est_cause == 0 || est_cause == 2);
	// 고우선과 우선순위 둘, 착신만 허용
	if (mask & (1u << 3))
		return !(est_cause == 1 || est_cause == 8 || est_cause == 9 || est_cause == 2);
	// 빈 마스크나 모르는 값이면 거부 목록을 알 수 없음. 부르는 쪽이 미상으로 처리함
	return 0;
}
/* 과부하 판정. 위에서부터 처음 맞는 줄을 씀. '살아 있는 AMF' 는 떨어져 나가지 않은 AMF 임
 *   1  살아 있는 AMF 가 없거나 모두 정상        -> 셈
 *   2  살아 있는 AMF 가 둘 이상이고 그중 하나라도 과부하거나 미상 -> 미상
 *   3  살아 있는 AMF 가 하나이고 그것이 미상    -> 미상
 *   4  action 이 있고 감축 지시가 없고 원인이 거부 목록에 있음    -> 뺌
 *   5  action 이 있고 감축 지시가 있고 원인이 거부 목록에 있음    -> 미상
 *   6  슬라이스 목록이 있음                     -> 미상
 *   7  action 이 없거나 모르는 값               -> 미상
 *   8  그 밖                                    -> 셈 */
static enum overload_decision decide_overload(struct tr *tr, int est_cause)
{
	int live_amf_count = 0, overload_or_unknown_count = 0;
	struct tr_amf_record *amf_record = NULL;
	for (uint32_t i = 0; i < tr->amf_count; i++) {
		if (!tr->amf_records[i].used || tr->amf_records[i].state == AMF_DETACHED) continue;
		live_amf_count++;
		if (tr->amf_records[i].state != AMF_NONE) {
			overload_or_unknown_count++;
			amf_record = &tr->amf_records[i];
		}
	}
	if (live_amf_count == 0 || overload_or_unknown_count == 0) return OVERLOAD_COUNT;   // 1
	if (live_amf_count >= 2) return OVERLOAD_UNKNOWN;                 // 2. 경고는 부르는 쪽이 셈
	if (amf_record->state == AMF_UNKNOWN) return OVERLOAD_UNKNOWN;    // 3. 지금 이 상태는 대입되지 않음
	// 여기부터는 살아 있는 AMF 가 하나이고 그것이 과부하인 경우임
	int in_list = amf_record->has_action && amf_record->action_mask != 0
			&& action_covers(amf_record->action_mask, est_cause);
	// 감축 지시가 1 이상이면 얼마나 줄이는지 모르므로 미상(5), 없으면 전부 거부로 보고 뺌(4)
	if (in_list) return amf_record->traffic_load_reduction_pct > 0 ? OVERLOAD_UNKNOWN : OVERLOAD_EXCLUDE;
	if (amf_record->nssai_list_present) return OVERLOAD_UNKNOWN;      // 6
	if (!amf_record->has_action || amf_record->action_mask == 0) return OVERLOAD_UNKNOWN;   // 7
	return OVERLOAD_COUNT;                                            // 8. action 이 있고 원인이 거부 목록 밖
}

// ---- N2 레코드 ----
static struct tr_n2_record *n2_lookup(struct tr *tr, uint32_t assoc_id, uint64_t ran_ue_ngap_id,
				      int create_if_missing)
{
	struct n2_key n2_key_probe = { assoc_id, ran_ue_ngap_id };
	uint64_t hash = n2_hash(assoc_id, ran_ue_ngap_id);
	uint32_t idx = hash_map_get(&tr->n2_map, hash, n2_eq, tr, &n2_key_probe);
	if (idx != UINT32_MAX) return &tr->n2_records[idx];
	if (!create_if_missing) return NULL;
	if (tr->n2_count == tr->n2_capacity) {
		uint32_t new_n2_capacity = tr->n2_capacity ? tr->n2_capacity * 2 : 32;
		struct tr_n2_record *n2_record =
			realloc(tr->n2_records, (size_t)new_n2_capacity * sizeof *n2_record);
		if (!n2_record) return NULL;
		memset(n2_record + tr->n2_capacity, 0,
			   (size_t)(new_n2_capacity - tr->n2_capacity) * sizeof *n2_record);
		tr->n2_records = n2_record; tr->n2_capacity = new_n2_capacity;
	}
	uint32_t new_index = tr->n2_count++;
	tr->n2_records[new_index].used = 1; tr->n2_records[new_index].assoc_id = assoc_id;
	tr->n2_records[new_index].ran_ue_ngap_id = ran_ue_ngap_id;
	tr->n2_records[new_index].uli_cell_index = -1; tr->n2_records[new_index].est_cause = -1;
	if (hash_map_put(&tr->n2_map, hash, n2_eq, tr, &n2_key_probe, new_index) < 0) {
		// 맵에 못 넣었으면 레코드도 되돌림
		tr->n2_records[new_index].used = 0;
		tr->n2_count--;
		return NULL;
	}
	return &tr->n2_records[new_index];
}

/* N2 레코드 하나를 지움. 마지막 원소를 구멍으로 옮겨 배열과 맵의 크기를 같이 줄임. N2 종료
 * 이벤트에서 부름(관측 층의 수명과 대칭).
 * UECNTX 의 시도와 성공은 누적 카운터라 레코드를 지워도 값에 영향이 없음. 메모리만 회수함 */
static void n2_remove(struct tr *tr, uint32_t assoc_id, uint64_t ran_ue_ngap_id)
{
	struct n2_key n2_key_probe = { assoc_id, ran_ue_ngap_id };
	uint64_t hash = n2_hash(assoc_id, ran_ue_ngap_id);
	uint32_t idx = hash_map_get(&tr->n2_map, hash, n2_eq, tr, &n2_key_probe);
	if (idx == UINT32_MAX) return;
	hash_map_del(&tr->n2_map, hash, n2_eq, tr, &n2_key_probe);
	uint32_t last = tr->n2_count - 1;
	if (idx != last) {
		struct n2_key moved_n2_key_probe = { tr->n2_records[last].assoc_id,
						     tr->n2_records[last].ran_ue_ngap_id };
		uint64_t moved_hash = n2_hash(moved_n2_key_probe.assoc_id, moved_n2_key_probe.ran_ue_ngap_id);
		tr->n2_records[idx] = tr->n2_records[last];   // 마지막 원소를 구멍으로 옮김
		// 옮긴 원소의 옛 매핑을 지우고 새 위치로 다시 넣음
		hash_map_del(&tr->n2_map, moved_hash, n2_eq, tr, &moved_n2_key_probe);
		hash_map_put(&tr->n2_map, moved_hash, n2_eq, tr, &moved_n2_key_probe, idx);
	}
	tr->n2_records[last].used = 0;
	tr->n2_count = last;
}

uint32_t tr_n2_count(const struct tr *tr) { return tr ? tr->n2_count : 0; }

// ---- 수립 종료 공통 ----
// 열린 수립을 결과를 모르는 실패로 닫음
static void close_setup_other(struct tr *tr, struct tr_ue_record *ue_record)
{
	if (ue_record->setup_state == SR_OPEN) {
		// 이 실패도 시도를 센 셀에 귀속함. 형제 분기와 같은 셀이어야 대칭이 맞음
		int cell_index = (ue_record->att_cell_index >= 0) ? ue_record->att_cell_index
									 : ue_record->req_cell_index;
		if (cell_index >= 0) {
			struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
			cell_record->cc_value[TR_METRIC_RRC_CONN_ESTAB_FAIL_CAUSE][FC_OTHER]++;
			cell_record->path_value[TR_METRIC_RRC_CONN_ESTAB_FAIL_CAUSE][ue_record->path]++;
		}
		settle_open_setup(tr, ue_record, SR_OTHER);
	}
}

/* close_setup_complete_unobserved: Msg5 를 못 본 채 연결이 성립했다는 증거만 본 열린 수립 시도를
 *   닫고, 그 사실을 unknown 밴드에 남김.
 *   이유: 부르는 곳 두 군데(F1 의 RRCRelease 관측, N2 의 RRCInactiveTransitionReport 관측)가 보는
 *     메시지는 RRC_CONNECTED 였던 UE 에만 존재함. TS 38.331 §5.3.8 "The network initiates the RRC
 *     connection release procedure to a UE in RRC_CONNECTED", 그리고 N2 보고는 NGAP UE 컨텍스트가
 *     있어야 하고 그 컨텍스트는 INITIAL UE MESSAGE(= Msg5 의 NAS)로만 생김. 즉 Msg5 는 CU 에 닿았음.
 *     그런데 그 Msg5 를 우리가 보지 못했으므로 Succ 본값에 넣을 수 없음. 본값은 와이어로 나가는 합
 *     이고(출력 쪽이 카운터 값을 원인 칸 value 의 합으로 냄), 그 키의 정의가 "칸 안에 받은
 *     RRCSetupComplete 수" 임. 받지 않은 것을 받았다고 세면 확신 있는 오값이고, 판정값을 부풀려
 *     실패를 가림.
 *     거꾸로 마감만 풀고 아무 칸도 올리지 않으면 시도만 서고 결과가 어디에도 없어 신호 없는 드롭이
 *     됨(실측: 시각을 100배 압축해 재생했을 때 수립 시도 6건이 Succ 와 FailCause 와 unknown 어디에도
 *     없었음).
 *     그래서 형제 분기(Complete 를 받았지만 못 읽은 경우)와 같은 unknown 밴드에 셈. unknown 은
 *     와이어에 나가지 않고 JSONL 에만 실려, 판정값은 과장되지 않고 운영자는 관측 구멍을 봄.
 *     값을 담지 않고 담지 않았음을 세는 두 걸음임.
 *   한계: 수립 경로만 셈. 재수립과 재개 폴백 레코드는 그 지표가 지금 측정되지 않아 올릴 칸이 없음.
 *   부작용: 시도를 성공으로 종결함(마감 해제, 반열림 비움). 이미 종결됐으면 아무것도 하지 않음 */
static void close_setup_complete_unobserved(struct tr *tr, struct tr_ue_record *ue_record)
{
	if (ue_record->setup_state != SR_OPEN) return;
	int cell_index = (ue_record->att_cell_index >= 0) ? ue_record->att_cell_index : ue_record->req_cell_index;
	if (ue_record->path == PATH_SETUP && cell_index >= 0) {
		struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
		enum tr_metric metric = TR_METRIC_RRC_CONN_ESTAB_SUCC;
		int cause_index = (ue_record->est_cause >= 0 && ue_record->est_cause < METRIC_CAUSE_CNT[metric])
				? ue_record->est_cause : -1;
		if (cause_index >= 0) cell_record->cc_unknown[metric][cause_index]++;
		else cell_record->cc_unknown_nocause[metric]++;
	}
	settle_open_setup(tr, ue_record, SR_SUCCESS);
}

// ---- 개별 이벤트 처리 ----
/* on_setup_request: RRCSetupRequest 한 건을 RRC.ConnEstabAtt 에 반영하고 새 F1 UE 레코드를 엶.
 *   이유: 이 메시지가 수립 시도의 시작점임. 여기서 연 레코드에 뒤따르는 Msg4, Msg5 의 결과가 붙음.
 *   부작용: 시도 카운터 한 칸 증가(본값 / 제외 / 미상 중 하나), 레코드 초기화, 마감 등록, 표 I 줄 방출 */
static void on_setup_request(struct tr *tr, const struct obs_event *event)
{
	int est_cause = event->payload.setup_request.est_cause;
	int cell_index = cell_lookup(tr, &event->cell, 1);
	if (cell_index < 0) return;                       // 셀 모름 -> 세지 않음(필수 IE 지만 방어)
	struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
	enum tr_metric metric = TR_METRIC_RRC_CONN_ESTAB_ATT;
	// 칸 수는 리터럴로 적지 않고 metrics.h 의 이름표에서 유도한 값을 씀
	int cause_index = (est_cause >= 0 && est_cause < METRIC_CAUSE_CNT[metric]) ? est_cause : -1;

	/* 진행 중 재요청 판정. 마감 안에 같은 단말(연결, 39비트 식별자)이 다시 요청하면 그 요청은 시도로
	 *   세지 않고 제외 칸에 넣음.
	 *   선행 레코드를 강제로 종결하지 않는 이유: F1 단말은 각자 자기 결과로만 닫힘. 제외한 재요청의
	 *     수립도 결과 하나를 받으므로, 두 F1 단말이 모두 Complete 면 성공은 2 임. 강제 종결하면 선행의
	 *     완료가 진단 칸으로 새고, 마감으로 서야 할 NoReply 도 사라짐.
	 *   시도와 성공의 합이 어긋날 수 있는 것은 설계 의도임 - 소프트 불변식(inv_soft_succ_le_att)이
	 *     합법적으로 경고할 수 있고 그것은 결함이 아님. 같은 du_ue_id 재사용은 아래 open_list_remove 가 막음 */
	struct sx_key sx_key_probe = { event->assoc_id, event->payload.setup_request.ue_identity39 };
	uint64_t setup_hash = sx_hash(event->assoc_id, event->payload.setup_request.ue_identity39);
	uint32_t prev = hash_map_get(&tr->setup_idx, setup_hash, sx_eq, tr, &sx_key_probe);
	int ongoing = 0;
	if (prev != UINT32_MAX) {
		struct tr_ue_record *prev_ue_record = &tr->ue_records[prev];
		if (prev_ue_record->setup_state == SR_OPEN && event->wallclock_ns < prev_ue_record->deadline_ns)
			ongoing = 1;
	}
	enum overload_decision overload_decision = decide_overload(tr, cause_index >= 0 ? cause_index : 0);

	if (cause_index < 0) {
		// establishmentCause 는 필수라 보통 없음 - 방어적으로 원인 없는 미상에 넣음
		cell_record->cc_unknown_nocause[metric]++;
	} else if (ongoing) {
		cell_record->cc_excluded[metric][TR_EXCLUDED_ONGOING_SETUP][cause_index]++;
		if (overload_decision == OVERLOAD_EXCLUDE)
			cell_record->cc_overlap[metric][cause_index][TR_OVERLAP_ONGOING_AND_OVL_EXCL]++;
		else if (overload_decision == OVERLOAD_UNKNOWN)
			cell_record->cc_overlap[metric][cause_index][TR_OVERLAP_ONGOING_AND_OVL_UNKNOWN]++;
	} else if (overload_decision == OVERLOAD_EXCLUDE) {
		cell_record->cc_excluded[metric][TR_EXCLUDED_AMF_OVERLOAD][cause_index]++;
	} else if (overload_decision == OVERLOAD_UNKNOWN) {
		cell_record->cc_unknown[metric][cause_index]++;
	} else {
		cell_record->cc_value[metric][cause_index]++;   // 요청은 평문이라 inferred 는 늘 0 임
	}

	// 새 F1 UE 레코드. 요청마다 새 du_ue_id 가 옴
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (!ue_record) return;
	/* 게이지 소속과 세션 플래그를 여기서 전부 비움.
	 *   이유: ue_lookup 은 같은 du_ue_id 가 다시 오면 memset 없이 기존 레코드를 돌려줌. 수립 요청은
	 *     연결의 첫 메시지이므로 이 레코드는 '어느 게이지에도 없고 세션 플래그가 0' 인 상태여야 함.
	 *     정상 재사용은 libobs 가 du_ue_id 재사용마다 교체, 축출, 연결 종료 이벤트를 먼저 내 주어
	 *     ue_record_free 가 거르므로 지금 동작은 바뀌지 않음. 그 발행에 의존하지 않고 요청 경계에서
	 *     못박아 libobs 가 바뀌어도 게이지 정합성이 유지되게 함.
	 *     비우지 않으면 남아 있던 in_conn 이 gauge_enter_conn 의 가드에 막혀 신규 연결이 누락되고 옛
	 *     셀이 누수됨 - 상시 계수되는 ConnMean, ConnMax 가 손상되므로 INACTIVE 지표가 늘 0 인 것보다
	 *     영향이 큼. 진행 중 재전송은 이 필드가 전부 0 이라 무영향이고 신규 레코드는 memset 으로 0 임 */
	open_list_remove(tr, ue_record);
	gauge_leave_conn(tr, ue_record);
	gauge_leave_inactive(tr, ue_record);
	half_open_leave(tr, ue_record);
	ue_record->est_cell_index = -1;
	ue_record->has_n2_pair = 0;
	ue_record->n2_released = 0;
	ue_record->suspend_resolved = 0;
	ue_record->rel_had_container = 0;
	ue_record->rel_inferred = 0;
	ue_record->conn_inferred = 0;
	ue_record->path = PATH_SETUP;
	ue_record->setup_state = SR_OPEN;
	ue_record->est_cause = est_cause;
	ue_record->req_cell_index = cell_index;
	ue_record->att_cell_index = cell_index;   // 시도를 센 셀. 뒤에 셀이 바뀌어도 이 칸은 두어 결과를 같은 셀에 귀속함
	// RRCSetupRequest 는 새 RRC 연결의 보안 전 CCCH 평문이므로 AS 보안은 NONE 이고 등급은 정확임
	ue_record->rrc_sec_state = TR_SEC_NONE;
	ue_record->rrc_sec_quality = TR_QUALITY_EXACT;
	ue_record->request_time_ns = event->wallclock_ns;
	ue_record->saw_setup_sent = 0;
	ue_record->ue_identity39 = event->payload.setup_request.ue_identity39;
	setup_recompute_deadline(tr, ue_record);
	open_list_add(tr, ue_record);
	// 제외한 재요청도 '가장 최근' 이 되어 마감을 뒤로 밀도록 색인을 갱신함
	hash_map_put(&tr->setup_idx, setup_hash, sx_eq, tr, &sx_key_probe,
		     (uint32_t)(ue_record - tr->ue_records));

	// 표 I: C-RNTI, S-TMSI 앞부분, RRC 상태, 마지막 RRC 메시지
	uint32_t changed_mask = 0;
	if (event->payload.setup_request.crnti) {
		ue_record->crnti = event->payload.setup_request.crnti;
		ue_record->has_crnti = 1;
		changed_mask |= TR_UE_F_CRNTI;
	}
	/* 앞부분만 온 경우 48비트 S-TMSI 는 아직 조립 전이고 앞부분 자체는 출력 계약에 없음. 그래서
	 * stmsi 변경 비트를 켜지 않음 - 값 없는 변경은 허위 신호임. 그 비트는 뒷부분이 와서 실제 48비트가
	 * 생기는 on_setup_complete 에서 켜짐. 내부 추적 칸은 조립용으로 유지함 */
	if (event->payload.setup_request.ue_identity_type == TR_UE_IDENTITY_STMSI_PART1) {
		ue_record->stmsi_part1 = event->payload.setup_request.ue_identity39;
		ue_record->has_stmsi_part1 = 1;
	}
	ue_record->rrc_state = RS_IDLE_PENDING;
	changed_mask |= TR_UE_F_RRC_STATE;
	changed_mask |= TR_UE_F_RRC_MSG;   // 마지막 RRC 메시지 값은 emit_ue_line 이 이벤트에서 직접 채움
	emit_ue_line(tr, ue_record, event, changed_mask, 0);
}

/* on_rrc_setup: RRCSetup(Msg4) 송신을 레코드에 표시하고 반쯤 열린 연결 창을 시작함.
 *   이유: 이 시점부터 Msg5 를 기다리므로 마감을 다시 계산해야 하고, 그 창 동안의 연결은 상한에만
 *     기여해야 함.
 *   부작용: 마감 재계산, 폴백 경로면 마감 등록, 게이지 이동 */
static void on_rrc_setup(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (!ue_record) return;
	/* 선행 요청이 무엇이었는지로 경로를 가름. 이미 폴백 경로가 잡혀 있으면 수립으로 끌어내리지 않음 -
	 * 요청이 먼저 경로를 기록했다면 그 귀속을 보존함.
	 * default 를 두지 않음: enum 에 값이 하나 늘면 -Wswitch 가 빌드를 깨 이 곳을 같이 고치게 함 */
	switch (event->payload.setup.prior_req) {
	case TR_PRIOR_REEST_FALLBACK:
		ue_record->path = PATH_REEST_FALLBACK;
		break;
	case TR_PRIOR_RESUME_FALLBACK:
		ue_record->path = PATH_RESUME_FALLBACK;
		break;
	case TR_PRIOR_SETUP:
	case TR_PRIOR_OTHER_OR_UNREADABLE:
		if (ue_record->path != PATH_REEST_FALLBACK && ue_record->path != PATH_RESUME_FALLBACK)
			ue_record->path = PATH_SETUP;
		break;
	}
	/* 여기서 마감을 다시 등록하는 것은 폴백 경로뿐임.
	 *   종결된 수립은 되살리지 않음: 중복, 재전송 RRCSetup 으로 되살리면 뒤이은 RRCSetupComplete 가
	 *     성공을 한 번 더 세어 성공이 시도를 넘김(재현됨). 정상 수립은 요청에서 이미 열리고 등록됐고
	 *     du_ue_id 재사용도 요청 핸들러가 다시 열므로 여기서 재개할 일이 없음.
	 *   폴백은 요청 핸들러가 열기만 하고 마감을 걸지 않아, RRCSetupComplete 가 없을 때 정상 수립과
	 *     대칭으로 NoReply 를 내려면 폴백 RRCSetup 을 본 지금 걸어야 함. 요청을 못 본 경우(경로가 수립)는
	 *     걸지 않음 - 시도 없는 NoReply 가 늘어남.
	 *   폴백의 모든 종결 경로가 마감 목록에서 빼므로 허위 NoReply 가 없고, 순수 재수립, 재개 성공은
	 *     이 핸들러에 오지 않음. open_list_add 는 멱등이라 중복 RRCSetup 도 안전함 */
	if (ue_record->setup_state == SR_OPEN
	    && (ue_record->path == PATH_REEST_FALLBACK || ue_record->path == PATH_RESUME_FALLBACK))
		open_list_add(tr, ue_record);
	if (ue_record->req_cell_index < 0 && event->cell.valid)
		ue_record->req_cell_index = cell_lookup(tr, &event->cell, 1);
	ue_record->saw_setup_sent = 1;
	ue_record->setup_sent_time_ns = event->wallclock_ns;
	setup_recompute_deadline(tr, ue_record);
	/* 반쯤 열린 창에 들어가기 전에 다른 게이지를 비움.
	 *   INACTIVE 단말이 요청 유실로 RRCSetup 부터 관측되면 반쯤 열림과 INACTIVE 가 공존해 그 창 동안
	 *   표본이 두 번 세어짐. 이미 연결 중인 단말에 재전송, 주입 RRCSetup 이 와도 같은 일이 생겨
	 *   ConnMax, ConnMean 의 상한이 2 로 불어남. 정상 재연결이면 옛 연결을 대체하는 것이 맞고 멱등이며,
	 *   정상 신규 경로에서는 둘 다 아무것도 하지 않음. 형제 on_setup_request 는 세 게이지를 전부 비움 */
	gauge_leave_conn(tr, ue_record);
	gauge_leave_inactive(tr, ue_record);
	half_open_enter(tr, ue_record, ue_record->req_cell_index);
}

/* on_setup_complete: RRCSetupComplete(Msg5) 한 건을 RRC.ConnEstabSucc 와 경로 칸에 반영하고 연결
 *   게이지에 넣음.
 *   이유: 이 메시지를 받은 것이 수립 성공의 정의임(TS 28.552 §5.1.1.15.2 c).
 *   부작용: 성공 카운터 또는 경로 칸 증가, 수립 종결, 게이지 진입, 표 I 줄 방출 */
static void on_setup_complete(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	if (!ue_record || ue_record->req_cell_index < 0) return;   // 요청을 못 봐 셀을 모름 -> 세지 않음
	// 카운터는 시도를 센 셀에 귀속하고, 게이지는 현재 셀을 씀(전사와 SpCell 변경을 반영)
	int cell_index = (ue_record->att_cell_index >= 0) ? ue_record->att_cell_index
							 : ue_record->req_cell_index;
	struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
	enum tr_metric metric = TR_METRIC_RRC_CONN_ESTAB_SUCC;
	int cause_index = (ue_record->est_cause >= 0 && ue_record->est_cause < METRIC_CAUSE_CNT[metric])
			? ue_record->est_cause : -1;

	/* 미상 등급 분기에도 '열린 수립' 가드를 둠. 이미 종결된 시도에 늦게 온 미상 Complete 를 성공으로
	 * 세면 한 시도가 실패와 성공에 동시에 들어감. 종결된 것은 아래 else 로 떨어져 진단 칸만 올림 -
	 * 종결된 정확 등급과 같은 처분임. 형제 on_reest_complete, on_resume_complete 는 이미 이 가드를 가짐 */
	if (event->quality == TR_QUALITY_UNKNOWN && ue_record->setup_state == SR_OPEN) {
		// 망 공유로 Complete 자체를 보지 못하고 추정한 경우 -> 원인별 미상
		if (cause_index >= 0) cell_record->cc_unknown[metric][cause_index]++;
		else cell_record->cc_unknown_nocause[metric]++;
	} else if (ue_record->setup_state == SR_OPEN && ue_record->path == PATH_SETUP) {
		/* 본값과 경로 칸을 같이 올림.
		 *   이 지표는 수립 경로만 원인 칸을 같이 올림. 나머지 경로 칸은 원인 칸을 올리지 않는 성공을
		 *   따로 세므로 경로 칸의 합과 본값이 같지 않음 - 소비자는 둘을 더하면 안 됨.
		 *   ConnEstabFailCause 는 반대로 모든 경로가 원인 칸을 올려 두 합이 같음.
		 *   실측: RRCSetupComplete 6건 = 수립 5 + 재수립 폴백 1 이고 본값은 5 임. 6번째는 요청을
		 *   뒤따르지 않아 TS 28.552 §5.1.1.15.2 c) "Receipt by the gNB of an RRCSetupComplete message
		 *   following a RRC connection setup request" 밖이고 수립 원인도 없음 */
		if (cause_index >= 0) {
			cell_record->cc_value[metric][cause_index]++;
			cell_record->path_value[metric][PATH_SETUP]++;
			/* 구조, 교차 추론으로 얻은 성공은 inferred 밴드로 보냄(exact = 본값 - inferred).
			 * 지금 libobs 는 Complete 를 늘 정확으로 주어 이 분기는 실행되지 않지만, 집계 층은 어떤
			 * 등급이 와도 정직하게 갈라야 함. 형제 on_reest_complete, on_resume_complete 와 같은 모양임 */
			if (event->quality == TR_QUALITY_STRUCT || event->quality == TR_QUALITY_CROSS)
				cell_record->cc_inferred[metric][cause_index]++;
		}
		else cell_record->cc_unknown_nocause[metric]++;
	} else if (ue_record->setup_state == SR_OPEN && ue_record->path == PATH_REEST_FALLBACK) {
		cell_record->path_value[metric][PATH_REEST_FALLBACK]++;
	} else if (ue_record->setup_state == SR_OPEN && ue_record->path == PATH_RESUME_FALLBACK) {
		cell_record->path_value[metric][PATH_RESUME_FALLBACK]++;
	} else if ((ue_record->setup_state == SR_NOREPLY || ue_record->setup_state == SR_UNKNOWN)
		   && event->quality != TR_QUALITY_UNKNOWN) {
		/* 마감이 지난 뒤 도착한 Msg5. 처분은 늦게 온 Msg5 도 성공으로 세고 이미 센 NoReply 는 그대로
		 *   두는 것임. TS 28.552 §5.1.1.15.2 c) 가 "Each RRCSetupComplete message received is added to
		 *   the relevant per establishment cause measurement" 라고 적어 받은 것마다 세라고 함.
		 *   두 값이 같이 서는 것이 모순이 아님 - NoReply 는 "마감 안에 답이 없었다", 성공은 "Msg5 를
		 *   받았다" 로 서로 다른 사실이고, 그 시차는 읽는 쪽이 맞춤.
		 *   종전에는 진단 칸만 올려 끝냈고 그 칸은 검산식과 와이어 둘 다에 없어서, 실제로 받은
		 *   Complete 11건이 성공 0 으로 나갔음(같은 고정물에서 PDU 간격 300 ms 는 11, 1100 ms 는 0).
		 *   미상 등급을 이 갈래에서 뺀 이유: 그 등급은 Msg5 를 실제로 보지 못하고 망 공유 정보로
		 *   추정한 것이라 "받았다" 가 성립하지 않음. 그 경우는 아래 else 로 떨어져 진단 칸만 올림 */
		cell_record->path_value[metric][PATH_LATE_COMPLETE]++;
		if (cause_index >= 0) {
			cell_record->cc_value[metric][cause_index]++;
			if (event->quality == TR_QUALITY_STRUCT || event->quality == TR_QUALITY_CROSS)
				cell_record->cc_inferred[metric][cause_index]++;
		} else {
			cell_record->cc_unknown_nocause[metric]++;
		}
	} else {
		cell_record->path_value[metric][PATH_OTHER]++;   // 이미 성공으로 닫힘(중복 Complete) 등
	}
	settle_open_setup(tr, ue_record, SR_SUCCESS);

	/* 연결 게이지 진입. 그 전에 INACTIVE 를 비움 - 요청을 못 봐 on_setup_request 의 비우기를 건너뛴
	 * INACTIVE 단말이 Complete 로 연결에 들어오면 한 단말이 두 게이지에 동시 계수되어 상시 계수되는
	 * ConnMean, ConnMax 가 과대해짐. 정상 경로는 아무것도 하지 않음. 형제 재수립, 재개 완료와 대칭임 */
	gauge_leave_inactive(tr, ue_record);
	half_open_leave(tr, ue_record);
	int level = (event->quality == TR_QUALITY_EXACT) ? LV_EXACT
			: (event->quality == TR_QUALITY_UNKNOWN ? LV_UNKNOWN : LV_INFERRED);
	gauge_enter_conn(tr, ue_record, ue_record->req_cell_index, level);
	ue_record->est_cell_index = ue_record->req_cell_index;   // 수립이 끝난 셀. 해제 계수가 이 칸을 씀

	// 표 I: S-TMSI 조립, RRC CONNECTED
	uint32_t changed_mask = 0;
	if (event->payload.setup_complete.has_stmsi48) {
		ue_record->stmsi48 = event->payload.setup_complete.stmsi48;
		ue_record->has_stmsi48 = 1;
		changed_mask |= TR_UE_F_STMSI;
	}
	else if (event->payload.setup_complete.has_stmsi_part2 && ue_record->has_stmsi_part1) {
		ue_record->stmsi48 = ((uint64_t)event->payload.setup_complete.stmsi_part2 << 39)
				   | (ue_record->stmsi_part1 & 0x7FFFFFFFFFull);
		ue_record->has_stmsi48 = 1;
		changed_mask |= TR_UE_F_STMSI;
	}
	ue_record->rrc_state = RS_CONNECTED;   // RRCSetupComplete 는 평문 직접 관측이라 등급은 정확임
	ue_record->conn_inferred = 0;
	changed_mask |= TR_UE_F_RRC_STATE;
	changed_mask |= TR_UE_F_RRC_MSG;   // 마지막 RRC 메시지 값은 emit_ue_line 이 이벤트에서 직접 채움
	// 초기 5GMM 상태. RRCSetupComplete 가 실어 온 초기 NAS 는 AS 보안 전 평문임. 연결모드는 AMF 응답 전이라 IDLE
	int nas_msg_type = event->payload.setup_complete.nas.msg_type,
	    nas_reg_type = event->payload.setup_complete.nas.reg_type;
	if (nas_msg_type == NAS_MM_REGISTRATION_REQUEST) {
		/* 등록 유형을 못 읽었으면 주상태를 단정하지 않음. 종전엔 -1 이 삼항의 거짓 가지로 떨어져
		 * DEREGISTERED 가 정확 등급으로 나갔음 - 안 읽은 것을 '읽어서 initial 이었음' 과 같은 모양으로
		 * 내보내는 확신 있는 오값임. 메시지 종류는 읽었으므로 연결모드는 그대로 둠.
		 * 등록 유형에 '범위 밖' 은 없음(TS 24.501 §9.11.3.7: 쓰이지 않는 값도 initial registration 으로
		 * 해석) -> 0 이상이면 전부 단정 가능하고, 이 분기는 '안 읽음' 하나만 가름 */
		bool reg_type_read = nas_reg_type >= 0;
		ue_record->nas_reg_state = !reg_type_read ? TR_5GMM_UNKNOWN
			: ((nas_reg_type == NAS_REG_MOBILITY || nas_reg_type == NAS_REG_PERIODIC
			    || nas_reg_type == NAS_REG_DISASTER_MOBILITY) ? TR_5GMM_REGISTERED
									 : TR_5GMM_DEREGISTERED);
		ue_record->nas_conn_mode = TR_CM_MODE_IDLE;
		/* 등급은 '무엇을 근거로 그 상태를 적었나' 임. 못 읽어서 미상이면 근거가 없으므로 판정 불가임.
		 * 구조 등급을 달면 읽는 쪽이 '절차 흐름으로 판정했음' 으로 읽음 */
		ue_record->nas_state_quality = reg_type_read ? TR_QUALITY_EXACT : TR_QUALITY_UNKNOWN;
		changed_mask |= TR_UE_F_NAS_STATE;
	} else if (nas_msg_type == NAS_MM_SERVICE_REQUEST || nas_msg_type == NAS_MM_CP_SERVICE_REQUEST) {
		/* TS 24.501 §4.4.6 이 초기 NAS 로 꼽는 셋 중 둘임. CONTROL PLANE SERVICE REQUEST 도
		 * 5GMM-REGISTERED 단말만 보냄(§5.6.1.1) */
		ue_record->nas_reg_state = TR_5GMM_REGISTERED;
		ue_record->nas_conn_mode = TR_CM_MODE_IDLE;
		ue_record->nas_state_quality = TR_QUALITY_EXACT;
		changed_mask |= TR_UE_F_NAS_STATE;
	}
	emit_ue_line(tr, ue_record, event, changed_mask, 0);
}

/* on_reject: RRCReject 를 ConnEstabFailCause[NetworkReject] 로 세고 수립을 닫음.
 *   부작용: 실패 원인 카운터와 경로 칸 증가, 수립 종결. 열린 수립이 아니면 아무것도 하지 않음 */
static void on_reject(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	// 실패 원인도 시도를 센 셀에 귀속함. SpCell 이 바뀐 뒤에도 같은 셀이어야 성공 쪽과 대칭이 맞음
	int cell_index = ue_record ? ((ue_record->att_cell_index >= 0) ? ue_record->att_cell_index
								: ue_record->req_cell_index) : -1;
	if (cell_index < 0) return;                             // 요청 셀 모름 -> 세지 않음
	struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
	int path = PATH_OTHER;
	/* 선행 요청이 무엇이었는지로 경로 칸을 가름. 읽지 못한 경우도 한 칸을 받음.
	 * default 를 두지 않음: enum 에 값이 하나 늘면 -Wswitch 가 빌드를 깨 이 곳을 같이 고치게 함.
	 * default 가 있으면 새 값이 조용히 PATH_OTHER 로 섞여 들어감 */
	switch (event->payload.reject.prior_req) {
	case TR_PRIOR_SETUP:
		path = PATH_SETUP;
		break;
	case TR_PRIOR_REEST_FALLBACK:
		path = PATH_REEST_FALLBACK;
		break;
	case TR_PRIOR_RESUME_FALLBACK:
		path = PATH_RESUME_FALLBACK;
		break;
	case TR_PRIOR_OTHER_OR_UNREADABLE:
		path = PATH_OTHER;
		break;
	}
	/* 계수를 '열린 수립' 가드 안에서 함. 종전엔 가드 밖이라 중복, 재전송 RRCReject 가 같은 원인을
	 * 다시 세거나 이미 성공한 단말을 실패로도 셌음. 형제 실패 원인 생산자는 모두 이 가드를 먼저 함 */
	if (ue_record->setup_state == SR_OPEN) {
		cell_record->cc_value[TR_METRIC_RRC_CONN_ESTAB_FAIL_CAUSE][FC_NETWORK_REJECT]++;
		cell_record->path_value[TR_METRIC_RRC_CONN_ESTAB_FAIL_CAUSE][path]++;
		gauge_leave_inactive(tr, ue_record);   // 폴백으로 다시 열린 INACTIVE 누수 방지(멱등)
		settle_open_setup(tr, ue_record, SR_NETWORK_REJECT);
	}
}

/* on_reest_request: RRCReestablishmentRequest 를 RRC.ReEstabAtt 에 세고 폴백 경로를 표시함.
 *   이 요청은 SRB0 평문이라 늘 정확하고 제외 칸이 없음 */
static void on_reest_request(struct tr *tr, const struct obs_event *event)
{
	int cell_index = cell_lookup(tr, &event->cell, 1);
	if (cell_index < 0) return;
	tr->cell_records[cell_index].cc_value[TR_METRIC_RRC_REESTAB_ATT][0]++;
	// 폴백 경로를 위해 레코드에 경로와 셀을 심음
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (ue_record) {
		ue_record->path = PATH_REEST_FALLBACK;
		ue_record->setup_state = SR_OPEN;
		ue_record->req_cell_index = cell_index;
		ue_record->att_cell_index = cell_index;   // 시도를 센 셀
		ue_record->request_time_ns = event->wallclock_ns;
		ue_record->est_cause = -1;
		ue_record->rrc_state = RS_IDLE_PENDING;
		ue_record->reest_succ_counted = 0;   // 새 재수립 주기 시작이므로 성공 계수 플래그를 리셋함
	}
	// 재수립 요청도 RRC 메시지이므로 마지막 RRC 메시지 변경 비트를 켬(형제 on_setup_request 와 대칭)
	if (ue_record) emit_ue_line(tr, ue_record, event, TR_UE_F_RRC_STATE | TR_UE_F_RRC_MSG, 0);
}

/* on_reest: RRCReestablishment(허가, DL)를 보고 ReEstabSuccWithUeContext 를 inferred 로 세고 연결
 *   게이지에 넣음.
 *   이유: 허가는 평문(TS 38.331 §5.3.7.4, 무결성만)이라 관측 가능한 '컨텍스트 있는 재수립 허가' 임.
 *     완료는 암호라 가시성 관문에서 막히므로 완료에서는 셀 수 없음. 허가 자체는 평문 정확 디코드지만
 *     지표의 뜻이 '완료' 이므로 완료는 추론이고, 그래서 정직하게 inferred 에 넣음. 실제로 이 지표는
 *     늘 inferred 밴드이고 exact 는 0 에 가까움 - 소비자는 exact = 본값 - inferred 로 읽어야 함.
 *   가드: 이미 실패나 미상으로 종결된 시도에 재전송, 재정렬된 허가가 와도 성공을 덧세지 않음.
 *     다만 정상 재수립은 허가 '전에' 연결 이전(on_ue_transfer)이 성공으로 올리므로 성공 상태도
 *     허용해야 함 - 열린 상태만 허용하면 정상 허가가 전부 막혀 이 지표가 다시 0 이 됨(실측).
 *     경로가 재수립 폴백인 것도 요구함: 성공 상태를 출처 불문 허용하면 수립이나 재개로 성공한
 *     레코드에 요청 없는 허가가 와도 이 지표를 세어 성공이 시도를 넘김(재현됨). 요청을 못 본
 *     중간 합류는 시도도 0 이라 세지 않는 쪽이 일관됨.
 *   부작용: 성공 카운터와 inferred 증가, 수립 종결, 게이지 이동, RRC 상태를 CONNECTED 로 */
static void on_reest(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (!ue_record) return;
	ue_record->wait_reest = 1;
	if (ue_record->req_cell_index < 0 || ue_record->reest_succ_counted
	    || ue_record->path != PATH_REEST_FALLBACK
	    || (ue_record->setup_state != SR_OPEN && ue_record->setup_state != SR_SUCCESS)) return;
	// 시도를 센 셀에 귀속함. 전사로 현재 셀이 옮겨가도 성공이 시도를 넘지 않게 하려는 것임
	int cell_index = (ue_record->att_cell_index >= 0) ? ue_record->att_cell_index
							 : ue_record->req_cell_index;
	struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
	enum tr_metric metric = TR_METRIC_RRC_REESTAB_SUCC_WITH_CTX;
	cell_record->cc_value[metric][0]++;   // 본값과 inferred 를 같이 올려 exact 기여는 0 이 됨
	cell_record->cc_inferred[metric][0]++;
	ue_record->reest_succ_counted = 1;
	// 연결 이전이 이미 성공으로 올렸으면 아무것도 하지 않음. 폴백으로 마감이 걸려 있었으면 해제함
	if (ue_record->setup_state == SR_OPEN) {
		ue_record->setup_state = SR_SUCCESS;
		open_list_remove(tr, ue_record);
	}
	gauge_leave_inactive(tr, ue_record);   // INACTIVE 였다면 연결 진입 전에 비움(이중 계수 방지)
	half_open_leave(tr, ue_record);
	gauge_enter_conn(tr, ue_record, ue_record->req_cell_index, LV_INFERRED);   // 완료 미관측이라 추론 진입
	ue_record->rrc_state = RS_CONNECTED;
	ue_record->conn_inferred = 1;   // 허가로 추론한 CONNECTED 이므로 등급은 구조 추론임
}

/* on_reest_complete: RRCReestablishmentComplete 를 본 경우의 폴백 계수.
 *   이유: 실가동에서는 이 완료가 암호라 늘 불가독이므로, 이 핸들러는 허가를 못 본 경로(합성, 전면
 *     가시성)용임.
 *   계수 규칙: 허가가 이미 inferred 로 셌으면 다시 세지 않음. 종전의 inferred -> exact 승격은 셀
 *     단위라 주기 경계에서 다른 단말의 추론분을 깎아 엉뚱한 단말을 exact 로 표기했음(재현됨). 게다가
 *     완료 가독은 실가동에서 도달 불가이므로 승격을 없애고 정직하게 inferred 를 유지함.
 *     실패나 미상으로 종결된 시도는 세지 않음. 성공 상태를 허용하는 이유와 경로를 요구하는 이유는
 *     on_reest 와 같음.
 *   부작용: 성공 카운터 증가, 수립 종결, 게이지 이동, RRC 상태를 CONNECTED 로 */
static void on_reest_complete(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	if (!ue_record || ue_record->req_cell_index < 0) return;
	int cell_index = (ue_record->att_cell_index >= 0) ? ue_record->att_cell_index
							 : ue_record->req_cell_index;
	struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
	enum tr_metric metric = TR_METRIC_RRC_REESTAB_SUCC_WITH_CTX;
	if (!ue_record->reest_succ_counted && ue_record->path == PATH_REEST_FALLBACK
	    && (ue_record->setup_state == SR_OPEN || ue_record->setup_state == SR_SUCCESS)) {
		if (event->quality == TR_QUALITY_UNKNOWN) cell_record->cc_unknown[metric][0]++;
		else {
			cell_record->cc_value[metric][0]++;
			if (event->quality == TR_QUALITY_STRUCT || event->quality == TR_QUALITY_CROSS)
				cell_record->cc_inferred[metric][0]++;
		}
		ue_record->reest_succ_counted = 1;
	}
	ue_record->wait_reest = 0;
	// 실패로 종결된 뒤면 게이지와 상태를 건드리지 않음(종결된 레코드를 되살리지 않음)
	if (ue_record->setup_state != SR_OPEN && ue_record->setup_state != SR_SUCCESS) return;
	settle_open_setup(tr, ue_record, SR_SUCCESS);
	/* 게이지 진입. 정상 경로는 연결 이전에서 이미 들어가 있어 멱등으로 아무 일도 없고, 허가가 먼저
	 * 추론 밴드로 들어갔으면 그대로 둠. 이전을 못 본 경우에만 실제로 진입함 */
	gauge_leave_inactive(tr, ue_record);
	half_open_leave(tr, ue_record);
	{
		int level = (event->quality == TR_QUALITY_EXACT) ? LV_EXACT
				: (event->quality == TR_QUALITY_UNKNOWN ? LV_UNKNOWN : LV_INFERRED);
		gauge_enter_conn(tr, ue_record, ue_record->req_cell_index, level);
	}
	ue_record->rrc_state = RS_CONNECTED;
	ue_record->conn_inferred = (event->quality != TR_QUALITY_EXACT);   // 평문 완료 관측이면 정확, 추론이면 구조
}

/* on_initial_ul: INITIAL UL RRC MESSAGE TRANSFER 한 건을 UE 컨텍스트 게이지와 두 계수기에 반영함.
 *   이유: 이 세 값은 메시지 안의 RRC 가 무엇인지, 풀렸는지와 무관하게 '메시지마다 1' 임. RRC
 *     핸들러에 얹으면 디코드 실패분이 빠져 과소가 됨.
 *   부작용: UE 컨텍스트 게이지 진입(멱등), 최대값, 메시지 수, DU-to-CU 컨테이너 없는 수 갱신 */
static void on_initial_ul(struct tr *tr, const struct obs_event *event)
{
	int cell_index = cell_lookup(tr, &event->cell, 1);
	if (cell_index < 0) return;   // 셀 모름 -> 세지 않음(필수 IE 지만 방어, on_setup_request 와 대칭)
	struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
	cell_record->initial_ul_count++;
	if (!event->payload.initial_ul.has_du_to_cu_rrc_container) cell_record->no_du_to_cu_count++;
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (ue_record) ue_context_enter(tr, ue_record, cell_index);
}

// on_resume_request: RRCResumeRequest 를 RRC.ResumeAtt 에 세고 재개 폴백 경로를 표시함
static void on_resume_request(struct tr *tr, const struct obs_event *event)
{
	int cell_index = cell_lookup(tr, &event->cell, 1);
	if (cell_index < 0) return;
	int resume_cause = event->payload.resume_request.resume_cause;
	// 칸 수는 리터럴로 적지 않고 metrics.h 의 이름표에서 유도한 값을 씀
	int cause_index = (resume_cause >= 0
			   && resume_cause < METRIC_CAUSE_CNT[TR_METRIC_RRC_RESUME_ATT]) ? resume_cause : -1;
	if (cause_index >= 0)
		tr->cell_records[cell_index].cc_value[TR_METRIC_RRC_RESUME_ATT][cause_index]++;
	else tr->cell_records[cell_index].cc_unknown_nocause[TR_METRIC_RRC_RESUME_ATT]++;
	/* 'INACTIVE 를 쓰지 않는 망' 이라는 전제가 깨졌음을 알리는 증거 하나.
	 *   재개 요청은 저장된 INACTIVE 컨텍스트가 있다는 뜻이고 이 신호는 암호 구간에서도 평문임. 그래서
	 *   그 전제를 켠 배치에서 재개 요청이 보이면 전제가 깨진 것임.
	 *   종전엔 증거 셋 중 평문 suspendConfig 하나만 경보를 올려, 재개 요청만 보이는 배치에서는 전제
	 *   위반을 알리지 않고 해제 쪽 구조 추론을 계속 적용했음 - 조용한 오값임 */
	if (tr->tr_cfg.assume_no_inactive) tr->inactive_alarm_count++;
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (ue_record) {
		ue_record->path = PATH_RESUME_FALLBACK;
		ue_record->setup_state = SR_OPEN;
		ue_record->req_cell_index = cell_index;
		ue_record->att_cell_index = cell_index;   // 시도를 센 셀
		ue_record->resume_cause_pending = resume_cause;
		ue_record->rrc_state = RS_IDLE_PENDING;
		ue_record->resume_succ_counted = 0;   // 새 재개 주기 시작이므로 성공 계수 플래그를 리셋함
	}
}

/* on_resume_complete: RRCResumeComplete 를 RRC.ResumeSucc 에 세고 INACTIVE 에서 연결로 옮김.
 *   원인은 평문 SRB0 요청에서 알려지므로 완료가 암호여서 등급이 미상이어도 원인별 미상 칸에 셈.
 *     원인 자체를 모를 때(요청 미관측)만 원인 없는 미상으로 감. 종전엔 미상 등급을 원인 미상과 묶어
 *     원인이 알려진 재개까지 원인 없는 칸으로 흘려 원인별 미상이 항상 0 이었음.
 *   가드 셋: 중복 완료 이중 계수 금지, 경로가 재개 폴백일 것, 실패나 미상으로 종결된 시도에 성공을
 *     덧세지 않을 것. 성공 상태를 허용하는 이유는 on_reest 와 같음. 종전엔 셀 색인만 검사해 중복,
 *     실패 뒤, 엉뚱한 완료가 전부 계수됐음.
 *   부작용: 성공 카운터 증가, 수립 종결, 게이지 이동, RRC 상태를 CONNECTED 로 */
static void on_resume_complete(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	if (!ue_record || ue_record->req_cell_index < 0) return;
	int cell_index = (ue_record->att_cell_index >= 0) ? ue_record->att_cell_index
							 : ue_record->req_cell_index;
	struct tr_cell_record *cell_record = &tr->cell_records[cell_index];
	enum tr_metric metric = TR_METRIC_RRC_RESUME_SUCC;
	int resume_cause_pending = ue_record->resume_cause_pending;
	int cause_index = (resume_cause_pending >= 0
			   && resume_cause_pending < METRIC_CAUSE_CNT[metric]) ? resume_cause_pending : -1;
	if (!ue_record->resume_succ_counted && ue_record->path == PATH_RESUME_FALLBACK
	    && (ue_record->setup_state == SR_OPEN || ue_record->setup_state == SR_SUCCESS)) {
		if (cause_index < 0) cell_record->cc_unknown_nocause[metric]++;
		else if (event->quality == TR_QUALITY_UNKNOWN)
			cell_record->cc_unknown[metric][cause_index]++;
		else {
			cell_record->cc_value[metric][cause_index]++;
			if (event->quality == TR_QUALITY_STRUCT || event->quality == TR_QUALITY_CROSS)
				cell_record->cc_inferred[metric][cause_index]++;
		}
		ue_record->resume_succ_counted = 1;
	}
	// 실패로 종결된 뒤면 게이지와 상태를 건드리지 않음(형제 on_reest_complete 와 대칭)
	if (ue_record->setup_state != SR_OPEN && ue_record->setup_state != SR_SUCCESS) return;
	settle_open_setup(tr, ue_record, SR_SUCCESS);
	// INACTIVE 게이지에서 빼고 연결 게이지로 옮김
	gauge_leave_inactive(tr, ue_record);
	half_open_leave(tr, ue_record);
	int level = (event->quality == TR_QUALITY_EXACT) ? LV_EXACT
			: (event->quality == TR_QUALITY_UNKNOWN ? LV_UNKNOWN : LV_INFERRED);
	gauge_enter_conn(tr, ue_record, ue_record->req_cell_index, level);
	ue_record->rrc_state = RS_CONNECTED;
	ue_record->conn_inferred = (event->quality != TR_QUALITY_EXACT);   // 평문 완료 관측이면 정확, 추론이면 구조
}

/* on_release: 평문 RRCRelease 를 보고 RRC.RelWithoutSuspendConfig 를 세거나 INACTIVE 로 옮김.
 *   suspendConfig 가 없으면 완전 해제이므로 셈. 있으면 단말이 INACTIVE 로 가므로 세지 않고 게이지만
 *     옮김. 암호라 못 읽었으면 'INACTIVE 를 쓰지 않는 망' 전제가 켜져 있을 때만 구조 추론으로 셈.
 *   부작용: 해제 카운터 또는 미상 칸 증가, 근거 수 갱신, 게이지 이동, 표 I 줄 방출 */
static void on_release(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	if (ue_record) {
		ue_record->suspend_resolved = 1;   // 평문으로 읽어 suspend 를 판정했으므로 추론이 필요 없음
		/* Complete 를 놓친 채(열린 수립, 마감 등록됨) RRCRelease 를 보면 - 캡처 1패킷 유실로 도달
		 * 가능 - RRCRelease 는 수립된 연결을 푸는 것이므로 연결은 성립했음. 그래서 열린 수립을 닫아
		 * 마감을 풀고 반쯤 열림을 비움. 안 하면 뒤에 마감이 허위 NoReply 를 발화하고 반쯤 열림이
		 * 누수됨. 형제 종결 핸들러는 모두 이 가드를 하는데 여기만 빠져 있었음 */
		close_setup_complete_unobserved(tr, ue_record);
	}
	enum tr_metric metric = TR_METRIC_RRC_REL_WITHOUT_SUSPEND;
	int suspend = event->payload.release.suspend;
	int count_it = 0, inferred = 0;
	if (suspend == TR_SUSPEND_NO) { count_it = 1; inferred = (event->quality != TR_QUALITY_EXACT); }
	else if (suspend == TR_SUSPEND_UNKNOWN && tr->tr_cfg.assume_no_inactive) {
		count_it = 1;   // 못 읽었지만 전제가 켜져 있으므로 구조 추론으로 셈
		inferred = 1;
	}
	else if (suspend == TR_SUSPEND_YES) {
		// 평문 suspendConfig 를 봤으면 망이 INACTIVE 를 쓴다는 뜻이므로 전제 위반 경보를 올림
		if (tr->tr_cfg.assume_no_inactive) tr->inactive_alarm_count++;
		/* suspendConfig 가 있으면 단말은 INACTIVE 로 감. 완전 해제가 아니므로 세지 않음.
		 * 연결 게이지에서 먼저 뺀 뒤 INACTIVE 게이지로 옮김 - 순서가 어긋나면 ConnMean, ConnMax 가
		 * 과대해짐. 그 게이지는 재개 완료나 레코드 해제에서 빠짐 */
		if (ue_record) {
			gauge_leave_conn(tr, ue_record);
			half_open_leave(tr, ue_record);
			ue_record->rrc_state = RS_INACTIVE;
			ue_record->rel_inferred = 0;   // 평문 직접 관측이므로 남아 있던 추론 표시를 지움
			int release_cell = ue_record->est_cell_index >= 0 ? ue_record->est_cell_index
									 : ue_record->req_cell_index;
			/* 들어갈 밴드를 가르는 것은 '그 단말의 소멸을 관측할 수 있는가' 하나임.
			 *   suspend 를 읽었다는 것 자체가 DCCH 가시성 관문을 통과했다는 뜻이므로 암호가 아닌 것은
			 *   이미 확인된 것임(암호면 libobs 가 미상으로 줌). 남은 판별자는 N2 와의 매칭 유무임.
			 *   매칭이 있으면 그 N2 의 NG 해제를 on_ng_release_cmd 가 받아 게이지에서 빼므로 모집단을
			 *   정확히 추적할 수 있어 정확 밴드임. 매칭이 없으면 소멸을 관측할 수 없어 레코드 해제까지
			 *   남으므로 과대 계수를 막기 위해 미상 밴드(정직한 상한)에 넣음.
			 *   이 선택은 on_ng_release_cmd 의 빼기와 한 묶음으로만 뜻이 성립함 */
			int inactive_level = ue_record->has_n2_pair ? LV_EXACT : LV_UNKNOWN;
			gauge_enter_inactive(tr, ue_record, release_cell, inactive_level);
			// CONNECTED 에서 INACTIVE 로 가는 전이 줄. 평문 RRCRelease 는 관측된 RRC 메시지임
			emit_ue_line(tr, ue_record, event, TR_UE_F_RRC_STATE | TR_UE_F_RRC_MSG, 0);
		}
		return;
	} else {
		// 전제가 꺼져 있고 암호라 못 읽음 -> 미상
		int cell_index = ue_record ? (ue_record->est_cell_index >= 0 ? ue_record->est_cell_index
									: ue_record->req_cell_index)
					   : cell_lookup(tr, &event->cell, 0);
		if (cell_index >= 0) tr->cell_records[cell_index].cc_unknown[metric][0]++;
		// 상태는 불확정이지만 RRCRelease 는 관측된 RRC 메시지이므로 줄은 냄
		if (ue_record) emit_ue_line(tr, ue_record, event, TR_UE_F_RRC_MSG, 0);
		return;
	}
	if (count_it) {
		// 보고 헤더가 내는 근거 수. 평문 관측과 추론을 따로 셈
		if (inferred) tr->release_basis_assumed_count++;
		else tr->release_basis_observed_count++;
		int target_cell = ue_record ? ue_record->est_cell_index : -1;   // 수립이 끝난 셀에 귀속함
		if (target_cell >= 0) {
			tr->cell_records[target_cell].cc_value[metric][0]++;
			if (inferred) tr->cell_records[target_cell].cc_inferred[metric][0]++;
		}
		else {                                      // 수립 셀 모름 -> 제외 칸
			int cell_index = ue_record ? ue_record->req_cell_index
						   : cell_lookup(tr, &event->cell, 0);
			if (cell_index >= 0)
				tr->cell_records[cell_index]
					.cc_excluded[metric][TR_EXCLUDED_EST_CELL_UNKNOWN][0]++;
		}
		/* 등급: 추론으로 센 해제는 교차 추론, 평문 관측은 정확임. 종전엔 추론일 때만 1 을 넣어
		 * 평문 관측에서 옛 값이 남아 정확한 해제가 추론 등급으로 나갔음 - 늘 대입하게 고침 */
		if (ue_record) {
			ue_record->rrc_state = RS_RELEASED;
			ue_record->rel_inferred = inferred;
		}
	}
	// RELEASED 또는 미계수 미상으로 가는 전이 줄(평문 RRCRelease)
	if (ue_record) emit_ue_line(tr, ue_record, event, TR_UE_F_RRC_STATE | TR_UE_F_RRC_MSG, 0);
}

/* on_ctx_release_cmd: UE CONTEXT RELEASE COMMAND 를 보고 RRC 상태를 정함.
 *   수립은 여기서 닫지 않음 - 응답 대기가 해제로 끝났는지는 COMPLETE 가 와야 정해지므로 실패 원인도
 *     그때 셈. 명령과 완료 사이에 마감이 떨어지면 대기 안에 해제가 끝나지 않은 것이라 무응답이 맞음.
 *   게이지도 여기서 빼지 않음 - 이탈의 원천만 기록하고 감소는 COMPLETE 에서 함. libobs 가 유예 시간
 *     만료 때 COMPLETE 를 합성해 주므로 늘 COMPLETE 가 옴.
 *   부작용: RRC 상태 갱신, 표 I 줄 방출 */
static void on_ctx_release_cmd(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	if (!ue_record) return;
	// 해제 명령에 RRC 컨테이너가 있었는지만 봄. SRB 번호는 보지 않음
	if (event->payload.f1_release.rrc_container_kind != TR_RRC_CONTAINER_NONE)
		ue_record->rel_had_container = 1;
	/* 여기 CONNECTED 로 남은 것은 두 경우뿐임. 평문 RRCRelease 는 on_release 가 이미 상태를 잡아
	 *   걸러짐.
	 *   RRC 컨테이너가 없는 해제 명령이면 완전 해제가 확실하므로 RELEASED 에 정확 등급임.
	 *   컨테이너가 있으나 암호라 suspend 를 못 읽었으면, 전제가 켜져 있을 때만 RELEASED 로 구조 추론
	 *   하고 꺼져 있으면 미상으로 둠. 종전엔 둘을 구분하지 않고 RELEASED 에 정확 등급으로 과신해
	 *   암호 해제를 '정확한 해제' 로 내보냈음 */
	if (ue_record->rrc_state != RS_CONNECTED)
		return;
	if (ue_record->rel_had_container) {
		if (tr->tr_cfg.assume_no_inactive) {
			ue_record->rrc_state = RS_RELEASED;
			ue_record->rel_inferred = 1;
		}
		else ue_record->rrc_state = RS_UNKNOWN;   // 정직하게 판정 불가로 둠
	} else {
		ue_record->rrc_state = RS_RELEASED;
		ue_record->rel_inferred = 0;   // 컨테이너 없음 -> 정확. 남아 있던 추론 표시를 지움
	}
	emit_ue_line(tr, ue_record, event, TR_UE_F_RRC_STATE, 0);
}

/* on_ctx_release_complete: UE CONTEXT RELEASE COMPLETE 로 게이지에서 빼고 레코드를 회수함.
 *   암호 구간에서 suspend 를 못 읽었을 때 여기서 한 번 더 추론함: 해제 명령에 컨테이너가 있었고
 *     N2 와 매칭돼 있으면, 명령과 완료 사이에 그 N2 의 NG 해제가 왔으면 완전 해제로 보고 세고, 안
 *     왔으면 NG 연결이 유지된 것이므로 suspend 로 보고 INACTIVE 로 둠(세지 않음).
 *     표준 순서상 완전 해제에서는 NG 해제가 F1 해제보다 먼저 와 그 표시가 제때 섬.
 *   부작용: 수립 실패 원인 카운팅, 해제 카운터 증가 가능, 게이지 감소, 연결모드 갱신, 닫힘 줄 방출,
 *     레코드 회수 */
static void on_ctx_release_complete(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	if (!ue_record) return;
	// 닫힘 줄의 변경 비트는 이 핸들러가 실제로 바꾼 칸만 실음
	int rrc_state_before = ue_record->rrc_state, nas_conn_mode_before = ue_record->nas_conn_mode;
	/* 수립이 아직 열린 채로 완료가 왔으면 응답 대기가 해제로 끝난 것이므로 Other 로 셈.
	 *   TS 28.552 §5.1.1.15.3 c) "Each expected RRCSetupComplete message unreceived by the gNB
	 *   after the RRCSetup message is added to the subcounter for cause 'NoReply'; and each failed
	 *   RRC connection establishment caused by the other reasons is added to measurement cause
	 *   'Other'." 마감이 먼저 떨어졌으면 상태가 열려 있지 않아 센 무응답이 그대로 남음 */
	close_setup_other(tr, ue_record);
	gauge_leave_conn(tr, ue_record);     // 게이지 감소는 명령이 아니라 완료에서 함
	half_open_leave(tr, ue_record);
	/* N2 와 매칭된 경우에만 추론함. 매칭이 없으면 추론을 금지하고 명령 핸들러가 남긴 미상을 유지함 -
	 * F1 만 보이는 캡처에서 허위 INACTIVE 를 만들지 않으려는 것임. 암호 INACTIVE 의 게이지 기여는
	 * 판정이 늦어 관측할 수 없고 그것이 암호 구간의 한계임 */
	if (!ue_record->suspend_resolved && ue_record->rel_had_container && ue_record->has_n2_pair) {
		ue_record->rel_inferred = 1;   // 아래 상태는 평문 관측이 아니라 추론이므로 교차 등급임
		enum tr_metric metric = TR_METRIC_RRC_REL_WITHOUT_SUSPEND;
		if (ue_record->n2_released) {        // 창 안에 NG 해제가 옴 -> 완전 해제 -> 추론 계수
			if (ue_record->est_cell_index >= 0) {
				tr->cell_records[ue_record->est_cell_index].cc_value[metric][0]++;
				tr->cell_records[ue_record->est_cell_index].cc_inferred[metric][0]++;
			}
			else if (ue_record->req_cell_index >= 0)
				tr->cell_records[ue_record->req_cell_index]
					.cc_excluded[metric][TR_EXCLUDED_EST_CELL_UNKNOWN][0]++;
			ue_record->rrc_state = RS_RELEASED;
		} else {                     // NG 연결 유지 -> suspend 추론 -> INACTIVE(세지 않음)
			ue_record->rrc_state = RS_INACTIVE;
		}
	}
	/* 컨텍스트 해제 완료이므로 연결모드는 IDLE 로 감. 등록 상태는 유지함 - 정상 해제 뒤에도 등록은
	 * 남을 수 있음. 다만 INACTIVE 는 N2 와 NAS 연결이 유지되어 연결모드가 CONNECTED 이므로 강제로
	 * IDLE 로 내리지 않음 */
	if (ue_record->nas_conn_mode == TR_CM_MODE_CONNECTED && ue_record->rrc_state != RS_INACTIVE)
		ue_record->nas_conn_mode = TR_CM_MODE_IDLE;
	uint32_t changed_mask = 0;
	if (ue_record->rrc_state != rrc_state_before) changed_mask |= TR_UE_F_RRC_STATE;
	if (ue_record->nas_conn_mode != nas_conn_mode_before)   changed_mask |= TR_UE_F_NAS_STATE;
	emit_ue_line(tr, ue_record, event, changed_mask, 1);
	ue_record_free(tr, ue_record);
}

/* drain_assoc: 한 연결에 속한 모든 UE 를 닫음. 전수 스캔이라 비용이 UE 수에 비례함.
 *   전체 범위 RESET 과 F1 SETUP 에서만 씀 - libobs 가 그 둘을 UE 별이 아니라 연결당 한 번만 보내기
 *     때문임. SCTP 연결 종료는 libobs 가 UE 별로 하나씩 보내므로 on_assoc_end 가 UE 하나씩 처리함.
 *     일부 범위 RESET 은 목록이 가리킨 UE 만 닫으므로 여기로 오지 않음 */
static void drain_assoc(struct tr *tr, uint32_t assoc_id, int as_other)
{
	for (uint32_t i = 0; i < tr->ue_count; i++) {
		struct tr_ue_record *ue_record = &tr->ue_records[i];
		if (!ue_record->used || ue_record->assoc_id != assoc_id) continue;
		if (as_other) close_setup_other(tr, ue_record);
		teardown_all_gauges(tr, ue_record);
		ue_record_free(tr, ue_record);
	}
}

/* on_reset: F1AP RESET 또는 F1 SETUP 이 가리킨 UE 를 닫음.
 *   TS 38.473 §8.2.1.2.1 "release all allocated resources on F1 ... related to the UE association(s)
 *   indicated explicitly or implicitly in the RESET message and remove the indicated UE contexts".
 *   F1 SETUP 도 같은 조항으로 묶는 근거는 §8.2.3.1 - "This procedure also re-initialises the F1AP
 *   UE-related contexts (if any) and erases all related signalling connections in the two nodes
 *   like a Reset procedure would do". 범위를 가르는 것은 libobs 이고(그쪽만 gNB-DU ID 를 앎) 여기는
 *   이벤트가 실어 온 범위를 그대로 적용함.
 *   전체 범위는 그 연결 전부, 일부 범위는 목록이 가리킨 UE 만임(목록이 비면 닫을 것이 없음).
 *   같은 조항이 "shall use the gNB-CU UE F1AP ID IE and/or the gNB-DU UE F1AP ID IE" 라고 적어
 *   항목에 CU 번호만 실릴 수 있는데, 우리 색인은 (연결, DU 번호)뿐이라 그런 항목은 못 가리킴.
 *   못 가리킨 것을 '전체' 로 넓히면 CU 가 유지한 멀쩡한 UE 까지 닫혀 지표가 과소 계수됨 -
 *   그래서 닫지 않고 셈. 그 UE 는 게이지에 남아 과대 계수되지만, 센 수가 그 사실을 말해 줌.
 *   부작용: 닫은 UE 마다 진행 중 수립을 Other 로 마감하고 게이지에서 뺌 */
static void on_reset(struct tr *tr, const struct obs_event *event)
{
	if (event->payload.reset.scope == TR_SCOPE_ALL) {
		drain_assoc(tr, event->assoc_id, 1);           // 결과를 모르는 실패로 닫음
		return;
	}
	/* 경계 검사: 집계 엔진은 libobs 를 믿지 않음(이벤트만 아는 계층이므로 들어온 값으로 판단함).
	 *   개수가 음수면 0 으로 보고, 목록이 없는데 개수가 있으면 가리키지 못한 것으로 셈 -
	 *   조용히 지나가면 "RESET 이 아무도 안 가리켰음" 과 같은 모양이 됨(값을 담지 않고 그 수를 셈) */
	int listed_count = event->payload.reset.ue_count > 0 ? event->payload.reset.ue_count : 0;
	int overflow_count = event->payload.reset.ue_overflow_count > 0
			   ? event->payload.reset.ue_overflow_count : 0;
	tr->reset_unresolved_count += (uint32_t)overflow_count;
	if (!event->payload.reset.ues) {
		tr->reset_unresolved_count += (uint32_t)listed_count;
		return;
	}
	for (int ue_index = 0; ue_index < listed_count; ue_index++) {
		const struct tr_reset_ue *reset_ue = &event->payload.reset.ues[ue_index];
		struct tr_ue_record *ue_record = ue_lookup(tr, &reset_ue->f1ue, 0, event->assoc_id);
		if (!ue_record) {
			// libobs 가 못 찾았거나(CU 번호만 온 항목) 우리에게 레코드가 없음. 둘 다 '가리키지 못함' 임
			tr->reset_unresolved_count++;
			continue;
		}
		close_setup_other(tr, ue_record);
		teardown_all_gauges(tr, ue_record);
		ue_record_free(tr, ue_record);
	}
}

/* on_assoc_end: SCTP 연결 종료로 그 UE 를 닫고 AMF 레코드를 회수함.
 *   libobs 는 이 연결의 F1 UE 마다 하나씩 보내므로 이벤트가 가리키는 UE 하나만 처리함. 종전엔 전수
 *     스캔을 UE 수만큼 반복해, 위조 ABORT 로 정리 비용이 UE 수의 제곱까지 늘었음. 식별 없는 벌크
 *     종료는 지금 libobs 가 보내지 않지만 대비로 전수 스캔을 남김 */
static void on_assoc_end(struct tr *tr, const struct obs_event *event)
{
	if (event->f1ue.valid) {
		struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
		if (ue_record) {
			close_setup_other(tr, ue_record);
			teardown_all_gauges(tr, ue_record);
			ue_record_free(tr, ue_record);
		}
	} else {
		drain_assoc(tr, event->assoc_id, 1);
	}
	/* 끊긴 AMF 의 과부하 상태가 영구히 남아 과부하 판정이 썩는 것을 막고 표 크기도 묶음. F1 경로라
	 * 보통 AMF 키와 연결이 맞지 않아 아무 일도 없지만 대칭으로 불러 둠 - 실제 N2 회수는 디스패치의
	 * N2 분기가 담당함 */
	amf_drop_assoc(tr, event->assoc_id);
}

// on_ue_replaced: 같은 du_ue_id 가 다시 쓰여 옛 레코드를 닫음
static void on_ue_replaced(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	if (!ue_record) return;
	close_setup_other(tr, ue_record);
	teardown_all_gauges(tr, ue_record);
	/* 번호 재사용은 해제 명령 없이 끝나는 것이므로 미상으로 닫음. RELEASED 와 INACTIVE 는 유지함 -
	 * 끝 신호가 RRC 결과를 알려 주지 않기 때문임. 종전엔 CONNECTED, 수립 대기 상태를 그대로 둬
	 * 닫힘 줄이 과신이었음. 바뀌면 변경 비트에 RRC 상태를 실음 */
	uint32_t changed_mask = 0;
	if (ue_record->rrc_state != RS_RELEASED && ue_record->rrc_state != RS_INACTIVE
	    && ue_record->rrc_state != RS_UNKNOWN) {
		ue_record->rrc_state = RS_UNKNOWN;
		changed_mask |= TR_UE_F_RRC_STATE;
	}
	emit_ue_line(tr, ue_record, event, changed_mask, 1);
	ue_record_free(tr, ue_record);
}

/* on_ue_evicted: 우리 쪽 레코드 상한으로 UE 를 버림. 수립 실패가 아니라 관측 한계임.
 *   게이지나 반쯤 열림에 실제로 들어 있던 UE 가 축출될 때만 그 주기의 표본 상한을 무효화함. 이미
 *     결과가 난 레코드의 축출은 상한을 건드리지 않음 */
static void on_ue_evicted(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	if (!ue_record) return;
	int was_in_gauge = ue_record->in_conn || ue_record->in_inactive || ue_record->half_open;
	// 무효화할 셀은 그 UE 가 실제로 기여 중인 게이지의 셀임
	int cell_index = ue_record->in_conn ? ue_record->conn_cell_index
			 : (ue_record->in_inactive ? ue_record->inactive_cell_index
						  : (ue_record->half_open ? ue_record->half_open_cell_index
									  : ue_record->req_cell_index));
	gauge_leave_conn(tr, ue_record);
	half_open_leave(tr, ue_record);
	open_list_remove(tr, ue_record);
	if (was_in_gauge && cell_index >= 0) tr->cell_records[cell_index].evicted_this_period = 1;
	tr->lost_evicted_count++;
	ue_record_free(tr, ue_record);
}

/* on_ue_transfer: 재수립 수락으로 옛 F1 UE 의 연결과 표 I 값을 새 레코드로 넘김.
 *   이유: 재수립 수락은 새 연결이 아니라 연결의 '이전' 임. 게이지 수치는 유지되어야 하고, 표 I 의
 *     관측값도 새 레코드에서 되살아나야 함.
 *   순서: 새 레코드를 먼저 만듬 - 생성이 배열을 재배치할 수 있어 옛 포인터는 그 뒤에 얻어야 함.
 *   부작용: 게이지 소유권 이전, 표 I 값 복사, 옛 레코드 회수, 수립 종결 */
static void on_ue_transfer(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *new_ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (!new_ue_record) return;
	struct tr_f1ue old_f1ue = event->f1ue;
	old_f1ue.du_ue_id = event->payload.ue_transfer.old_du_ue_id;
	// 생성하지 않으므로 배열 재배치가 없고 위에서 얻은 포인터가 유효함
	struct tr_ue_record *old_ue_record = ue_lookup(tr, &old_f1ue, 0, event->assoc_id);
	/* 이어지는 연결이 놓이는 셀은 이 전송이 일어난 셀임(libobs 가 추적하는 현재 셀). 정상 재수립에서는
	 * 재수립 요청 셀과 같음. 새 레코드 자신의 옛 수립 셀이 아님 - du_ue_id 재사용 같은 경우엔 둘이
	 * 다를 수 있음. 셀을 모르면 옛 셀을 유지함. 셀 조회는 셀 배열만 재배치하므로 UE 포인터는 안전함 */
	int target_cell_index = event->cell.valid ? cell_lookup(tr, &event->cell, 1) : -1;
	if (old_ue_record && old_ue_record != new_ue_record) {
		/* 목적지가 이미 게이지에 있으면 그 기여를 먼저 비운 뒤 옛 상태를 넘겨받음 - du_ue_id 재사용과
		 * 이전 해제 유실이 겹친 경우임. 안 비우면 목적지의 옛 1 이 고아가 되어 그 셀 게이지가 영영
		 * 빠지지 않아 ConnMean, ConnMax 가 과대해짐. 신규 레코드면 세 호출 모두 아무 일도 하지 않음 */
		gauge_leave_conn(tr, new_ue_record);
		half_open_leave(tr, new_ue_record);
		gauge_leave_inactive(tr, new_ue_record);
		if (old_ue_record->in_conn) {                 // 소유권 이전이므로 수치는 유지함
			new_ue_record->in_conn = 1;
			new_ue_record->conn_level = old_ue_record->conn_level;
			new_ue_record->conn_cell_index = old_ue_record->conn_cell_index;
			old_ue_record->in_conn = 0;
			/* 전송 셀이 옛 연결 셀과 다르면 1 을 옛 셀에서 전송 셀로 옮김(한쪽 -1, 다른쪽 +1 이라
			 * 합은 보존됨). 같은 셀이면 아무 일도 하지 않으므로 단일 셀 배치는 무영향임 */
			conn_move_cell(tr, new_ue_record,
				       (target_cell_index >= 0) ? target_cell_index
								: old_ue_record->conn_cell_index);
		}
		if (old_ue_record->est_cell_index >= 0)
			new_ue_record->est_cell_index = old_ue_record->est_cell_index;
		// 시도를 센 셀도 넘김. 옛 레코드에서 요청을 봤다면 새 레코드의 성공이 그 셀에 귀속되어야 함
		if (old_ue_record->att_cell_index >= 0 && new_ue_record->att_cell_index < 0)
			new_ue_record->att_cell_index = old_ue_record->att_cell_index;
		new_ue_record->has_stmsi48 = old_ue_record->has_stmsi48;
		new_ue_record->stmsi48 = old_ue_record->stmsi48;
		new_ue_record->stmsi_part1 = old_ue_record->stmsi_part1;
		new_ue_record->has_stmsi_part1 = old_ue_record->has_stmsi_part1;
		new_ue_record->has_alg = old_ue_record->has_alg;
		new_ue_record->ciph_alg = old_ue_record->ciph_alg;
		new_ue_record->integ_alg = old_ue_record->integ_alg;
		new_ue_record->ciph_alg_now = old_ue_record->ciph_alg_now;
		new_ue_record->integ_alg_now = old_ue_record->integ_alg_now;
		new_ue_record->alg_changed_after_smc = old_ue_record->alg_changed_after_smc;
		new_ue_record->alg_change_opportunity_count = old_ue_record->alg_change_opportunity_count;
		/* 표 I 항목은 전부 옮김. 새 레코드에서 본 값으로 두는 것은 C-RNTI 와 RRC 메시지 기록뿐임.
		 * 종전 복사 블록은 S-TMSI, 알고리즘, RRC 상태만 옮기고 NAS 상태, AS 보안, NAS 보안, 마지막
		 * NAS, N2 매칭을 빠뜨려 전사 뒤 CONNECTED 인데 보안 상태가 미상으로 리셋됐음 - 내부가 서로
		 * 모순되고 관측값이 사라짐. 형제 분기 사이의 비대칭이 그대로 결함이 된 곳임 */
		new_ue_record->rrc_sec_state = old_ue_record->rrc_sec_state;
		new_ue_record->rrc_sec_quality = old_ue_record->rrc_sec_quality;
		new_ue_record->nas_sec_state = old_ue_record->nas_sec_state;
		new_ue_record->nas_sec_quality = old_ue_record->nas_sec_quality;
		new_ue_record->nas_reg_state = old_ue_record->nas_reg_state;
		new_ue_record->nas_conn_mode = old_ue_record->nas_conn_mode;
		new_ue_record->nas_reg_state_origin = old_ue_record->nas_reg_state_origin;
		new_ue_record->nas_state_quality = old_ue_record->nas_state_quality;
		new_ue_record->last_nas_epd = old_ue_record->last_nas_epd;
		new_ue_record->last_nas_sht = old_ue_record->last_nas_sht;
		new_ue_record->last_nas_msg_type = old_ue_record->last_nas_msg_type;
		new_ue_record->has_last_nas = old_ue_record->has_last_nas;
		new_ue_record->nas_msg_quality = old_ue_record->nas_msg_quality;
		new_ue_record->has_n2_pair = old_ue_record->has_n2_pair;
		new_ue_record->n2_released = old_ue_record->n2_released;
		new_ue_record->rrc_state = RS_CONNECTED;   // 전사도 등급을 승계함(위 블록과 같은 이유)
		new_ue_record->conn_inferred = old_ue_record->conn_inferred;
		half_open_leave(tr, old_ue_record);
		old_ue_record->in_conn = 0;
		ue_record_free(tr, old_ue_record);
	}
	if (target_cell_index >= 0) new_ue_record->req_cell_index = target_cell_index;
	else if (new_ue_record->req_cell_index < 0 && event->cell.valid)
		new_ue_record->req_cell_index = cell_lookup(tr, &event->cell, 1);
	/* 전사는 연결이 계속되는 '이전' 이지 열린 수립이 아니므로 종결함.
	 *   레코드가 기본값인 열린 수립으로 남으면(요청 미관측, 옛 레코드 미상, 완료 미도달) 위에서 셀을
	 *   심었으므로 이후 해제 명령이나 완료가 '열린 수립 + 셀 있음' 을 보고 실패 원인을 허위 계수함.
	 *   재수립 성공 계수는 무영향임 - 그 핸들러는 수립 상태와 무관하게 셈.
	 *   종결에 settle 을 쓰는 이유는 반쯤 열림도 같이 비우기 때문임. 옛 레코드가 있던 경로는 위에서
	 *   이미 비웠으니 여기서는 아무 일도 하지 않고, 옛 레코드가 없거나 같은 레코드인 경로에서만 남아
	 *   있던 반쯤 열림을 비움 - 전사로 이 레코드는 연결 레코드가 되므로 그 창은 끝나야 함. 종전에는
	 *   손으로 펼쳐 쓰면서 반쯤 열림 비우기를 빠뜨려 그 게이지가 주기를 넘겨 영구히 누수됐음 */
	settle_open_setup(tr, new_ue_record, SR_SUCCESS);
}

/* on_cell_config: F1 SETUP REQUEST 또는 GNB-DU CONFIGURATION UPDATE 의 Served Cell 하나.
 *   이 이벤트로 하는 일은 셀 표에 그 셀을 등록하는 것뿐임.
 *   사건이 없는 셀도 0건 주기 보고를 내야 하는데, 등록이 없으면 그 셀은 첫 UE 가 붙을 때까지
 *   아예 보고되지 않음 - 읽는 쪽은 빠진 칸을 '알 수 없음' 으로 보류함 */
static void on_cell_config(struct tr *tr, const struct obs_event *event)
{
	cell_lookup(tr, &event->cell, 1);
}

/* on_smc: AS 보안 모드 명령 또는 알고리즘을 바꾸는 재설정에서 암호, 무결성 알고리즘을 받음.
 *   명령이면 보안 상태를 CMD_SENT 로 올리고, 재설정이면 지금 값과 달라졌는지만 봄 */
static void on_smc(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (!ue_record) return;
	uint32_t changed_mask = 0;
	if (event->kind == TR_EVENT_RRC_SMC) {
		ue_record->ciph_alg = event->payload.smc.ciph_alg;
		ue_record->integ_alg = event->payload.smc.integ_alg;
		ue_record->ciph_alg_now = ue_record->ciph_alg;
		ue_record->integ_alg_now = ue_record->integ_alg;
		ue_record->has_alg = 1;
		changed_mask |= TR_UE_F_ALG;
		ue_record->rrc_sec_state = TR_SEC_CMD_SENT;   // 하행 보안 모드 명령 -> 명령 보냄
		ue_record->rrc_sec_quality = TR_QUALITY_EXACT;
		changed_mask |= TR_UE_F_SEC;
	} else { /* 알고리즘을 바꾸는 재설정: 지금 값의 변경만 관측함 */
		int new_ciph_alg = event->payload.smc.ciph_alg, new_integ_alg = event->payload.smc.integ_alg;
		/* '명령 뒤' 라는 말이 성립하려면 명령을 봤어야 함. 안 보고 비교하면 초기값과 달랐다는 사실이
		 * '명령 뒤 변경' 으로 나가 없는 사건을 지어냄. 그래서 명령을 봤는지를 관문으로 씀 */
		if (ue_record->has_alg
		    && ((new_ciph_alg >= 0 && new_ciph_alg != ue_record->ciph_alg_now)
			|| (new_integ_alg >= 0 && new_integ_alg != ue_record->integ_alg_now))) {
			ue_record->alg_changed_after_smc = 1;
			changed_mask |= TR_UE_F_ALG;
		}
		if (new_ciph_alg >= 0) ue_record->ciph_alg_now = new_ciph_alg;
		if (new_integ_alg >= 0) ue_record->integ_alg_now = new_integ_alg;
	}
	emit_ue_line(tr, ue_record, event, changed_mask, 0);
}

// on_alg_opportunity: 알고리즘을 바꿀 수 있었던 재설정 수. 바뀌었는지와 무관하게 기회만 셈
static void on_alg_opportunity(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (ue_record) ue_record->alg_change_opportunity_count++;
}

/* on_smc_result: AS 보안 모드 완료 또는 실패로 보안 상태를 확정함.
 *   완료면 ACTIVE, 실패면 FAILED(보안 전과 같은 상태)임. 둘 다 규격상 평문 상행이라 정확 등급임 */
static void on_smc_result(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (!ue_record) return;
	ue_record->rrc_sec_state = (event->kind == TR_EVENT_RRC_SMC_COMPLETE) ? TR_SEC_ACTIVE
									      : TR_SEC_FAILED;
	ue_record->rrc_sec_quality = TR_QUALITY_EXACT;
	emit_ue_line(tr, ue_record, event, TR_UE_F_SEC, 0);
}

/* on_rrc_dcch_opaque: 탭을 붙이기 전부터 연결돼 있던 단말을 미상 연결 모집단에 넣음.
 *   이유: 그런 단말의 첫 신호는 암호 SRB1 이라 가시성 관문에서 막혀 내용을 알 수 없음. 그래도 연결은
 *     실재하므로 ConnMean, ConnMax 의 상한에는 기여해야 함.
 *   규칙: 이미 추적 중인 단말은 손대지 않음 - 그 단말은 이미 정확이나 반쯤 열림 모집단에 있어 미상으로
 *     다시 넣으면 이중 계수임. 셀을 모르면 어느 셀에도 귀속할 수 없어 세지 않음(정직한 잔여 한계).
 *     수립 상태를 미상으로 둬 '수립 시도' 로 오인되어 실패 원인이 오발화하지 않게 함 */
static void on_rrc_dcch_opaque(struct tr *tr, const struct obs_event *event)
{
	if (ue_lookup(tr, &event->f1ue, 0, event->assoc_id)) return;   // 이미 추적 중 -> 아무것도 하지 않음
	if (!event->cell.valid) return;                          // 셀 미상 -> 귀속 불가
	int cell_index = cell_lookup(tr, &event->cell, 1);
	if (cell_index < 0) return;
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (!ue_record) return;
	ue_record->req_cell_index = cell_index;
	ue_record->setup_state = SR_UNKNOWN;        // 수립 시도가 아니므로 실패 원인 오발화를 막음
	gauge_enter_conn(tr, ue_record, cell_index, LV_UNKNOWN);   // 미상 밴드라 표본 상한에만 기여함
	ue_record->rrc_state = RS_CONNECTED;
	ue_record->conn_inferred = 1;   // 암호 SRB1 중간 합류의 구조 추론이라 직접 관측이 아님
}

/* on_ue_ctx_setup: UE CONTEXT SETUP / MODIFICATION REQUEST 에서 C-RNTI 와 현재 셀을 갱신함.
 *   SpCell ID 로 현재 셀이 바뀌면 연결 게이지를 옛 셀에서 새 셀로 옮김(DU 안 핸드오버).
 *   부작용: 게이지 셀 이동, 현재 셀 갱신, C-RNTI 가 오면 표 I 줄 방출 */
static void on_ue_ctx_setup(struct tr *tr, const struct obs_event *event)
{
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 1, event->assoc_id);
	if (!ue_record) return;
	if (event->cell.valid) {
		int cell_index = cell_lookup(tr, &event->cell, 1);
		if (cell_index >= 0) {
			conn_move_cell(tr, ue_record, cell_index);   // 연결 중이면 옮기고 아니면 아무 일도 없음
			/* 현재 셀은 수립이나 연결을 실제로 관측한 레코드에만 심음.
			 *   이 이벤트로 처음 본 중간 합류 단말은 수립 요청과 RRCSetup 을 못 봤고 게이지에도 없는
			 *   채 기본값인 열린 수립으로 남음. 그런 레코드에 셀을 심으면 이후 해제 명령이 '열린
			 *   수립 + 셀 있음' 을 보고 실패 원인을 허위 계수함 - 열린 수립은 RRCSetupRequest 를
			 *   관측했을 때만 세는 것이 규칙임.
			 *   반쯤 열림, 연결, 종결된 상태는 실제 관측이므로 SpCell 로 현재 셀을 갱신함 */
			if (ue_record->setup_state != SR_OPEN || ue_record->half_open
			    || ue_record->saw_setup_sent || ue_record->in_conn)
				ue_record->req_cell_index = cell_index;
		}
	}
	if (event->payload.ue_ctx_setup.has_crnti) {
		ue_record->crnti = event->payload.ue_ctx_setup.crnti;
		ue_record->has_crnti = 1;
		emit_ue_line(tr, ue_record, event, TR_UE_F_CRNTI, 0);
	}
}

// ---- N2 이벤트 ----
/* on_initial_ue_msg: INITIAL UE MESSAGE 를 UECNTX.ConnEstabAtt 에 세고 N2 레코드에 원인과 셀을 심음.
 *   TS 28.552 §5.1.1.16.1 c) "On transmission of an INITIAL UE MESSAGE by the gNodeB to the AMF ...
 *   is incremented by 1" - 메시지 송신 자체가 발화 조건임 */
static void on_initial_ue_msg(struct tr *tr, const struct obs_event *event)
{
	tr->n2_observed = 1;
	int cell_index = cell_lookup(tr, &event->cell, 1);
	int est_cause = event->payload.initial_ue.est_cause;
	enum tr_metric metric = TR_METRIC_UECNTX_CONN_ESTAB_ATT;
	int cause_index = (est_cause >= 0 && est_cause < METRIC_CAUSE_CNT[metric]) ? est_cause : -1;
	if (cell_index >= 0) {
		if (cause_index >= 0) tr->cell_records[cell_index].cc_value[metric][cause_index]++;
		else tr->cell_records[cell_index].cc_unknown_nocause[metric]++;
	}
	// 성공 쪽에서 쓸 원인과 셀을 N2 레코드에 저장함
	if (event->n2ue.valid) {
		struct tr_n2_record *n2_record = n2_lookup(tr, event->assoc_id,
							   event->n2ue.ran_ue_ngap_id, 1);
		if (n2_record) {
			n2_record->est_cause = est_cause;
			n2_record->uli_cell_index = cell_index;
			n2_record->amf_id_seen = 0;
		}
	}
}

/* on_amf_dl: AMF 가 그 단말에 처음 내려 보낸 하행을 UECNTX.ConnEstabSucc 에 셈.
 *   amf_id_seen 은 중복 가드임 - libobs 가 레코드를 다시 만들어 '첫 하행' 을 또 보내도 성공은 한 번만
 *     세어야 함. 종전에는 기록만 하고 읽지 않아 쓰이지 않는 칸이었음 */
static void on_amf_dl(struct tr *tr, const struct obs_event *event)
{
	tr->n2_observed = 1;
	if (!event->payload.amf_dl.first_for_ran_ue_ngap_id || !event->n2ue.valid) return;
	struct tr_n2_record *n2_record = n2_lookup(tr, event->assoc_id, event->n2ue.ran_ue_ngap_id, 0);
	if (!n2_record || n2_record->uli_cell_index < 0 || n2_record->amf_id_seen) return;
	enum tr_metric metric = TR_METRIC_UECNTX_CONN_ESTAB_SUCC;
	int cause_index = (n2_record->est_cause >= 0
			   && n2_record->est_cause < METRIC_CAUSE_CNT[metric]) ? n2_record->est_cause : -1;
	if (cause_index >= 0)
		tr->cell_records[n2_record->uli_cell_index].cc_value[metric][cause_index]++;
	else tr->cell_records[n2_record->uli_cell_index].cc_unknown_nocause[metric]++;
	n2_record->amf_id_seen = 1;
}

/* on_ng_release_cmd: NG UE CONTEXT RELEASE COMMAND 로 완전 해제 신호를 남기고 INACTIVE 게이지를 비움.
 *   이 이벤트가 F1 단말에 붙어 왔다는 것 자체가 F1 과 N2 의 매칭이 성립했다는 증거임. F1 만 보이는
 *     캡처에는 N2 이벤트가 아예 없어 그 칸이 계속 0 이므로, 매칭 없는 암호 해제는 미상으로 남음.
 *   해제 원인이 NAS 해제면 5GMM 은 DEREGISTERED 로 감(교차 추론). 그 밖 원인은 등록이 유지되므로
 *     표 I 에 변화가 없고 줄도 내지 않음 */
static void on_ng_release_cmd(struct tr *tr, const struct obs_event *event)
{
	tr->n2_observed = 1;
	if (!event->f1ue.valid) return;   // 매칭된 F1 이 없으면 표 I 에 반영할 대상이 없음
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	if (!ue_record) return;
	ue_record->has_n2_pair = 1;
	ue_record->n2_released = 1;   // 완전 해제 신호. 내부 플래그라 그 자체로 줄을 내지 않음
	/* 매칭된 N2 단말의 NG 해제는 INACTIVE 모집단에서 그 단말이 사라졌다는 뜻이므로 여기서 바로 비움.
	 * 종전엔 레코드 해제까지 남아 과잉 잔류였음. gauge_leave_inactive 는 멱등이라 뒤에 레코드 해제가
	 * 다시 불러도 이중 감소가 없음. 들어간 밴드를 그대로 되돌리므로 늦게 매칭이 생겨 미상 밴드로
	 * 들어간 단말도 정확히 그 칸에서 빠짐. INACTIVE 에서 RELEASED 로 가는 전이는 평문 RRC 관측이
	 * 아니라 N2 교차 추론임 */
	if (ue_record->in_inactive) {
		gauge_leave_inactive(tr, ue_record);
		ue_record->rrc_state = RS_RELEASED;
		ue_record->rel_inferred = 1;
	}
	if (event->payload.ng_cause.cause_group == TR_NGAP_CAUSE_GRP_NAS &&
	    event->payload.ng_cause.cause_value == TR_NGAP_CAUSE_NAS_DEREGISTER) {
		ue_record->nas_reg_state = TR_5GMM_DEREGISTERED;
		ue_record->nas_state_quality = TR_QUALITY_CROSS;
		emit_ue_line(tr, ue_record, event, TR_UE_F_NAS_STATE, 0);
	}
}

/* on_rrc_state_report: N2 의 RRC INACTIVE TRANSITION REPORT 로 INACTIVE 진입을 확정하고 전제 위반을
 *   경보함.
 *   이유: 이 보고가 오면 망이 RRC_INACTIVE 를 쓴다는 것이 확정됨. 암호 구간에서는 suspend 를 읽을 수
 *     없어 미상으로만 남는데, 이 보고는 그 구간에서도 진입을 확정해 줌.
 *   밴드가 정확인 이유: 망이 자기 상태를 NGAP 로 명시 보고한 것이라 평문 suspendConfig 경로의 매칭
 *     추정보다 강한 근거임. 다만 F1 레코드에는 교차 귀속으로 붙으므로 상태 등급은 교차로 둠 -
 *     관측한 쪽은 N2 이고 F1 단말로는 추론임.
 *   RRCState 가 connected 인 보고는 아무 전이도 만들지 않음: INACTIVE 에서 CONNECTED 로 되돌리는 것은
 *     규격이 정한 것이 아니라 우리 설계 결정이 됨. 비우기는 기존 경로(재개 완료, NG 해제, 레코드
 *     해제)가 맡고 그때까지 게이지는 정직한 상한으로 남음. 조용한 드롭이 아님 - 이벤트는 처리되고
 *     매칭 표시도 갱신하되 상태를 새로 주장하지 않을 뿐임.
 *   부작용: 전제 위반 경보 증가(중복 보고는 제외), 열린 수립을 단일 종결 관문으로 닫음, 게이지를
 *     연결에서 INACTIVE 로 옮김, 표 I 줄 방출. 평문으로 이미 판정된 단말은 덮지 않고 경고만 올림 */
static void on_rrc_state_report(struct tr *tr, const struct obs_event *event)
{
	tr->n2_observed = 1;
	int rrc_state = event->payload.rrc_state_report.rrc_state;
	if (rrc_state != TR_NGAP_RRC_STATE_INACTIVE) return;   // connected 와 확장값은 전이를 만들지 않음

	struct tr_ue_record *ue_record = event->f1ue.valid
				       ? ue_lookup(tr, &event->f1ue, 0, event->assoc_id) : NULL;
	if (ue_record) ue_record->has_n2_pair = 1;   // 교차 귀속된 N2 이벤트는 매칭 성립의 증거임

	/* 중복, 재전송 보고는 경보도 세지 않음. 종전엔 게이지만 멱등이고 경보 증가는 가드 위에 있어, 한
	 *   INACTIVE 구간이 경보 4건(평문 해제 + 보고 + 중복 보고 + 재개 요청)으로 불어났음. 이 경보는
	 *   혼자서도 주기 보고를 만들어 내므로 부풀면 보고 자체가 왜곡됨. 게이지와 같은 멱등성을 줌 */
	bool already_inactive = ue_record && ue_record->rrc_state == RS_INACTIVE;
	/* 전제 위반 경보는 매칭된 F1 이 없어도 올림 - 이 보고 자체가 "망이 RRC_INACTIVE 를 쓴다" 는
	 * 증거이고, 전제는 단말이 아니라 배치에 대한 것임 */
	if (tr->tr_cfg.assume_no_inactive && !already_inactive) tr->inactive_alarm_count++;

	if (!ue_record || already_inactive) return;   // 매칭된 F1 이 없으면 표 I 에 반영할 대상이 없음

	/* 평문으로 suspend 가 이미 판정됐으면 교차 추론으로 덮지 않음.
	 *   형제 추론 지점이 쓰는 전제와 같음. 안 막으면 재정렬, 중복 보고가 직접 관측한 RELEASED 를
	 *   INACTIVE 로 뒤집어, 같은 단말이 완전 해제로 세어진 채 INACTIVE 게이지에도 들어감 - 표 II 의
	 *   두 값이 서로 모순됨. 강한 직접 관측을 약한 추론으로 낮추지 않는다는 등급 정책의 정반대임.
	 *   조용히 버리지도 않음 - 모순 자체를 운영자 신호로 올림 */
	if (ue_record->suspend_resolved) {
		warn(tr, "RRC_STATE_CONTRADICTION",
		     "N2 RRCInactiveTransitionReport(inactive) contradicts plaintext RRCRelease; keeping the plaintext");
		return;
	}

	/* 형제 on_release 처럼 단일 종결 관문을 먼저 통과함. 종전엔 그 경로를 인용하면서 게이지 이동만
	 *   베끼고 관문을 빠뜨렸음 - 열린 수립이 마감을 건 채 남아, 뒤에 마감이 허위 NoReply 를
	 *   발화했음. 그러면 같은 단말이 수립 실패로 세어진 동시에 INACTIVE 의 정확 밴드에 들어감.
	 *   반쯤 열림만 비우고 시도를 열어 두면 그 창이 잘려 ConnMean, ConnMax 상한도 과소가 됨 */
	close_setup_complete_unobserved(tr, ue_record);   // 완료는 못 봤으므로 시도는 미상 밴드에 남김

	/* 형제 경로(on_release 의 suspend 있음)와 같은 순서로 옮김: 연결에서 빼고 반쯤 열림을 비운 뒤
	 * INACTIVE 로 진입함. 순서가 어긋나면 ConnMean, ConnMax 가 과대해지거나 반쯤 열림이 누수됨 */
	int release_cell = ue_record->est_cell_index >= 0 ? ue_record->est_cell_index
							 : ue_record->req_cell_index;
	gauge_leave_conn(tr, ue_record);
	half_open_leave(tr, ue_record);
	ue_record->rrc_state = RS_INACTIVE;
	ue_record->rel_inferred = 1;   // N2 교차 귀속이라 상태 등급은 교차임
	gauge_enter_inactive(tr, ue_record, release_cell, LV_EXACT);
	emit_ue_line(tr, ue_record, event, TR_UE_F_RRC_STATE, 0);
}

// on_overload_start: AMF 과부하 시작. 과부하 판정이 읽을 입력을 AMF 레코드에 담음
static void on_overload_start(struct tr *tr, const struct obs_event *event)
{
	tr->n2_observed = 1;
	uint64_t amf_key = event->amf_id ? ((uint64_t)event->amf_id | (1ull << 40))
					 : ((uint64_t)event->assoc_id);
	struct tr_amf_record *amf_record = amf_lookup(tr, amf_key, 1);
	if (amf_record) {
		amf_record->state = AMF_OVERLOAD;
		amf_record->action_mask = event->payload.overload.action_mask;
		amf_record->last_assoc = event->assoc_id;
		amf_record->has_action = event->payload.overload.has_action;
		amf_record->traffic_load_reduction_pct = event->payload.overload.traffic_load_reduction_pct;
		amf_record->nssai_list_present = event->payload.overload.nssai_list_present;
	}
}

// on_overload_stop: AMF 과부하 종료. 과부하 내용을 비움
static void on_overload_stop(struct tr *tr, const struct obs_event *event)
{
	tr->n2_observed = 1;
	uint64_t amf_key = event->amf_id ? ((uint64_t)event->amf_id | (1ull << 40))
					 : ((uint64_t)event->assoc_id);
	struct tr_amf_record *amf_record = amf_lookup(tr, amf_key, 0);
	if (amf_record) {
		amf_record->state = AMF_NONE;
		amf_record->action_mask = 0;
		amf_record->has_action = 0;
		amf_record->traffic_load_reduction_pct = -1;
		amf_record->nssai_list_present = 0;
	}
}

// on_ng_setup: NG SETUP 성공으로 그 AMF 의 과부하 상태를 초기화함
static void on_ng_setup(struct tr *tr, const struct obs_event *event)
{
	tr->n2_observed = 1;
	if (event->payload.ng_setup.outcome_failure) return;
	uint64_t amf_key = event->amf_id ? ((uint64_t)event->amf_id | (1ull << 40))
					 : ((uint64_t)event->assoc_id);
	struct tr_amf_record *amf_record = amf_lookup(tr, amf_key, 1);
	if (amf_record) {
		amf_record->state = AMF_NONE;
		amf_record->action_mask = 0;
		amf_record->last_assoc = event->assoc_id;
		amf_record->has_action = 0;
		amf_record->traffic_load_reduction_pct = -1;
		amf_record->nssai_list_present = 0;
	}
}

/* on_nas: F1 또는 N2 에서 본 NAS 메시지 하나로 마지막 NAS 기록, NAS 보안 상태, 5GMM 상태를 갱신함.
 *   관측자이므로 전진 조건을 좁게 잡음 - 전달 실패한 하행, 형식 오류 PDU, 방향이 어긋난 보안 헤더는
 *     상태를 전진시키지 않음. 그 셋은 모두 공격자가 만들 수 있는 모양임.
 *   부작용: 표 I 의 마지막 NAS, NAS 보안 상태, 5GMM 주상태와 연결모드 갱신, 표 I 줄 방출 */
static void on_nas(struct tr *tr, const struct obs_event *event)
{
	if (event->iface == TR_IFACE_N2) tr->n2_observed = 1;
	struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
	if (!ue_record) return;
	/* NAS Non Delivery Indication 에 실린 NAS 는 기지국이 단말에 전달하지 못한 하행임 -> 단말은 받지
	 * 못했으므로 NAS 상태 기계를 전진시키면 안 됨. libobs 가 그 표시를 달아 줌. N2 관측 자체는
	 * 실재했으므로 위에서 이미 표시해 둠 */
	if (event->payload.nas.non_delivered) return;
	// libobs 가 유일한 F1 과 N2 매칭으로 교차 귀속한 N2 NAS 이므로 소멸을 관측할 수 있다는 신호임
	if (event->iface == TR_IFACE_N2 && event->quality == TR_QUALITY_CROSS)
		ue_record->has_n2_pair = 1;
	ue_record->last_nas_sht = event->payload.nas.sht;
	ue_record->last_nas_msg_type = event->payload.nas.msg_type;
	/* 마지막 NAS 기록은 '마지막으로 본 NAS 메시지' 임. 형식 오류 PDU 의 보안 헤더 니블은 공격자가 고른
	 * 바이트이므로 헤더에서 읽은 값은 담되(libnas 가 음수 반환에도 그 두 칸은 유효하다고 계약) 메시지를
	 * 봤다는 주장은 하지 않음 - 그 표시가 거짓이면 출력 등급이 미상으로 떨어짐. 아래에서 보안 상태를
	 * 막은 것과 같은 이유임. 못 읽은 수는 libobs 가 셈 */
	/* NAS 보안 모드 명령이 고른 암호 알고리즘. 그 메시지가 아닌 줄에서는 음수라 걸리지 않음.
	 * 종전엔 '이 메시지를 푼 알고리즘'(libobs 가 앞선 명령에서 학습해 둔 값)을 같은 칸에서 읽고
	 * 있었음 - 첫 명령에서는 학습 전이라 음수이고, 그 뒤 보호된 NAS 줄에서 뒤늦게 들어와 엉뚱한
	 * 메시지에 귀속됐음 */
	if (event->payload.nas.smc_ciph_alg >= 0)
		ue_record->nas_ciph_alg = event->payload.nas.smc_ciph_alg;
	// libnas 가 확장 프로토콜 판별자를 보안 헤더보다 먼저 세우므로 '헤더는 읽고 판별자는 못 읽음' 은 도달 불가임
	ue_record->last_nas_epd = event->payload.nas.epd;
	if (event->payload.nas.parse_ok) ue_record->has_last_nas = 1;
	// 교차 귀속이면 교차 등급, 평문이면 정확 등급임. 추론한 메시지 종류는 읽은 것이 아니라 구조 판정이므로 더 약한 쪽을 씀
	ue_record->nas_msg_quality = event->payload.nas.msg_type_inferred
				   ? ((event->quality > TR_QUALITY_STRUCT) ? event->quality
									   : TR_QUALITY_STRUCT)
				   : event->quality;
	// NAS 보안 상태는 보안 헤더 종류로만 유도함(암호 구간에서도 가능). 0 평문, 1/2 보호, 3 명령, 4 완료
	int nas_sec_state_before = ue_record->nas_sec_state;
	/* 전진 조건 둘을 여기서 한 칸으로 묶음.
	 *   형식 오류 PDU 의 보안 헤더 니블은 공격자가 고른 바이트임. AMF 도 버릴 메시지이므로 보안 상태를
	 *     전진시키지 않음. 종전엔 두 바이트가 보안 헤더 4 로 읽혀 NAS 보안 ACTIVE 를 평문 관측 등급
	 *     그대로 올렸음 - 확신 있는 오값임.
	 *   방향까지 맞아야 전진함. 보안 헤더 3 과 4 는 규격이 각각 한 방향뿐인 메시지에만 묶어 두었으므로
	 *     어긋난 조합은 조작으로만 생김 - 상행 3 을 받아 주면 단말이 자기 보안 상태를 명령 보냄으로,
	 *     하행 4 를 받아 주면 ACTIVE 로 올릴 수 있음. 방향 판정은 방향을 아는 libobs 가 하고 그쪽이 셈 */
	int sht_for_sec_state = (event->payload.nas.parse_ok && event->payload.nas.sec_header_direction_ok)
			      ? event->payload.nas.sht : -1;
	switch (sht_for_sec_state) {
	case 3:
		ue_record->nas_sec_state = TR_SEC_CMD_SENT;
		ue_record->nas_sec_quality = event->quality;
		break;
	case 4:
		ue_record->nas_sec_state = TR_SEC_ACTIVE;
		ue_record->nas_sec_quality = event->quality;
		break;
	case 1: case 2:   // 보호된 NAS 를 봤으면 보안은 활성임(구조 추론). 이미 활성이면 유지함
		/* 명령 보냄 상태에서도 올림 - 완료를 놓친 채 암호 트래픽만 보이면 상태가 멈춤. 종단 상태인
		 * 실패는 보존함. 교차 귀속이면 구조보다 강할 수 없으므로 둘 중 약한 등급을 씀 */
		if (ue_record->nas_sec_state != TR_SEC_ACTIVE
		    && ue_record->nas_sec_state != TR_SEC_FAILED) {
			ue_record->nas_sec_state = TR_SEC_ACTIVE;
			ue_record->nas_sec_quality = (event->quality > TR_QUALITY_STRUCT) ? event->quality
											 : TR_QUALITY_STRUCT;
		}
		break;
	case 0:   // 평문 NAS 는 보안 전이라는 뜻임. 이미 활성이면 되돌리지 않음
		if (ue_record->nas_sec_state == TR_SEC_UNKNOWN) {
			ue_record->nas_sec_state = TR_SEC_NONE;
			ue_record->nas_sec_quality = event->quality;
		}
		break;
	default:
		break;
	}
	// 5GMM 주상태와 연결모드. N2 NAS 는 교차 귀속으로 F1 단말에 붙음
	uint32_t changed_mask = TR_UE_F_NAS_MSG;
	/* NAS 보안 상태 전이도 변경 비트에 실음. 종전엔 그 비트가 AS 보안에서만 세워져 NAS 쪽 전이가
	 * 변경 목록에서 사라졌음. 비트 하나를 AS 와 NAS 가 함께 쓰는데, 나누는 것은 출력 형식 변경이라
	 * 지금 하지 않음 */
	if (ue_record->nas_sec_state != nas_sec_state_before) changed_mask |= TR_UE_F_SEC;
	if (event->iface == TR_IFACE_N2 && event->direction == TR_DIRECTION_DOWN
	    && ue_record->nas_conn_mode != TR_CM_MODE_CONNECTED) {
		ue_record->nas_conn_mode = TR_CM_MODE_CONNECTED;   // 첫 AMF 하행 NAS -> 연결모드 CONNECTED
		changed_mask |= TR_UE_F_NAS_STATE;
	}
	int nas_msg_type = event->payload.nas.msg_type, mm_cause = event->payload.nas.mm_cause,
	    nas_reg_state = -1;
	switch (nas_msg_type) {
	case NAS_MM_AUTH_REQUEST: case NAS_MM_IDENTITY_REQUEST: case NAS_MM_SECURITY_MODE_COMMAND:
		// 공통 절차 시작. 되돌아갈 출발 상태를 기억해 둠
		if (ue_record->nas_reg_state != TR_5GMM_COMMON_PROC_INIT)
			ue_record->nas_reg_state_origin = ue_record->nas_reg_state;
		nas_reg_state = TR_5GMM_COMMON_PROC_INIT; break;
	case NAS_MM_AUTH_RESPONSE: case NAS_MM_IDENTITY_RESPONSE: case NAS_MM_SECURITY_MODE_COMPLETE:
		/* 공통 절차 응답이면 출발 상태로 복귀함. 등록된 단말의 독립 공통 절차(재인증, 재키잉)는
		 * 등록 상태로 돌아가고, 초기 등록이면 등록 완료까지 공통 절차 상태를 유지함 */
		if (ue_record->nas_reg_state == TR_5GMM_COMMON_PROC_INIT
		    && ue_record->nas_reg_state_origin == TR_5GMM_REGISTERED)
			nas_reg_state = TR_5GMM_REGISTERED;
		break;
	case NAS_MM_SECURITY_MODE_REJECT:
	case NAS_MM_AUTH_REJECT:
		nas_reg_state = TR_5GMM_DEREGISTERED;
		break;
	case NAS_MM_REGISTRATION_ACCEPT:
		nas_reg_state = TR_5GMM_COMMON_PROC_INIT;
		break;   // 등록 완료를 기다리는 상태
	case NAS_MM_REGISTRATION_COMPLETE:
		nas_reg_state = TR_5GMM_REGISTERED;
		break;
	case NAS_MM_SERVICE_ACCEPT:
		nas_reg_state = TR_5GMM_REGISTERED;
		break;
	case NAS_MM_REGISTRATION_REQUEST:   // 5GS 등록 유형이 출발 상태를 가름(TS 24.501 §9.11.3.7)
		/* F1 쪽 on_setup_complete 과 같은 판정임. 한쪽에만 두면 등록 갱신이 N2 에서만 사라짐 -
		 * 암호가 없는 구간에서는 그 메시지를 읽을 수 있으므로 실제로 도달함.
		 * 등록 유형을 못 읽었으면 단정하지 않음(libobs 가 필수 IE 누락으로 이미 셌음) */
		if (event->payload.nas.reg_type >= 0)
			nas_reg_state = (event->payload.nas.reg_type == NAS_REG_MOBILITY
				      || event->payload.nas.reg_type == NAS_REG_PERIODIC
				      || event->payload.nas.reg_type == NAS_REG_DISASTER_MOBILITY)
				      ? TR_5GMM_REGISTERED : TR_5GMM_DEREGISTERED;
		break;
	case NAS_MM_SERVICE_REQUEST: case NAS_MM_CP_SERVICE_REQUEST:
		// 둘 다 5GMM-REGISTERED 단말만 보냄(TS 24.501 §5.6.1.1, §4.4.6)
		nas_reg_state = TR_5GMM_REGISTERED; break;
	case NAS_MM_REGISTRATION_REJECT: case NAS_MM_SERVICE_REJECT:
		// 초기 등록이었거나 원인이 불법 단말, 불법 기기, 5GS 불허면 등록 해제, 그 밖은 미상
		nas_reg_state = (ue_record->nas_reg_state == TR_5GMM_DEREGISTERED
			      || mm_cause == NAS_CAUSE_ILLEGAL_UE
			      || mm_cause == NAS_CAUSE_ILLEGAL_ME
			      || mm_cause == NAS_CAUSE_5GS_NOT_ALLOWED) ? TR_5GMM_DEREGISTERED
									: TR_5GMM_UNKNOWN; break;
	case NAS_MM_DEREG_REQ_UE_ORIG:
	case NAS_MM_DEREG_ACC_UE_ORIG:
	case NAS_MM_DEREG_ACC_UE_TERM:
		nas_reg_state = TR_5GMM_DEREGISTERED;
		break;
	case NAS_MM_DEREG_REQ_UE_TERM:
		nas_reg_state = TR_5GMM_DEREG_INITIATED;
		break;   // 망이 먼저 해제를 걸었으므로 응답을 기다림
	default:
		/* 형식은 정상이나 암호라 종류를 못 읽음 -> 미상. 보안 헤더만 보면 규격상 없는 조합(조작으로만
		 * 생기는 하행 완료)이 이 줄을 건너뛰어 옛 상태가 남으므로, 안쪽을 읽을 수 있었는지로 판정함.
		 * 잘리거나 깨진 PDU 는 캡처 손실이라 알려진 상태를 지우지 않음 */
		if (nas_msg_type < 0 && !event->payload.nas.inner_readable
		    && event->payload.nas.parse_ok) nas_reg_state = TR_5GMM_UNKNOWN;
		break;
	}
	if (nas_reg_state >= 0) {
		ue_record->nas_reg_state = nas_reg_state;
		/* 추론한 메시지 종류는 읽은 것이 아니라 구조 판정이므로 등급을 더 약한 쪽으로 깎음.
		 * 상태가 미상이면 근거가 없으므로 등급도 판정 불가임(위 초기 NAS 쪽과 같은 규칙) */
		ue_record->nas_state_quality = (nas_reg_state == TR_5GMM_UNKNOWN) ? TR_QUALITY_UNKNOWN
			: (event->payload.nas.msg_type_inferred
			   ? ((event->quality > TR_QUALITY_STRUCT) ? event->quality : TR_QUALITY_STRUCT)
			   : event->quality);
		changed_mask |= TR_UE_F_NAS_STATE;
	}
	emit_ue_line(tr, ue_record, event, changed_mask, 0);
}
// ---- 공개 API ----
/* tr_new: 집계 엔진 하나를 만듬.
 *   설정과 출력 함수 표는 값으로 복사하므로 부르는 쪽이 들고 있을 필요가 없음. user_ctx 는 그 표의
 *     콜백에 그대로 되돌려 주는 포인터이고 수명은 부르는 쪽이 책임짐.
 *   반환: 실패하면 NULL(할당 실패). 실패 시 해제할 것 없음 */
struct tr *tr_new(const struct tr_cfg *tr_cfg, const struct tr_sink_ops *sink_ops, void *user_ctx)
{
	struct tr *tr = calloc(1, sizeof *tr);
	if (!tr) return NULL;
	if (tr_cfg) tr->tr_cfg = *tr_cfg;
	if (sink_ops) tr->sink_ops = *sink_ops;
	tr->user_ctx = user_ctx;
	tr->overflow_cell_index = -1;
	// 자기 검사는 설정이나 환경변수 어느 쪽으로도 켤 수 있음
	tr->self_check = (tr_cfg && tr_cfg->self_check) || getenv("TR_SELF_CHECK") != NULL;
	if (hash_map_init(&tr->cell_map, 64) < 0 || hash_map_init(&tr->ue_map, 256) < 0 ||
		hash_map_init(&tr->setup_idx, 256) < 0 || hash_map_init(&tr->n2_map, 128) < 0 ||
		hash_map_init(&tr->amf_map, 16) < 0) {
		tr_free(tr); return NULL;
	}
	return tr;
}

// tr_advance: 이벤트 없이 시각만 밀어 주기 경계를 넘김. 조용한 구간에도 0건 주기가 나가게 함
void tr_advance(struct tr *tr, uint64_t now_ns)
{
	if (!tr) return;
	advance_to(tr, now_ns);
}

/* tr_on_event: 관측 이벤트 하나를 받아 해당 핸들러로 보냄.
 *   시각을 먼저 미는 이유: 부르는 쪽이 tr_advance 를 빼먹어도 주기 경계가 밀리게 함. 이미 밀었으면
 *     아무 일도 하지 않음.
 *   이미 닫힌 주기의 이벤트는 반영할 칸이 없으므로 버리고 그 수를 셈 - 버린 사실을 남기지 않으면
 *     "그런 이벤트가 없었다" 와 같은 모양이 됨.
 *   부작용: 주기 경계를 넘으면 그 주기를 방출함. 처리 뒤 자기 검사를 돌림 */
void tr_on_event(struct tr *tr, const struct obs_event *event)
{
	if (!tr || !event) return;
	advance_to(tr, event->wallclock_ns);
	if (event->wallclock_ns < tr->cur_start_ns) { tr->late_event_count++; return; }

	switch (event->kind) {
	case TR_EVENT_RRC_SETUP_REQUEST:
		on_setup_request(tr, event);
		break;
	case TR_EVENT_RRC_SETUP:
		on_rrc_setup(tr, event);
		break;
	case TR_EVENT_RRC_SETUP_COMPLETE:
		on_setup_complete(tr, event);
		break;
	case TR_EVENT_RRC_DCCH_OPAQUE:
		on_rrc_dcch_opaque(tr, event);
		break;   // 중간 합류 암호 SRB1 -> 미상 연결 모집단
	case TR_EVENT_RRC_REJECT:
		on_reject(tr, event);
		break;
	case TR_EVENT_RRC_REEST_REQUEST:
		on_reest_request(tr, event);
		break;
	case TR_EVENT_RRC_REEST:
		on_reest(tr, event);
		break;
	case TR_EVENT_RRC_REEST_COMPLETE:
		on_reest_complete(tr, event);
		break;
	case TR_EVENT_RRC_RESUME_REQUEST:
		on_resume_request(tr, event);
		break;
	case TR_EVENT_RRC_RESUME_COMPLETE:
		on_resume_complete(tr, event);
		break;
	case TR_EVENT_RRC_RELEASE:
		on_release(tr, event);
		break;
	case TR_EVENT_F1_UE_CTX_RELEASE_CMD:
		on_ctx_release_cmd(tr, event);
		break;
	case TR_EVENT_F1_UE_CTX_RELEASE_COMPLETE:
		on_ctx_release_complete(tr, event);
		break;
	case TR_EVENT_F1_INITIAL_UL:
		on_initial_ul(tr, event);
		break;
	case TR_EVENT_F1_UE_CTX_RELEASE_REQ:
		// DU 가 먼저 해제를 요청함. 열린 수립이 있으면 결과를 모르는 실패로 닫음
		{
			struct tr_ue_record *ue_record = ue_lookup(tr, &event->f1ue, 0, event->assoc_id);
			if (ue_record) close_setup_other(tr, ue_record);
		}
		break;
	case TR_EVENT_F1_RESET:
	case TR_EVENT_F1_SETUP:
		on_reset(tr, event);
		break;
	case TR_EVENT_SCTP_ASSOC_END:
		// AMF 레코드는 N2 연결로 색인되므로 N2 종료에서 회수함. F1 종료는 그 키와 맞지 않음
		if (event->iface == TR_IFACE_N2) {
			n2_remove(tr, event->assoc_id, event->n2ue.ran_ue_ngap_id);
			amf_drop_assoc(tr, event->assoc_id);
		}
		else on_assoc_end(tr, event);
		break;
	case TR_EVENT_OBS_UE_REPLACED:
		on_ue_replaced(tr, event);
		break;
	case TR_EVENT_OBS_UE_EVICTED:
		if (event->iface == TR_IFACE_N2)
			n2_remove(tr, event->assoc_id, event->n2ue.ran_ue_ngap_id);
		else on_ue_evicted(tr, event);
		break;
	case TR_EVENT_F1_UE_TRANSFER:
		on_ue_transfer(tr, event);
		break;
	case TR_EVENT_F1_CELL_CONFIG:
		on_cell_config(tr, event);
		break;
	case TR_EVENT_RRC_SMC:
	case TR_EVENT_RRC_RECONFIG_SEC:
		on_smc(tr, event);
		break;
	case TR_EVENT_RRC_SMC_COMPLETE:
	case TR_EVENT_RRC_SMC_FAILURE:
		on_smc_result(tr, event);
		break;   // AS 보안 상태 확정
	case TR_EVENT_F1_ALG_CHANGE_OPPORTUNITY:
		on_alg_opportunity(tr, event);
		break;
	case TR_EVENT_F1_UE_CTX_SETUP:
		on_ue_ctx_setup(tr, event);
		break;
	case TR_EVENT_NG_INITIAL_UE_MESSAGE:
		on_initial_ue_msg(tr, event);
		break;
	case TR_EVENT_NG_AMF_DL_UE_MSG:
		on_amf_dl(tr, event);
		break;
	case TR_EVENT_NG_UE_CTX_RELEASE_CMD:
		on_ng_release_cmd(tr, event);
		break;   // 해제 원인이 NAS 해제면 5GMM DEREGISTERED 로
	case TR_EVENT_NG_UE_CTX_RELEASE_COMPLETE:
		n2_remove(tr, event->assoc_id, event->n2ue.ran_ue_ngap_id);
		break;   // 실제 완료와 libobs 가 유예 만료로 합성한 것 둘 다 N2 레코드를 회수함
	case TR_EVENT_NG_RRC_STATE_REPORT:
		on_rrc_state_report(tr, event);
		break;   // INACTIVE 즉시 확정 + 전제 위반 경보
	case TR_EVENT_NG_OVERLOAD_START:
		on_overload_start(tr, event);
		break;
	case TR_EVENT_NG_OVERLOAD_STOP:
		on_overload_stop(tr, event);
		break;
	case TR_EVENT_NG_SETUP:
		on_ng_setup(tr, event);
		break;
	case TR_EVENT_NAS_F1:
	case TR_EVENT_NG_NAS:
		on_nas(tr, event);
		break;
	default:
		break;   // 그 밖(오류 표시 등)은 지금 지표에 쓰이지 않음
	}
	tr_self_check(tr);   // 게이지, 소속, 열린 수립 목록이 정합한지 검사(시험과 새니타이저 빌드에서만)
}

/* period_has_content: 지금 열려 있는 주기에 표 II 로 방출할 내용이 있는가.
 *   내용의 정의: close_period 가 주기마다 리셋하는 누적 중 실제 수치가 비어 있지 않은 것. 카운터와
 *     그 제외, 중첩, 경로 분해, 표본 수, 반쯤 열림 합, 엔진 수준의 늦은 이벤트와 축출 수가 여기 듦.
 *     순수 상태 플래그는 내용이 아니므로 뺌.
 *   이 집합은 close_period 의 리셋 집합을 그대로 비춤 - 누적을 하나 추가하면 양쪽을 같이 고칠 것.
 *     한쪽만 고치면 그 값이 유일한 내용인 주기가 조용히 사라짐.
 *   반환: 내용이 있으면 1, 없으면 0 */
static int period_has_content(const struct tr *tr)
{
	if (tr->late_event_count || tr->lost_evicted_count) return 1;
	/* 전제 위반 경보와 해제 근거 수도 보고 헤더에 실리는 내용임. 이들이 유일한 내용인 주기 -
	 * suspendConfig 를 본 해제만 있었던 주기처럼 카운터가 하나도 오르지 않은 경우 - 가 종전엔
	 * 조용히 드롭돼 '깨끗한 주기' 로 보였음 */
	if (tr->inactive_alarm_count || tr->release_basis_observed_count
	    || tr->release_basis_assumed_count) return 1;
	/* 탭 전체의 커버리지 증가분도 내용임. 종전엔 늦은 이벤트, 축출, 셀 카운터와 표본만 봐서
	 * tr_finish 의 길이 0 최종 주기가 TSN 공백, 링 버퍼 포화, ESP, IP 조각, 관측자 내부 유실을
	 * 조용히 드롭했음. emit_coverage_only_period 의 손실 관문과 같은 집합으로 맞춤 */
	#define COVERAGE_DELTA(cur, snap) ((cur) >= (snap) ? (cur) - (snap) : 0)
	int has_coverage =
		COVERAGE_DELTA(tr->coverage_tsn_gap_count, tr->coverage_snapshot_tsn_gap_count) ||
		COVERAGE_DELTA(tr->coverage_ringbuf_full_count, tr->coverage_snapshot_ringbuf_full_count) ||
		COVERAGE_DELTA(tr->coverage_esp_seen_count, tr->coverage_snapshot_esp_seen_count) ||
		COVERAGE_DELTA(tr->coverage_ip_frag_skipped_count, tr->coverage_snapshot_ip_frag_skipped_count) ||
		COVERAGE_DELTA(tr->coverage_obs_lost_count, tr->coverage_snapshot_obs_lost_count);
	#undef COVERAGE_DELTA
	if (has_coverage) return 1;
	for (uint32_t i = 0; i < tr->cell_count; i++) {
		const struct tr_cell_record *cell_record = &tr->cell_records[i];
		if (cell_record->conn_sample_count || cell_record->inactive_sample_count
		    || cell_record->half_open_sum) return 1;
		for (int metric_index = 0; metric_index < TR_METRIC__COUNT; metric_index++) {
			if (cell_record->cc_unknown_nocause[metric_index]) return 1;
			for (int path_index = 0; path_index < PATH__COUNT; path_index++)
				if (cell_record->path_value[metric_index][path_index]) return 1;
			for (int cause_index = 0; cause_index < MAX_CAUSE; cause_index++) {
				if (cell_record->cc_value[metric_index][cause_index]
				    || cell_record->cc_unknown[metric_index][cause_index]) return 1;
				for (int excl_index = 0; excl_index < TR_EXCLUDED__COUNT; excl_index++)
					if (cell_record->cc_excluded[metric_index][excl_index][cause_index]) return 1;
				for (int overlap_index = 0; overlap_index < TR_OVERLAP__COUNT; overlap_index++)
					if (cell_record->cc_overlap[metric_index][cause_index][overlap_index]) return 1;
			}
		}
	}
	return 0;
}

/* tr_finish: 마지막 주기를 닫고 방출함.
 *   끝 시각이 주기 경계에 정확히 떨어지면 advance_to 가 그 주기를 닫고 길이 0 인 주기로 넘어감.
 *     그 주기가 비었으면 방출이 잡음이라 생략하되, 끝 시각에 기록된 이벤트가 있으면 유실 없이
 *     방출해야 함. 길이가 있는 빈 주기는 늘 유지함 - 시도 0 과 커버리지도 뜻이 있는 값임.
 *   부작용: 마지막 주기를 부분 주기로 표시해 방출함. 종료 상태 자기 검사를 돌림 */
void tr_finish(struct tr *tr, uint64_t end_ns)
{
	if (!tr) return;
	advance_to(tr, end_ns);
	if (tr->started && (tr->cur_start_ns < end_ns ||
					   (tr->cur_start_ns == end_ns && period_has_content(tr))))
		close_period(tr, 1);
	tr_self_check(tr);
}

/* tr_set_capture_alive: 캡처가 살아 있다고 확인된 시각을 올림.
 *   값을 내리지 않는 이유: 보고 헤더의 '캡처 확인' 은 '적어도 이 시각까지는 살아 있었다' 는 뜻이라
 *     단조 증가여야 함 */
void tr_set_capture_alive(struct tr *tr, uint64_t capture_alive_until_ns)
{
	if (!tr) return;
	if (capture_alive_until_ns > tr->capture_alive_until_ns) tr->capture_alive_until_ns = capture_alive_until_ns;
}

/* tr_set_coverage: 캡처 쪽 누적 카운터 넷을 받아 저장함. 주기를 닫을 때 증가분으로 헤더에 실림.
 *   역행을 경고하는 이유: 누적 카운터는 한 번 돌리는 동안 단조 증가여야 함. 역행은 탭 재부착이나
 *     커널 카운터 리셋을 뜻하고, 그때 증가분 계산이 그 주기를 0 으로 묶음. 0 으로 묶는 것은 '그
 *     구간의 유실이 없었다' 로 읽히므로 맹점을 숨기지 않도록 한 번 경고를 올림 */
void tr_set_coverage(struct tr *tr, uint64_t coverage_tsn_gap_count, uint64_t coverage_ringbuf_full_count,
					 uint64_t coverage_esp_seen_count, uint64_t coverage_ip_frag_skipped_count)
{
	if (!tr) return;
	if (!tr->warned_coverage_reset &&
	    (coverage_tsn_gap_count < tr->coverage_tsn_gap_count ||
	     coverage_ringbuf_full_count < tr->coverage_ringbuf_full_count ||
	     coverage_esp_seen_count < tr->coverage_esp_seen_count ||
	     coverage_ip_frag_skipped_count < tr->coverage_ip_frag_skipped_count)) {
		warn(tr, "coverage_reset", "coverage counter decreased (tap reattach/counter reset); period delta clamped to 0");
		tr->warned_coverage_reset = 1;
	}
	tr->coverage_tsn_gap_count = coverage_tsn_gap_count;
	tr->coverage_ringbuf_full_count = coverage_ringbuf_full_count;
	tr->coverage_esp_seen_count = coverage_esp_seen_count;
	tr->coverage_ip_frag_skipped_count = coverage_ip_frag_skipped_count;
}

// tr_set_obs_coverage: 관측자 내부 유실 누적을 저장함. 주기를 닫을 때 증가분으로 헤더에 실림
void tr_set_obs_coverage(struct tr *tr, uint64_t coverage_obs_lost_count)
{
	if (!tr) return;
	tr->coverage_obs_lost_count = coverage_obs_lost_count;
}

/* tr_period_pending_close: 지금 tr_advance 를 부르면 주기가 닫히는가.
 *   이유: 부르는 쪽이 주기가 닫히기 직전에만 커버리지를 갱신하게 해, 라이브 경로에서 레코드마다
 *     커널 카운터를 조회하는 비용을 없앰. 증가분은 누적과 스냅샷의 차이로 계산하므로 그 주기 전체의
 *     손실은 그대로 잡힘.
 *   반환: 아직 시작하지 않았으면 거짓(첫 레코드는 엔진을 시작하기만 함) */
bool tr_period_pending_close(const struct tr *tr, uint64_t now_ns)
{
	return tr && tr->started && now_ns >= tr->cur_end_ns;
}

// tr_free: 엔진과 그 안의 모든 배열을 해제함. NULL 이어도 안전함
void tr_free(struct tr *tr)
{
	if (!tr) return;
	hash_map_free(&tr->cell_map); hash_map_free(&tr->ue_map); hash_map_free(&tr->setup_idx);
	hash_map_free(&tr->n2_map); hash_map_free(&tr->amf_map);
	free(tr->cell_records); free(tr->ue_records); free(tr->n2_records);
	free(tr->amf_records); free(tr->open_list);
	free(tr);
}
