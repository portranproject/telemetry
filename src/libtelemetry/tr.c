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
		warn(tr, "overflow_cell", "max_cell_count exceeded; new cells merged");
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
	uint32_t limit = tr->tr_cfg.max_cell_count ? tr->tr_cfg.max_cell_count : DEF_MAX_CELL_COUNT;
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
static uint32_t applied_setup_outcome_timeout_ms(const struct tr *tr)
{
	return tr->tr_cfg.setup_outcome_timeout_ms ? tr->tr_cfg.setup_outcome_timeout_ms
						    : TR_DEF_SETUP_OUTCOME_TIMEOUT_MS;
}

/* setup_recompute_deadline: 열린 수립 하나의 마감을 다시 잡음.
 *   구간이 둘이라 값도 둘임(tr.h 가 두 구간을 표로 적어 둠). Msg4 를 봤으면 그 시각부터 무응답
 *   대기이고, 못 봤으면 Msg3 시각부터 결과를 못 봤다고 포기하는 창임. 한 값으로 묶으면 둘 중 하나가 틀림 */
static void setup_recompute_deadline(struct tr *tr, struct tr_ue_record *ue_record)
{
	uint64_t base_ns = ue_record->saw_setup_sent ? ue_record->setup_sent_time_ns : ue_record->request_time_ns;
	uint32_t timeout_ms = ue_record->saw_setup_sent ? applied_noreply_timeout_ms(tr)
							: applied_setup_outcome_timeout_ms(tr);
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
	uint64_t conn_period_ns = (uint64_t)(tr->tr_cfg.conn_sample_period_ms ? tr->tr_cfg.conn_sample_period_ms
									 : DEF_CONN_SAMPLE_PERIOD_MS) * 1000000ull;
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
	uint64_t conn_period_ns = (uint64_t)(tr->tr_cfg.conn_sample_period_ms ? tr->tr_cfg.conn_sample_period_ms
									 : DEF_CONN_SAMPLE_PERIOD_MS) * 1000000ull;
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

