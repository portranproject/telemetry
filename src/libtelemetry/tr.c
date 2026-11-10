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

