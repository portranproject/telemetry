#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libcap/cap.h"
#include "sctp.h"

// MARK: - 상수

// TSN 하나당 1비트. 재전송은 최근 TSN 에서 오므로 이 범위면 중복을 가려냄. uint64_t 배열이라 64 의 배수여야 함
#define TSN_WINDOW_BITS 4096
// window_bits 한 칸(uint64_t)의 비트 수. 창 안 위치를 (몇 번째 칸, 칸 안 몇 번째 비트)로 바꿀 때 씀
#define TSN_WINDOW_WORD_BITS 64
// 창을 밀 때 꼭 필요한 만큼에 더해 더 미는 비트 수(창의 1/4). 여유 없이 밀면 순서대로 오는 새 TSN 마다 창을 다시 밀어야 함
#define TSN_SHIFT_SLACK_BITS (TSN_WINDOW_BITS / 4)

// 방향 표 칸 수. 주소·포트를 바꿔 가며 주입해도 메모리·탐색 시간이 이 상한에 묶이도록. 정상 배치는 방향이 몇 개뿐
#define DIRECTION_MAX_COUNT 2048
// 연결 표 칸 수.
#define ASSOC_MAX_COUNT 2048

// 한 방향에 보관하는 미완성 조각의 바이트 합 상한(1 MiB). B 조각만 계속 보내는 입력이 메모리를 끝없이 잡지 않도록
#define FRAGMENT_MAX_BYTES (1024u * 1024u)
// 한 방향에 보관하는 미완성 조각의 개수 상한. 아주 작은 조각을 많이 보내 목록 탐색이 길어지지 않도록
#define FRAGMENT_MAX_COUNT 1024
// 조각을 기다리는 최대 시간(5초). 유실된 조각(캡처 누락 포함)을 무한정 기다리며 메모리를 잡지 않도록
#define FRAGMENT_TIMEOUT_NS (5ull * 1000000000ull)

// SCTP 공통 헤더 길이(포트·vtag·체크섬), 첫 청크는 이 뒤에서 시작
#define SCTP_COMMON_HEADER_BYTES 12

// 청크 헤더 길이: 타입 1 + 플래그 1 + 길이 2
#define CHUNK_HEADER_BYTES 4
// 청크는 이 크기의 배수로 패딩. 다음 청크는 패딩 뒤에서 시작
#define CHUNK_ALIGN_BYTES 4

// DATA 청크 헤더 길이: 청크 헤더 4 + TSN 4 + 스트림 2 + SSN 2 + PPID 4. 사용자 데이터는 이 뒤에서 시작
#define DATA_CHUNK_HEADER_BYTES 16
#define DATA_FLAG_END 0x01   // DATA 청크 E 비트: 메시지의 마지막 조각
#define DATA_FLAG_BEGIN 0x02 // DATA 청크 B 비트: 메시지의 첫 조각
// DATA 청크 U 비트: 순서 무관 메시지. 이때 SSN 은 의미가 없어 같은 메시지의 조각인지 가를 때 비교하지 않음
#define DATA_FLAG_UNORDERED 0x04

// INIT·INIT-ACK 청크의 고정 부분 길이: 청크 헤더 4 + Initiate Tag 4 + a_rwnd 4 + 스트림 수 2·2 + Initial TSN 4
// 이보다 짧으면 Initial TSN 을 읽을 수 없음
#define INIT_CHUNK_MIN_BYTES 20

// ABORT·SHUTDOWN COMPLETE 청크 T 비트: vtag 가 보낸 쪽 자기 값이 아니라, 받은 패킷의 vtag 를 되돌려 쓴 값이라는 뜻
#define ABORT_FLAG_T 0x01
// 기대와 다른 같은 vtag 가 이만큼 이어지면 연결 재시작으로 받아들임. 위조 패킷 하나로는 연결 상태가 바뀌지 않게 2
#define VTAG_RESTART_CONFIRM_COUNT 2

// MARK: - 청크 종류·바이트 읽기

// sctp_chunk_type: 청크 헤더 첫 바이트의 청크 종류 번호 (RFC 9260 §3.2).
//   libsctp 가 처리하는 종류만 둠. 여기 없는 번호(SACK, HEARTBEAT, COOKIE 등)는 무시.
//   패킷에서 읽은 바이트에는 여기 없는 값도 들어오므로, 읽은 값은 uint8_t 로 두고 이 값들과 비교만 함
enum sctp_chunk_type {
    CHUNK_TYPE_DATA = 0,               // 사용자 데이터(F1AP/NGAP 메시지)
    CHUNK_TYPE_INIT = 1,               // 연결 시작 요청. Initiate Tag·Initial TSN 을 담음
    CHUNK_TYPE_INIT_ACK = 2,           // 연결 시작 응답. INIT 과 같은 값을 담음
    CHUNK_TYPE_ABORT = 6,              // 연결 강제 종료
    CHUNK_TYPE_SHUTDOWN_COMPLETE = 14, // 정상 종료 완료
};

/* read_be16: ptr 위치의 2바이트를 빅엔디안(네트워크 순서) 정수로
 *   호출한 쪽이 ptr 부터 2바이트가 캡처 범위 안인지 먼저 확인 필요
 */
static inline uint16_t read_be16(const uint8_t *ptr) {
    return (uint16_t)(((uint16_t)ptr[0] << 8) | (uint16_t)ptr[1]);
}

/* read_be32: ptr 위치의 4바이트를 빅엔디안(네트워크 순서) 정수로
 *   호출한 쪽이 ptr 부터 4바이트가 캡처 범위 안인지 먼저 확인 필요
 */
static inline uint32_t read_be32(const uint8_t *ptr) {
    return ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) | ((uint32_t)ptr[2] << 8) | (uint32_t)ptr[3];
}

// MARK: - 자료구조

// fragment: 아직 메시지를 완성하지 못한 DATA 조각 하나(SCTP 메시지 단편).
// 패킷 버퍼는 sctp_input 이 끝나면 사라지므로 바이트 복사
struct fragment {
    struct fragment *next;     // 목록의 다음 조각. 목록은 TSN 이 작은 것부터 순서대로라, 같은 메시지의 조각이 나란히 있음
    uint64_t received_time_ns; // 오래 못 채운 조각을 버리는 기준
    uint32_t tsn;              // 연속 판정
    uint32_t ppid;             // 첫 조각(B)의 값을 메시지 PPID 로 씀
    uint16_t stream_id;
    uint16_t ssn;
    uint8_t flags; // DATA 청크의 B·E·U 비트. 메시지 시작·끝, 순서 무관 여부
    size_t len;
    uint8_t data[]; // 조각의 사용자 데이터 복사본
};

// reassembly_queue: 한 방향의 미완성 조각 목록. 메모리 상한을 지키기 위함
struct reassembly_queue {
    struct fragment *head;
    size_t total_bytes;
    uint32_t fragment_count;
};

// tsn_space: 한 방향의 TSN 중복 판정 창. 재전송된 DATA 를 걸러 같은 메시지를 두 번 넘기지 않기 위함
struct tsn_space {
    bool has_base;                                                // false = 아직 이 방향의 TSN 을 본 적 없음(캡처 도중 합류 포함)
    uint32_t base_tsn;                                            // window_bits 의 비트 0 에 해당하는 TSN
    uint64_t window_bits[TSN_WINDOW_BITS / TSN_WINDOW_WORD_BITS]; // 본 TSN 이면 1
    bool has_seen_range;                                          // 아래 두 값이 유효한지
    uint32_t lowest_seen_tsn;                                     // 이 방향에서 본 가장 앞 TSN
    uint32_t highest_seen_tsn;                                    // 이 방향에서 본 가장 뒤 TSN
};

// vtag_state: 한 방향의 vtag 검사 상태. 다른 연결의 패킷이나 위조 패킷을 걸러내기 위함 (RFC 9260 §8.5)
struct vtag_state {
    bool has_expected;      // false = 아직 기대 vtag 를 모름(검사하지 않음)
    uint32_t expected_vtag; // 이 방향 패킷이 가져야 할 vtag
    uint32_t pending_vtag;  // INIT 을 못 본 채 바뀐 vtag 후보. 재시작인지 확인하는 동안 보관
    uint32_t pending_count; // pending_vtag 가 연속으로 나온 패킷 수
};

// sctp_direction: 한 방향(보내는 끝 → 받는 끝). TSN·조각·vtag 는 방향마다 따로 흘러가므로 방향 단위로 둠
struct sctp_direction {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    struct tsn_space tsn;
    struct reassembly_queue fragments;
    struct vtag_state vtag;
};

// sctp_assoc_record: 한 연결(양방향 공통). 두 방향의 메시지에 같은 연결 번호를 붙이기 위함
//   두 끝을 (주소, 포트) 사전순으로 정렬해 저장하므로 A→B 와 B→A 패킷이 같은 레코드를 찾음.
//   비교는 저장된 값 그대로 함(바이트 순서와 무관하게 양방향에서 같은 결과만 나오면 됨).
struct sctp_assoc_record {
    uint32_t low_addr; // (주소, 포트)가 작은 쪽 끝
    uint16_t low_port;
    uint32_t high_addr; // (주소, 포트)가 큰 쪽 끝
    uint16_t high_port;
    uint32_t assoc_id; // 0 = 아직 번호 없음. INIT·재시작마다 새 번호
};

// raw_chunk: 청크 하나의 헤더 값과 바이트(종류별로 해석하기 전). 청크 종류별 처리 함수에 하나의 개념으로 넘기기 위함
struct raw_chunk {
    const uint8_t *bytes; // 청크 헤더 첫 바이트. 패킷 버퍼 안을 가리킴(호출한 쪽 소유, 복사 아님)
    uint8_t type;         // 청크 종류(enum sctp_chunk_type)
    uint8_t flags;        // 뜻은 종류마다 다름(DATA 는 B·E·U 비트)
    uint16_t len;         // 청크 헤더를 포함한 길이, 패딩 제외. CHUNK_HEADER_BYTES 이상임을 확인한 값
    bool is_partial;      // 청크 끝이 캡처 범위 밖. true 면 bytes 에서 len 만큼 읽으면 안 됨
};

// data_chunk: DATA 청크 하나에서 읽은 값 청크를 읽는 곳과 쓰는 곳 사이에 하나의 개념으로 넘기기 위함
struct data_chunk {
    uint32_t tsn;
    uint32_t ppid;
    uint16_t stream_id;
    uint16_t ssn;
    uint8_t flags;       // B·E·U 비트
    const uint8_t *data; // 사용자 데이터. 패킷 버퍼 안을 가리킴(호출한 쪽 소유, 복사 아님)
    size_t len;          // data 의 바이트 수
};

// sctp_ctx: libsctp 전체 상태(sctp.h 에서는 이름만 공개). sctp_new 가 만들고 sctp_free 가 해제.
// 방향, 연결 표는 상한만큼 sctp_new 에서 한 번에 할당. 표가 자라며 옮겨지지 않으므로 레코드 포인터가 바뀌지 않음.
struct sctp_ctx {
    sctp_message_callback on_message; // 완성된 메시지를 넘길 함수(NULL 이면 넘기지 않음)
    sctp_assoc_callback on_assoc;     // 연결 시작·끝을 알릴 함수(NULL 이면 알리지 않음)
    void *user;                       // 콜백 첫 인자로 그대로 돌려줄 포인터(호출한 쪽 소유)
    struct sctp_stats stats;

    struct sctp_direction *directions; // 방향 표
    size_t direction_count;
    size_t direction_clock; // 표가 꽉 찼을 때 다음에 밀어낼 칸.

    uint8_t *reassembly_buf;     // 조각을 이어 붙일 버퍼. 메시지마다 할당하지 않으려고 재사용
    size_t reassembly_buf_bytes; // reassembly_buf 에 할당된 크기

    struct sctp_assoc_record *assocs; // 연결 표
    size_t assoc_count;
    size_t assoc_clock;     // 표가 꽉 찼을 때 다음에 밀어낼 칸
    uint32_t next_assoc_id; // 다음에 매길 연결 번호. 0 은 '연결 없음' 이라 1부터
};

// MARK: - 생성·해제·통계

/* fragments_clear: 조각 목록의 조각을 모두 해제하고 목록을 비움.
 *   이유: 방향을 해제·초기화·재사용할 때 남은 조각을 한꺼번에 반납해야 누수가 없음.
 */
static void fragments_clear(struct reassembly_queue *queue) {
    struct fragment *fragment = queue->head;
    while (fragment) {
        struct fragment *next = fragment->next;
        free(fragment);
        fragment = next;
    }
    queue->head = NULL;
    queue->total_bytes = 0;
    queue->fragment_count = 0;
}

/* sctp_new: libsctp 상태를 만듦.
 *   이유: 방향·연결 표를 상한만큼 여기서 한 번에 잡아, 처리 중에 표가 옮겨지거나 할당에 실패하는 일을 없앰.
 *   반환: 새 상태. 하나라도 할당에 실패하면 이미 잡은 것을 해제하고 NULL.
 *   user 는 호출한 쪽 소유. 보관했다가 콜백 첫 인자로 넘기기만 함.
 */
struct sctp_ctx *sctp_new(sctp_message_callback on_message, sctp_assoc_callback on_assoc, void *user) {
    struct sctp_ctx *ctx = calloc(1, sizeof(*ctx)); // 통계 포함 전부 0
    if (!ctx)
        return NULL;

    ctx->directions = calloc(DIRECTION_MAX_COUNT, sizeof(*ctx->directions));
    ctx->assocs = calloc(ASSOC_MAX_COUNT, sizeof(*ctx->assocs));
    if (!ctx->directions || !ctx->assocs) {
        free(ctx->directions); // 둘 중 하나는 NULL 일 수 있음. free(NULL) 은 아무것도 하지 않음
        free(ctx->assocs);
        free(ctx);
        return NULL;
    }

    ctx->on_message = on_message;
    ctx->on_assoc = on_assoc;
    ctx->user = user;
    ctx->next_assoc_id = 1;
    return ctx;
}

/* sctp_free: 모든 방향의 남은 조각, 방향·연결 표, 재조립 버퍼, 상태 자신을 해제
 *   ctx 가 NULL 이면 아무것도 하지 않음.
 */
void sctp_free(struct sctp_ctx *ctx) {
    if (!ctx)
        return;

    for (size_t i = 0; i < ctx->direction_count; i++)
        fragments_clear(&ctx->directions[i].fragments);
    free(ctx->directions);
    free(ctx->assocs);
    free(ctx->reassembly_buf);
    free(ctx);
}

// sctp_get_stats: 누적 통계의 주소. ctx 가 해제되기 전까지 유효. ctx 는 NULL 이면 안 됨.
const struct sctp_stats *sctp_get_stats(const struct sctp_ctx *ctx) {
    return &ctx->stats;
}

// MARK: - 콜백 전달

/* deliver_message: 완성된 메시지 하나를 on_message 콜백으로 넘김.
 *   이유: 메시지를 내보내는 곳을 한 군데로 모아, 콜백이 없을 때의 처리와 메시지 수 세기를 한 번만 씀.
 *   콜백이 NULL 이어도 message_count 는 셈(통계가 콜백 등록 여부와 무관해야 비교할 수 있음).
 *   message 와 그 안의 포인터는 콜백이 돌아오면 무효.
 */
static void deliver_message(struct sctp_ctx *ctx, const struct sctp_message *message) {
    ctx->stats.message_count++;
    if (ctx->on_message)
        ctx->on_message(ctx->user, message);
}

/* notify_assoc: 연결 시작·끝을 on_assoc 콜백으로 알림.
 *   이유: 알림을 내보내는 곳을 한 군데로 모아, 콜백이 없을 때의 처리를 한 번만 씀.
 *   알림 구조체와 그 안의 포인터는 콜백이 돌아오면 무효.
 *   함께 바뀌는 것: on_assoc 호출.
 */
static void notify_assoc(struct sctp_ctx *ctx, const struct cap_record *record, uint32_t assoc_id, enum sctp_assoc_kind kind) {
    if (!ctx->on_assoc)
        return;

    struct sctp_assoc_event event = {
        .record = record,
        .assoc_id = assoc_id,
        .kind = kind,
    };
    ctx->on_assoc(ctx->user, &event);
}

// MARK: - 방향·연결 찾기

// direction_side: direction_get 이 패킷과 같은 방향을 찾을지, 반대 방향을 찾을지
enum direction_side {
    DIRECTION_FORWARD, // 패킷과 같은 방향(출발 → 도착)
    DIRECTION_REVERSE, // 반대 방향(도착 → 출발). 연결이 새로 시작될 때 상대 쪽 방향의 상태도 비우려고
};

/* direction_get: 패킷의 방향(출발 → 도착) 레코드, 또는 그 반대 방향 레코드를 방향 표에서 찾고, 없으면 새로 만듦.
 *   이유: TSN 창·조각·vtag 는 방향마다 따로 흘러가므로, 패킷마다 자기 방향의 상태를 찾아 써야 함.
 *   키는 패킷의 (출발 주소, 도착 주소, 출발 포트, 도착 포트). DIRECTION_REVERSE 면 출발과 도착을 바꾼 키로 찾음.
 *   표가 꽉 차면 direction_clock 이 가리키는 칸을 비워 재사용하고 다음 칸으로 넘김. 끝난 연결의 칸은 지우지 않아
 *   재연결이 쌓이면 표가 차는데, 그때도 새 연결을 처리하기 위함. 그 칸이 keep 이면 다음 칸을 씀(호출한 쪽이 지금 들고
 *   있는 레코드를 지키려고. 지킬 것이 없으면 NULL).
 *   반환: 방향 레코드(표 안을 가리킴, sctp_free 전까지 주소가 바뀌지 않음). NULL 은 돌려주지 않음.
 *   함께 바뀌는 것: 새로 만들면 ctx 의 direction_count, 밀어내면 direction_clock·direction_evicted_count 와 밀려난 칸의 조각 해제.
 */
static struct sctp_direction *direction_get(struct sctp_ctx *ctx, const struct cap_record *record, enum direction_side side,
                                            const struct sctp_direction *keep) {
    uint32_t src_addr = record->src_addr;
    uint32_t dst_addr = record->dst_addr;
    uint16_t src_port = record->src_port;
    uint16_t dst_port = record->dst_port;
    if (side == DIRECTION_REVERSE) {
        src_addr = record->dst_addr;
        dst_addr = record->src_addr;
        src_port = record->dst_port;
        dst_port = record->src_port;
    }

    for (size_t i = 0; i < ctx->direction_count; i++) {
        struct sctp_direction *direction = &ctx->directions[i];
        bool is_same_direction = direction->src_addr == src_addr
                              && direction->dst_addr == dst_addr
                              && direction->src_port == src_port
                              && direction->dst_port == dst_port;
        if (is_same_direction)
            return direction;
    }

    struct sctp_direction *direction;
    if (ctx->direction_count < DIRECTION_MAX_COUNT) {
        direction = &ctx->directions[ctx->direction_count];
        ctx->direction_count++;
    } else {
        bool is_keep_slot = &ctx->directions[ctx->direction_clock] == keep;
        if (is_keep_slot)
            ctx->direction_clock = (ctx->direction_clock + 1) % ctx->direction_count;
        direction = &ctx->directions[ctx->direction_clock];
        ctx->direction_clock = (ctx->direction_clock + 1) % ctx->direction_count;
        fragments_clear(&direction->fragments); // 밀려난 방향의 조각 메모리 반납
        ctx->stats.direction_evicted_count++;
    }

    // 키만 넣고 나머지(TSN 창·조각·vtag)는 0 으로 시작함. 0 은 "아직 본 것 없음"을 뜻함
    *direction = (struct sctp_direction){
        .src_addr = src_addr,
        .dst_addr = dst_addr,
        .src_port = src_port,
        .dst_port = dst_port,
    };
    return direction;
}

// assoc_id_mode: assoc_id_assign 이 지금 번호를 쓸지, 새 번호를 매길지
enum assoc_id_mode {
    ASSOC_ID_CURRENT, // 이미 번호가 있으면 그 번호. 없으면 새로 매김
    ASSOC_ID_NEW,     // 번호가 있어도 새로 매김. 같은 주소·포트로 연결이 새로 시작됐을 때(INIT, 재시작)
};

/* assoc_id_assign: 패킷이 속한 연결(양방향 공통)을 연결 표에서 찾거나 만들고, 그 연결 번호를 돌려줌.
 *   이유: 탐지 쪽이 두 방향의 메시지를 같은 연결로 묶어 보려면, 메시지마다 연결 번호가 붙어야 함.
 *   표가 꽉 차면 assoc_clock 이 가리키는 칸을 비워 재사용하고 다음 칸으로 넘김(direction_get 과 같은 이유).
 *   밀려난 연결의 패킷이 다시 오면 새 레코드에 새 번호를 받음. 연결 레코드는 포인터로 들고 있는 곳이 없어 keep 이 필요 없음.
 *   반환: 연결 번호(1 부터). 0 은 돌려주지 않음.
 *   함께 바뀌는 것: 새로 만들면 ctx 의 assoc_count, 밀어내면 assoc_clock·assoc_evicted_count, 번호를 매기면 next_assoc_id.
 */
static uint32_t assoc_id_assign(struct sctp_ctx *ctx, const struct cap_record *record, enum assoc_id_mode mode) {
    // 출발 끝을 low 로 두고, 도착 끝이 더 작으면 바꿈
    uint32_t low_addr = record->src_addr;
    uint16_t low_port = record->src_port;
    uint32_t high_addr = record->dst_addr;
    uint16_t high_port = record->dst_port;
    bool is_dst_lower = record->dst_addr < record->src_addr
                     || (record->dst_addr == record->src_addr && record->dst_port < record->src_port);
    if (is_dst_lower) {
        low_addr = record->dst_addr;
        low_port = record->dst_port;
        high_addr = record->src_addr;
        high_port = record->src_port;
    }

    struct sctp_assoc_record *assoc = NULL;
    for (size_t i = 0; i < ctx->assoc_count; i++) {
        struct sctp_assoc_record *candidate = &ctx->assocs[i];
        bool is_same_assoc = candidate->low_addr == low_addr
                          && candidate->low_port == low_port
                          && candidate->high_addr == high_addr
                          && candidate->high_port == high_port;
        if (is_same_assoc) {
            assoc = candidate;
            break;
        }
    }

    if (!assoc) {
        if (ctx->assoc_count < ASSOC_MAX_COUNT) {
            assoc = &ctx->assocs[ctx->assoc_count];
            ctx->assoc_count++;
        } else {
            assoc = &ctx->assocs[ctx->assoc_clock];
            ctx->assoc_clock = (ctx->assoc_clock + 1) % ctx->assoc_count;
            ctx->stats.assoc_evicted_count++;
        }
        *assoc = (struct sctp_assoc_record){
            .low_addr = low_addr,
            .low_port = low_port,
            .high_addr = high_addr,
            .high_port = high_port,
        }; // assoc_id 는 0(아직 번호 없음)으로 시작
    }

    if (assoc->assoc_id == 0 || mode == ASSOC_ID_NEW) {
        assoc->assoc_id = ctx->next_assoc_id;
        ctx->next_assoc_id++;
        if (ctx->next_assoc_id == 0)
            ctx->next_assoc_id = 1; // 2^32 번 매겨 0 으로 돌아오면 건너뜀. 0 은 "연결 번호 없음"
    }
    return assoc->assoc_id;
}

// MARK: - TSN 판정

/* tsn_window_shift: TSN 창을 shift_bits 비트만큼 앞으로 이동. 맨 앞(오래된 TSN)의 비트는 버리고, 뒤에 새로 생기는 비트는 0.
 *   이유: 창 끝보다 앞선 TSN 이 오면 창을 옮겨야 그 TSN 을 표시할 수 있음. base_tsn 은 호출한 쪽이 같이 옮김.
 *   창 위치 k 의 비트는 window_bits[k / 64] 의 (k % 64)번 비트. 밀고 나면 새 위치 k 의 비트 = 옛 위치 k + shift_bits 의 비트.
 */
static void tsn_window_shift(struct tsn_space *space, uint32_t shift_bits) {
    if (shift_bits >= TSN_WINDOW_BITS) {
        memset(space->window_bits, 0, sizeof(space->window_bits)); // 옛 비트가 하나도 창에 남지 않음
        return;
    }

    size_t word_count = TSN_WINDOW_BITS / TSN_WINDOW_WORD_BITS;
    size_t word_shift = shift_bits / TSN_WINDOW_WORD_BITS;  // 칸 단위로 옮길 수
    unsigned bit_shift = shift_bits % TSN_WINDOW_WORD_BITS; // 칸 안에서 더 옮길 비트 수

    // 앞 칸부터 채움. 읽는 칸(i + word_shift 이상)은 아직 덮어쓰지 않은 칸이라 제자리에서 옮길 수 있음
    for (size_t i = 0; i < word_count; i++) {
        // 새 칸 i = 옛 칸 i + word_shift 의 윗부분 + 그 다음 칸의 아랫부분. 창 밖의 옛 칸은 0 으로 봄
        uint64_t low_word = 0;
        uint64_t high_word = 0;
        if (i + word_shift < word_count)
            low_word = space->window_bits[i + word_shift];
        if (i + word_shift + 1 < word_count)
            high_word = space->window_bits[i + word_shift + 1];

        if (bit_shift == 0)
            space->window_bits[i] = low_word; // high_word << 64 는 C 에서 정의되지 않은 동작이라 따로 처리
        else
            space->window_bits[i] = (low_word >> bit_shift) | (high_word << (TSN_WINDOW_WORD_BITS - bit_shift));
    }
}

/* tsn_count_gaps: 창을 shift_bits 만큼 밀기 전에, 밀려서 더는 판정할 수 없게 되는 TSN 중 끝내 보지 못한 것을 tsn_gap_count 에 더함(유실 추정).
 *   이유: 창 안에 있는 동안은 늦게 오거나 재전송으로 올 수 있어 세지 않음. 창 밖으로 밀리면 다시 와도 오래됨으로 버리므로
 *   그때 끝내 못 본 것으로 확정. 이 방향에서 본 TSN 범위(가장 앞 ~ 가장 뒤) 밖은 세지 않음. 처음 본 TSN 보다 앞은
 *   캡처를 시작하기 전에 지나간 것이라 유실이 아님.
 *   tsn_window_shift 보다 먼저 불러야 함(밀고 나면 비트가 없어짐).
 *   함께 바뀌는 것: ctx 의 tsn_gap_count.
 */
static void tsn_count_gaps(struct sctp_ctx *ctx, const struct tsn_space *space, uint32_t shift_bits) {
    if (!space->has_seen_range)
        return; // 아직 본 TSN 이 없어 셀 범위가 없음

    // ① 밀려 나가는 비트 중 범위 안인데 꺼진 것. 창보다 크게 밀어도 밀려 나가는 비트는 창 크기까지
    uint32_t leaving_bits = shift_bits < TSN_WINDOW_BITS ? shift_bits : TSN_WINDOW_BITS;
    for (uint32_t i = 0; i < leaving_bits; i++) {
        uint32_t tsn = space->base_tsn + i;
        bool is_in_seen_range = (int32_t)(tsn - space->lowest_seen_tsn) >= 0
                             && (int32_t)(tsn - space->highest_seen_tsn) <= 0;
        uint64_t bit_mask = (uint64_t)1 << (i % TSN_WINDOW_WORD_BITS);
        bool is_seen = (space->window_bits[i / TSN_WINDOW_WORD_BITS] & bit_mask) != 0;
        if (is_in_seen_range && !is_seen)
            ctx->stats.tsn_gap_count++;
    }

    // ② 새 창 시작(base_tsn + shift_bits)이 가장 뒤 TSN 보다 뒤면, 그 사이 TSN 은 창에 들어오지 못하고 지나감(크게 유실되거나 TSN 이 크게 건너뛸 때)
    int32_t skipped_count = (int32_t)((space->base_tsn + shift_bits) - (space->highest_seen_tsn + 1));
    if (skipped_count > 0)
        ctx->stats.tsn_gap_count += (uint64_t)skipped_count;
}

// tsn_result: tsn_mark 의 판정 결과
enum tsn_result {
    TSN_NEW,       // 처음 본 TSN. 창에 표시함
    TSN_DUPLICATE, // 이미 본 TSN(재전송)
    TSN_TOO_OLD,   // 창보다 오래되어 처음인지 알 수 없음
};

/* tsn_mark: 받은 DATA 청크의 TSN 을 처음 본 것인지 판정하고, 처음이면 창에 표시.
 *   이유: 수동 관측자는 재전송된 DATA 도 그대로 보므로, 중복을 걸러야 같은 메시지를 상위로 두 번 넘기지 않음.
 *   TSN 은 2^32 다음에 0 으로 돌아옴. 그래서 뺄셈 결과를 부호 있는 값으로 보고 앞뒤를 정함(직렬번호 산술, RFC 9260 §1.6).
 *   반환: TSN_NEW / TSN_DUPLICATE / TSN_TOO_OLD.
 *   함께 바뀌는 것: space 의 창·base_tsn·본 TSN 범위. 창을 밀면 ctx 의 tsn_gap_count(tsn_count_gaps).
 */
static enum tsn_result tsn_mark(struct sctp_ctx *ctx, struct tsn_space *space, uint32_t tsn) {
    if (!space->has_base) {
        // 이 방향의 첫 TSN(캡처 도중 합류 포함). 창 가운데에 두어, 이보다 앞선 TSN 이 늦게 와도 처음 본 것으로 받음
        space->has_base = true;
        space->base_tsn = tsn - TSN_WINDOW_BITS / 2;
        memset(space->window_bits, 0, sizeof(space->window_bits));
    }

    int32_t window_offset = (int32_t)(tsn - space->base_tsn); // 창 안 위치. 음수면 창 시작보다 앞
    if (window_offset < 0)
        return TSN_TOO_OLD;

    if (window_offset >= TSN_WINDOW_BITS) {
        // tsn 이 창 마지막 비트에 오는 최소 이동(window_offset - TSN_WINDOW_BITS + 1)에 여유를 더함
        uint32_t shift_bits = (uint32_t)window_offset - TSN_WINDOW_BITS + 1 + TSN_SHIFT_SLACK_BITS;
        tsn_count_gaps(ctx, space, shift_bits);
        tsn_window_shift(space, shift_bits);
        space->base_tsn += shift_bits;
        window_offset -= (int32_t)shift_bits;
    }

    size_t word_index = (size_t)window_offset / TSN_WINDOW_WORD_BITS;
    uint64_t bit_mask = (uint64_t)1 << ((size_t)window_offset % TSN_WINDOW_WORD_BITS);
    if (space->window_bits[word_index] & bit_mask)
        return TSN_DUPLICATE;

    space->window_bits[word_index] |= bit_mask;

    // 유실 추정(tsn_count_gaps)이 셀 범위를 넓힘. 처음 본 TSN 이면 범위는 그 TSN 하나
    if (!space->has_seen_range) {
        space->has_seen_range = true;
        space->lowest_seen_tsn = tsn;
        space->highest_seen_tsn = tsn;
        return TSN_NEW;
    }
    bool is_after_highest = (int32_t)(tsn - space->highest_seen_tsn) > 0;
    bool is_before_lowest = (int32_t)(tsn - space->lowest_seen_tsn) < 0; // 늦게 온 앞쪽 TSN
    if (is_after_highest)
        space->highest_seen_tsn = tsn;
    if (is_before_lowest)
        space->lowest_seen_tsn = tsn;
    return TSN_NEW;
}

/* direction_reset: 한 방향의 TSN 창과 조각 목록을 비움. 연결이 새로 시작될 때(INIT·vtag 재시작) 옛 기록이 새 DATA 를
 *   버리거나 옛 조각이 새 메시지에 이어 붙지 않게 함. vtag 상태는 건드리지 않음(연결 시작을 처리하는 쪽이 정함).
 */
static void direction_reset(struct sctp_direction *direction) {
    fragments_clear(&direction->fragments);
    direction->tsn = (struct tsn_space){.has_base = false}; // 창·기준·유실 추정 범위 모두 0(아직 본 것 없음)
}

// MARK: - 조각 재조립

/* fragment_remove: link 가 가리키는 조각 하나를 목록에서 떼어 내고 해제.
 *   이유: 조립에 쓴 조각과 버리는 조각을 같은 방법으로 반납해, 목록의 바이트·개수 합계가 실제와 어긋나지 않게 함.
 *   link 는 "그 조각을 가리키는 포인터"의 주소(맨 앞이면 &queue->head, 아니면 앞 조각의 &next).
 *   목록을 다시 훑지 않고 바로 뗌. 돌아오면 *link 는 떼어 낸 조각의 다음 조각을 가리킴.
 *   함께 바뀌는 것: queue 의 head·total_bytes·fragment_count.
 */
static void fragment_remove(struct reassembly_queue *queue, struct fragment **link) {
    struct fragment *fragment = *link;
    *link = fragment->next; // 앞쪽이 fragment 를 건너뛰고 그다음을 가리키게 함
    queue->total_bytes -= fragment->len;
    queue->fragment_count--;
    free(fragment);
}

/* fragment_evict: 조각 목록에서 너무 오래 기다린 조각과, 상한을 넘게 하는 조각을 버림.
 *   이유: 유실된 조각은 끝내 오지 않고, 공격자는 B 조각만 계속 보낼 수 있음. 정리하지 않으면 메모리가 끝없이 늘어남.
 *   1) 받은 지 FRAGMENT_TIMEOUT_NS 를 넘긴 조각을 버림. now_ns 는 벽시계라 뒤로 갈 수 있으므로,
 *      조각 시각보다 이르면 지난 시간을 0 으로 보고 버리지 않음.
 *   2) 새 조각(incoming_bytes)을 넣으면 개수·바이트 상한을 넘는 동안, 받은 시각이 가장 이른 조각부터 버림.
 *      시각이 같으면 목록 앞쪽(TSN 이 작은 것, 먼저 보낸 것)을 버림.
 *   함께 바뀌는 것: queue, ctx 의 fragment_evicted_count.
 */
static void fragment_evict(struct sctp_ctx *ctx, struct reassembly_queue *queue, uint64_t now_ns, size_t incoming_bytes) {
    struct fragment **link = &queue->head;
    while (*link) {
        struct fragment *fragment = *link;
        bool is_expired = now_ns > fragment->received_time_ns
                       && now_ns - fragment->received_time_ns > FRAGMENT_TIMEOUT_NS;
        if (is_expired) {
            fragment_remove(queue, link); // 떼고 나면 *link 가 다음 조각이므로 link 는 그대로 둠
            ctx->stats.fragment_evicted_count++;
        } else {
            link = &fragment->next;
        }
    }

    while (queue->head) {
        bool is_over_limit = queue->fragment_count >= FRAGMENT_MAX_COUNT
                          || queue->total_bytes + incoming_bytes > FRAGMENT_MAX_BYTES;
        if (!is_over_limit)
            break;

        struct fragment **oldest_link = &queue->head;
        for (struct fragment **candidate_link = &queue->head->next; *candidate_link; candidate_link = &(*candidate_link)->next) {
            if ((*candidate_link)->received_time_ns < (*oldest_link)->received_time_ns)
                oldest_link = candidate_link;
        }
        fragment_remove(queue, oldest_link);
        ctx->stats.fragment_evicted_count++;
    }
}

/* fragment_add: 메시지 일부만 담은 DATA 청크(조각)를 보관하고, 그 조각으로 메시지가 다 모였으면 이어 붙여 전달.
 *   이유: 패킷 하나에 안 들어가는 큰 메시지는 여러 DATA 청크로 나뉘어 오고, 순서가 섞이거나 사이에 다른 메시지가 끼기도 함.
 *   같은 메시지의 조각 = TSN 이 1 씩 이어지고, 스트림이 같고, 순서를 지키는 메시지(U 없음)면 SSN 도 같음 (RFC 9260 §3.3.1).
 *   처리 순서는 본문의 1)~4). 다 모이지 않았으면 조각만 보관하고, 나머지 조각이 오면 그때 다시 봄.
 *   chunk 와 record 는 호출한 쪽 소유. 전달하는 메시지의 data 는 reassembly_buf 를 가리키며 콜백 안에서만 유효.
 *   함께 바뀌는 것: queue, ctx 의 reassembly_buf·통계(fragment_evicted_count, reassembled_count), on_message 호출.
 */
static void fragment_add(struct sctp_ctx *ctx, struct reassembly_queue *queue, const struct cap_record *record,
                         uint32_t assoc_id, const struct data_chunk *chunk) {
    // DATA 청크 하나는 64 KiB 를 넘지 못해 지금 상한에선 걸리지 않지만, 상한을 줄여도 보관 합계가 상한을 넘지 않게 지킴
    if (chunk->len > FRAGMENT_MAX_BYTES) {
        ctx->stats.fragment_evicted_count++;
        return;
    }
    fragment_evict(ctx, queue, record->capture_time_ns, chunk->len);

    struct fragment *added = malloc(sizeof(*added) + chunk->len);
    if (!added)
        return; // 메모리 부족. 이 조각을 버리므로 그 메시지는 조립되지 않음
    added->received_time_ns = record->capture_time_ns;
    added->tsn = chunk->tsn;
    added->ppid = chunk->ppid;
    added->stream_id = chunk->stream_id;
    added->ssn = chunk->ssn;
    added->flags = chunk->flags;
    added->len = chunk->len;
    memcpy(added->data, chunk->data, chunk->len);

    // 1) 제자리에 끼우기: 나보다 앞 TSN 인 조각을 지나, 처음 만난 뒤 TSN 조각 앞에 넣음.
    //    TSN 은 2^32 다음에 0 으로 돌아오므로 뺄셈 결과의 부호로 앞뒤를 정함(직렬번호 산술, RFC 9260 §1.6).
    //    같은 TSN 은 tsn_mark 가 먼저 걸러 목록에 두 번 들어오지 않음
    struct fragment **insert_link = &queue->head;
    while (*insert_link) {
        bool is_earlier = (int32_t)((*insert_link)->tsn - added->tsn) < 0;
        if (!is_earlier)
            break;
        insert_link = &(*insert_link)->next;
    }
    added->next = *insert_link;
    *insert_link = added;
    queue->total_bytes += chunk->len;
    queue->fragment_count++;

    bool is_ordered = !(added->flags & DATA_FLAG_UNORDERED); // 순서를 지키는 메시지만 SSN 으로 같은 메시지인지 가림

    // 2) 새 조각이 든 이어진 구간 찾기. 앞 조각(segment_last)과 이어지면 같은 구간, 아니면 새 구간이 시작됨.
    //    조각 수는 목록 길이(FRAGMENT_MAX_COUNT) 이하라 uint16_t 에 들어감
    struct fragment **segment_link = &queue->head; // 구간 첫 조각을 가리키는 포인터의 주소. 구간을 뗄 때 씀
    struct fragment *segment_first = NULL;
    struct fragment *segment_last = NULL;
    size_t message_len = 0;
    uint16_t piece_count = 0;
    bool has_added = false;
    for (struct fragment **link = &queue->head; *link; link = &(*link)->next) {
        struct fragment *piece = *link;
        bool continues_segment = segment_last
                              && piece->tsn == segment_last->tsn + 1
                              && piece->stream_id == segment_last->stream_id
                              && !(segment_last->flags & DATA_FLAG_END) // 앞 조각이 E 면 앞 메시지가 끝남
                              && !(piece->flags & DATA_FLAG_BEGIN)      // 이 조각이 B 면 새 메시지가 시작됨
                              && (!is_ordered || piece->ssn == segment_last->ssn);
        if (!continues_segment) {
            if (has_added)
                break; // 새 조각이 든 구간이 앞 조각에서 끝남
            segment_link = link;
            segment_first = piece;
            message_len = 0;
            piece_count = 0;
        }
        segment_last = piece;
        message_len += piece->len;
        piece_count++;
        if (piece == added)
            has_added = true;
    }

    // 3) 다 모였는지. 새 조각이 목록에 있으므로 segment_first·segment_last 는 NULL 이 아님
    bool is_complete = (segment_first->flags & DATA_FLAG_BEGIN) && (segment_last->flags & DATA_FLAG_END);
    if (!is_complete)
        return;

    // 4) 이어 붙이기. message_len 은 보관 합계 이하라 FRAGMENT_MAX_BYTES 를 넘지 않음
    if (message_len > ctx->reassembly_buf_bytes) {
        uint8_t *grown = realloc(ctx->reassembly_buf, message_len);
        if (!grown)
            return; // 메모리 부족. 조각은 남겨 두므로 시간 초과·상한 정리로 반납됨
        ctx->reassembly_buf = grown;
        ctx->reassembly_buf_bytes = message_len;
    }

    // 첫 조각은 아래에서 해제되므로 메시지에 쓸 값을 먼저 꺼내 둠. PPID 는 첫 조각(B)의 값을 씀
    uint32_t first_tsn = segment_first->tsn;
    uint32_t first_ppid = segment_first->ppid;
    uint16_t stream_id = segment_first->stream_id;

    // 구간은 TSN 순서로 나란히 있음. 맨 앞 조각을 떼면 다음 조각이 *segment_link 자리로 오므로 같은 자리에서 차례로 뗌
    size_t copied_bytes = 0;
    for (uint16_t i = 0; i < piece_count; i++) {
        struct fragment *piece = *segment_link;
        if (piece->len > 0)
            memcpy(ctx->reassembly_buf + copied_bytes, piece->data, piece->len); // 길이가 0 이면 버퍼가 아직 NULL 일 수 있음
        copied_bytes += piece->len;
        fragment_remove(queue, segment_link);
    }
    ctx->stats.reassembled_count++;

    if (message_len == 0)
        return; // 사용자 데이터가 없는 메시지는 넘길 내용이 없음

    struct sctp_message message = {
        .record = record,
        .assoc_id = assoc_id,
        .ppid = first_ppid,
        .stream_id = stream_id,
        .tsn = first_tsn,
        .fragment_count = piece_count,
        .data = ctx->reassembly_buf,
        .len = message_len,
    };
    deliver_message(ctx, &message);
}

// MARK: - vtag 검사

// vtag_result: vtag_check 의 판정 결과
enum vtag_result {
    VTAG_ACCEPT,  // 이 연결의 패킷(또는 검사하지 않는 패킷). 처리
    VTAG_DROP,    // 기대와 다른 vtag. 이 패킷은 버림
    VTAG_RESTART, // 같은 새 vtag 가 이어짐. 연결 재시작으로 받아들였고, 이 방향의 TSN 창·조각은 이미 비움
};

/* vtag_check: 패킷의 vtag 가 이 방향에서 기대하는 값인지 봄
 *   이유: 다른 연결의 패킷이나 위조 패킷이 이 방향의 TSN 창·조각·연결 상태를 바꾸지 못하게, 받는 SCTP 스택처럼
 *   기대 vtag 와 다른 패킷은 버림. 다만 캡처가 INIT 을 놓친 채 연결이 다시 시작됐을 수 있으므로, 같은 새 vtag 가
 *   VTAG_RESTART_CONFIRM_COUNT 번 이어지면 재시작으로 보고 받아들임.
 *   처음 보는 방향은 기대값이 없어 그 패킷의 vtag 를 기대값으로 삼음(캡처 도중 합류).
 *   검사도 갱신도 하지 않는 패킷: 첫 청크 종류를 읽을 수 없는 패킷, 첫 청크가 INIT·ABORT·SHUTDOWN COMPLETE 인 패킷.
 *   INIT 은 vtag 가 0 이고, ABORT·SHUTDOWN COMPLETE 는 T 비트 규칙이 따로 있어 handle_end_chunk 가 봄.
 *   반환: VTAG_ACCEPT / VTAG_DROP / VTAG_RESTART.
 *   함께 바뀌는 것: direction 의 vtag 상태(재시작이면 TSN 창·조각도), ctx 의 통계.
 */
static enum vtag_result vtag_check(struct sctp_ctx *ctx, struct sctp_direction *direction, const struct cap_record *record) {
    if (record->captured_len < SCTP_COMMON_HEADER_BYTES + CHUNK_HEADER_BYTES)
        return VTAG_ACCEPT; // 첫 청크 종류를 못 읽어 예외 청크인지 알 수 없음

    uint8_t first_chunk_type = record->sctp_packet[SCTP_COMMON_HEADER_BYTES];
    bool is_exempt_chunk = first_chunk_type == CHUNK_TYPE_INIT
                        || first_chunk_type == CHUNK_TYPE_ABORT
                        || first_chunk_type == CHUNK_TYPE_SHUTDOWN_COMPLETE;
    if (is_exempt_chunk)
        return VTAG_ACCEPT;

    struct vtag_state *state = &direction->vtag;
    uint32_t vtag = read_be32(record->sctp_packet + 4); // 공통 헤더의 출발·도착 포트(2 + 2) 뒤
    enum vtag_result result = VTAG_ACCEPT;
    bool is_mismatch = state->has_expected && vtag != state->expected_vtag;
    if (is_mismatch) {
        bool is_same_candidate = state->pending_count > 0 && state->pending_vtag == vtag;
        if (is_same_candidate) {
            state->pending_count++;
        } else {
            state->pending_vtag = vtag;
            state->pending_count = 1;
        }
        if (state->pending_count < VTAG_RESTART_CONFIRM_COUNT) {
            ctx->stats.vtag_mismatch_drop_count++;
            return VTAG_DROP; // 기대값은 그대로 둠. 패킷 하나로는 바뀌지 않음
        }

        // 같은 새 vtag 가 이어짐. INIT 을 놓친 연결 재시작으로 보고 옛 연결의 TSN 창·조각을 버림
        direction_reset(direction);
        ctx->stats.vtag_reset_count++;
        result = VTAG_RESTART;
    }

    state->has_expected = true;
    state->expected_vtag = vtag;
    state->pending_count = 0;
    return result;
}

// MARK: - 청크 종류별 처리

/* handle_data_chunk: DATA 청크 하나를 처리.
 *   TSN 을 먼저 판정해, 이미 본 것(재전송)이나 창보다 오래된 것은 세고 버림.
 *   완성된 메시지를 담은 청크는 바로 전달하고, 메시지 일부만 담은 청크(조각)는 fragment_add 로 넘김.
 *   이유: 청크 종류마다 처리가 길어, sctp_input 은 청크를 종류별로 나눠 주기만 하고 처리는 종류마다 따로 둠.
 *   raw_chunk 의 바이트는 잘리지 않았음을 확인한 뒤에만 읽음.
 *   함께 바뀌는 것: ctx 의 통계, direction 의 TSN 창·조각 목록, on_message 호출.
 */
static void handle_data_chunk(struct sctp_ctx *ctx, struct sctp_direction *direction, const struct cap_record *record,
                              uint32_t assoc_id, const struct raw_chunk *raw_chunk) {
    ctx->stats.data_chunk_count++;
    if (raw_chunk->len < DATA_CHUNK_HEADER_BYTES) {
        ctx->stats.bad_header_count++; // 이 청크만 건너뛰고 다음 청크로
        return;
    }
    if (raw_chunk->is_partial) {
        ctx->stats.partial_chunk_count++;
        return;
    }

    struct data_chunk chunk = {
        .tsn = read_be32(raw_chunk->bytes + 4),
        .stream_id = read_be16(raw_chunk->bytes + 8),
        .ssn = read_be16(raw_chunk->bytes + 10),
        .ppid = read_be32(raw_chunk->bytes + 12),
        .flags = raw_chunk->flags,
        .data = raw_chunk->bytes + DATA_CHUNK_HEADER_BYTES,
        .len = (size_t)raw_chunk->len - DATA_CHUNK_HEADER_BYTES,
    };

    // 조각 청크도 자기 TSN 이 있음. 완성 메시지인지 가르기 전에 판정해야 재전송된 조각도 걸러짐
    enum tsn_result mark_result = tsn_mark(ctx, &direction->tsn, chunk.tsn);
    if (mark_result == TSN_DUPLICATE) {
        ctx->stats.duplicate_chunk_count++; // 재전송. 처음 온 청크를 이미 처리함
        return;
    }
    if (mark_result == TSN_TOO_OLD) {
        ctx->stats.too_old_chunk_count++; // 중복인지 알 수 없음. 두 번 넘길 수 있으므로 넘기지 않음
        return;
    }

    bool is_whole_message = (chunk.flags & DATA_FLAG_BEGIN) && (chunk.flags & DATA_FLAG_END);
    if (!is_whole_message) {
        ctx->stats.fragment_chunk_count++;
        fragment_add(ctx, &direction->fragments, record, assoc_id, &chunk);
        return;
    }

    struct sctp_message message = {
        .record = record,
        .assoc_id = assoc_id,
        .ppid = chunk.ppid,
        .stream_id = chunk.stream_id,
        .tsn = chunk.tsn,
        .fragment_count = 1,
        .data = chunk.data,
        .len = chunk.len,
    };
    deliver_message(ctx, &message);
}

/* handle_init_chunk: INIT·INIT-ACK 청크 하나를 처리. 보낸 쪽이 연결을 새로 시작한다는 뜻.
 *   이 방향의 TSN 창과 조각을 비우고, 청크의 Initial TSN 이 창 가운데 오게 기준을 다시 잡음. 반대 방향도 비움
 *   (그쪽 기준은 상대의 INIT·INIT-ACK 이나 첫 DATA 로 다시 정해짐).
 *   청크의 Initiate Tag 는 상대가 이쪽으로 보낼 때 쓸 vtag 라, 반대 방향의 기대 vtag 로 적음.
 *   INIT 이면 같은 주소·포트라도 새 연결 번호를 매기고 연결 시작을 알림. INIT-ACK 은 그 INIT 에 대한 응답이라
 *   번호를 바꾸지 않음.
 *   이유: 같은 주소·포트로 연결이 다시 시작되면 TSN 이 옛 연결과 상관없는 값에서 다시 시작함. 옛 창이 남아 있으면
 *   새 연결의 DATA 를 재전송으로 잘못 보고 버림. 새 번호는 위층이 옛 연결과 새 연결의 메시지를 섞지 않게 함.
 *   반환: 이 청크 뒤에 쓸 연결 번호(INIT 이면 새 번호, 아니면 assoc_id 그대로).
 *   잘렸거나 Initial TSN 까지 들어 있지 않은 청크는 무시하고 assoc_id 를 그대로 돌려줌.
 *   함께 바뀌는 것: ctx 의 통계·방향 표·연결 표, direction 과 반대 방향의 TSN 창·조각, 반대 방향의 기대 vtag, on_assoc 호출.
 */
static uint32_t handle_init_chunk(struct sctp_ctx *ctx, struct sctp_direction *direction, const struct cap_record *record,
                                  uint32_t assoc_id, const struct raw_chunk *raw_chunk) {
    bool has_initial_tsn = !raw_chunk->is_partial && raw_chunk->len >= INIT_CHUNK_MIN_BYTES;
    if (!has_initial_tsn)
        return assoc_id;

    uint32_t initiate_tag = read_be32(raw_chunk->bytes + 4);
    uint32_t initial_tsn = read_be32(raw_chunk->bytes + 16);

    // 이 방향의 DATA 는 Initial TSN 부터 옴. tsn_mark 가 첫 TSN 을 볼 때와 같게 창 가운데에 둠
    direction_reset(direction);
    direction->tsn.has_base = true;
    direction->tsn.base_tsn = initial_tsn - TSN_WINDOW_BITS / 2;

    // 표가 꽉 차 반대 방향 칸을 밀어내서 만들어도 지금 방향은 밀어내지 않음(keep). 표를 미리 잡아 두어 direction 포인터도 그대로 유효
    struct sctp_direction *reverse = direction_get(ctx, record, DIRECTION_REVERSE, direction);

    // 반대 방향 패킷의 vtag 는 이 Initiate Tag. 옛 연결의 재시작 후보도 버림(direction_reset 은 vtag 를 건드리지 않음)
    reverse->vtag.has_expected = true;
    reverse->vtag.expected_vtag = initiate_tag;
    reverse->vtag.pending_count = 0;
    direction_reset(reverse);

    ctx->stats.init_count++;
    if (raw_chunk->type == CHUNK_TYPE_INIT) {
        assoc_id = assoc_id_assign(ctx, record, ASSOC_ID_NEW); // 이 패킷의 뒤 청크와 이후 메시지가 새 번호를 받음
        notify_assoc(ctx, record, assoc_id, SCTP_ASSOC_START);
    }
    return assoc_id;
}

/* handle_end_chunk: ABORT·SHUTDOWN COMPLETE 청크 하나를 처리. 이 연결의 패킷이 맞으면 연결 끝을 알림.
 *   이유: 위층이 그 연결에 딸린 상태(UE 등)를 정리할 때를 알 수 있게 함. 다른 연결이나 위조 패킷이 우연히
 *   이 청크 종류를 담고 있어도 거짓 끝을 내지 않도록, vtag 가 맞을 때만 받아들임
 *   vtag 가 이 방향의 기대값과 같으면 받아들임. 아니어도 T 비트가 켜져 있으면, 받은 패킷의 vtag 를 되돌려 쓴 것이라
 *   반대 방향의 기대값과 같을 때 받아들임.
 *   연결 번호는 바꾸지 않음. 같은 주소·포트로 다시 시작하면 그 INIT 에서 새 번호를 매김.
 *   함께 바뀌는 것: ctx 의 통계·방향 표(T 비트일 때 반대 방향 레코드를 만들거나, 표가 꽉 차면 다른 칸을 밀어낼 수 있음), on_assoc 호출.
 */
static void handle_end_chunk(struct sctp_ctx *ctx, struct sctp_direction *direction, const struct cap_record *record,
                             uint32_t assoc_id, const struct raw_chunk *raw_chunk) {
    ctx->stats.abort_shutdown_count++; // vtag 검사 전에 셈. 버린 것까지 세야 위조·이상 입력을 가늠할 수 있음

    uint32_t vtag = read_be32(record->sctp_packet + 4); // 공통 헤더는 sctp_input 이 이미 확인함
    bool is_vtag_ok = direction->vtag.has_expected && vtag == direction->vtag.expected_vtag;
    bool is_reflected = (raw_chunk->flags & ABORT_FLAG_T) != 0;
    if (!is_vtag_ok && is_reflected) {
        struct sctp_direction *reverse = direction_get(ctx, record, DIRECTION_REVERSE, direction);
        is_vtag_ok = reverse->vtag.has_expected && vtag == reverse->vtag.expected_vtag;
    }
    if (!is_vtag_ok) {
        ctx->stats.vtag_mismatch_drop_count++;
        return;
    }

    notify_assoc(ctx, record, assoc_id, SCTP_ASSOC_END);
}

// MARK: - 패킷 입력

/* sctp_input: 캡처한 패킷 하나를 처리.
 *   1) 패킷 수를 세고, 공통 헤더가 없는 패킷은 버리고, 캡처가 잘린 패킷은 표시.
 *   2) 패킷 방향의 레코드를 찾음(없으면 만듦. 방향 표가 꽉 차면 옛 칸을 밀어내고 만듦).
 *      패킷이 속한 연결의 번호를 정함. 이 패킷에서 나오는 메시지에 이 번호를 붙임.
 *      vtag 가 이 방향의 기대값과 다르면 패킷을 버림. 같은 새 vtag 가 이어져 재시작으로 받아들이면 새 번호를 매기고
 *      연결 시작을 알림.
 *   3) 공통 헤더 뒤의 청크를 하나씩 읽어(번들링) 종류별 처리 함수에 넘김.
 *      DATA 는 handle_data_chunk(메시지), INIT·INIT-ACK 는 handle_init_chunk(연결 시작),
 *      ABORT·SHUTDOWN COMPLETE 는 handle_end_chunk(연결 끝)가 처리. 그 밖의 청크 종류는 무시.
 *   이유: 패킷 바이트는 공격자가 보낸 입력일 수 있으므로, 모든 읽기 전에 캡처된 길이 안인지 확인.
 *   record 는 호출한 쪽 소유. 이 함수가 돌아온 뒤에는 쓰지 않음.
 *   함께 바뀌는 것: ctx 의 통계, on_message·on_assoc 호출.
 */
void sctp_input(struct sctp_ctx *ctx, const struct cap_record *record) {
    ctx->stats.packet_count++; // 버리는 패킷까지 세야 다른 통계의 비율 확인 가능

    if (record->captured_len < SCTP_COMMON_HEADER_BYTES) {
        ctx->stats.bad_header_count++;
        return;
    }

    // 잘린 패킷도 앞쪽 청크는 온전할 수 있으므로 버리지 않고 표시
    if (record->captured_len < record->packet_len)
        ctx->stats.truncated_packet_count++;

    struct sctp_direction *direction = direction_get(ctx, record, DIRECTION_FORWARD, NULL);
    uint32_t assoc_id = assoc_id_assign(ctx, record, ASSOC_ID_CURRENT);

    enum vtag_result check_result = vtag_check(ctx, direction, record);
    if (check_result == VTAG_DROP)
        return; // 이 연결의 패킷이 아님. 청크를 읽지 않음
    if (check_result == VTAG_RESTART) {
        assoc_id = assoc_id_assign(ctx, record, ASSOC_ID_NEW); // INIT 없이 다시 시작한 연결. 이 패킷부터 새 번호
        notify_assoc(ctx, record, assoc_id, SCTP_ASSOC_START);
    }

    const uint8_t *packet_bytes = record->sctp_packet;
    size_t captured_len = record->captured_len;
    size_t offset = SCTP_COMMON_HEADER_BYTES; // 첫 청크는 공통 헤더 바로 뒤. size_t 라 아래 덧셈이 넘치지 않음

    while (offset + CHUNK_HEADER_BYTES <= captured_len) {
        const uint8_t *chunk_bytes = packet_bytes + offset;
        uint16_t chunk_len = read_be16(chunk_bytes + 2); // 청크 헤더를 포함한 길이, 패딩 제외

        if (chunk_len < CHUNK_HEADER_BYTES) {
            ctx->stats.bad_header_count++; // 길이를 믿을 수 없으니 다음 청크 위치도 알 수 없음
            break;
        }
        ctx->stats.chunk_count++;

        struct raw_chunk chunk = {
            .bytes = chunk_bytes,
            .type = chunk_bytes[0],
            .flags = chunk_bytes[1],
            .len = chunk_len,
            .is_partial = offset + chunk_len > captured_len,
        };

        // 청크 종류별 처리. 처리 함수는 그 청크만 다루고, 다음 청크로 넘어가는 일은 아래에서 함
        switch (chunk.type) {
        case CHUNK_TYPE_DATA:
            handle_data_chunk(ctx, direction, record, assoc_id, &chunk);
            break;
        case CHUNK_TYPE_INIT:
        case CHUNK_TYPE_INIT_ACK:
            assoc_id = handle_init_chunk(ctx, direction, record, assoc_id, &chunk);
            break;
        case CHUNK_TYPE_ABORT:
        case CHUNK_TYPE_SHUTDOWN_COMPLETE:
            handle_end_chunk(ctx, direction, record, assoc_id, &chunk);
            break;
        default:
            break; // 처리하지 않는 청크(SACK, HEARTBEAT 등)는 메시지가 없으므로 무시
        }

        if (chunk.is_partial)
            break; // 캡처가 이 청크 중간에서 끝났으니 뒤에 읽을 청크가 없음

        // 다음 청크는 이 청크를 CHUNK_ALIGN_BYTES 의 배수로 패딩한 뒤에서 시작
        size_t padded_len = ((size_t)chunk_len + CHUNK_ALIGN_BYTES - 1) / CHUNK_ALIGN_BYTES * CHUNK_ALIGN_BYTES;
        offset += padded_len;
    }
}
