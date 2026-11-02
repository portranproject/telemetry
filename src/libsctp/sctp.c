/* libsctp/sctp.c — 와이어의 SCTP 패킷 → 완성된 사용자 메시지(F1AP/NGAP PDU)  (RFC 9260)
 *
 *   입력: 캡처 모듈이 준 패킷 하나(struct cap_record). sctp_input 으로 들어온다.
 *   출력: 완성된 메시지(struct sctp_message)와 연결 시작·끝(struct sctp_assoc_event). 콜백으로 나간다.
 *   패킷 1개 ≠ 메시지 1개다. 한 패킷에 메시지 여러 개(번들링), 한 메시지가 여러 패킷(단편화),
 *   재전송 중복, 캡처 잘림이 섞여 온다. 이것을 정리해 완성된 메시지만 넘기는 것이 이 파일의 일이다.
 *   수동 관측자라 재전송을 요청할 수 없으므로, 끝내 못 본 TSN 은 유실 추정(tsn_gap_count)으로만 센다.
 *
 * 핵심 자료구조(안쪽 → 바깥쪽):
 *   fragment          — 아직 메시지를 완성하지 못한 DATA 조각 하나(힙)
 *   reassembly_queue  — 한 방향의 미완성 조각 목록
 *   tsn_space         — 한 방향의 TSN 중복 판정 창 + 유실 추정 범위
 *   vtag_state        — 한 방향의 vtag 검사 상태
 *   sctp_direction    — 한 방향(보내는 끝 → 받는 끝). 위 셋을 품는다
 *   sctp_assoc_record — 한 연결(양방향 공통)과 그 연결 번호
 *   data_chunk        — DATA 청크 하나에서 읽은 값(패킷 버퍼를 가리킴, 처리 중에만 씀)
 *   sctp_ctx          — libsctp 전체 상태. 방향 표·연결 표·재조립 버퍼·콜백·통계
 *
 * 주요 함수:
 *   sctp_input                            — 패킷 하나 처리의 입구. 헤더 확인 → 청크를 하나씩 읽어 DATA 를 메시지로 전달
 *   deliver_message                       — 완성된 메시지 하나를 on_message 콜백으로 넘김
 *   sctp_new / sctp_free / sctp_get_stats — 상태 생성·해제, 누적 통계
 *   fragments_clear                       — 한 방향의 조각 목록 전체 해제
 *   read_be16 / read_be32                 — 패킷의 빅엔디안(네트워크 순서) 정수 읽기
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "libcap/cap.h"
#include "sctp.h"

// TSN 하나당 1비트. 재전송은 최근 TSN 에서 오므로 이 범위면 중복을 가려낸다. uint64_t 배열이라 64 의 배수여야 한다
#define TSN_WINDOW_BITS 4096

// 방향 표 칸 수. 주소·포트를 바꿔 가며 주입해도 메모리·탐색 시간이 이 상한에 묶이도록. 정상 배치는 방향이 몇 개뿐이다
#define DIRECTION_MAX_COUNT 2048
// 연결 표 칸 수.
#define ASSOC_MAX_COUNT 2048

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

// sctp_chunk_type: 청크 헤더 첫 바이트의 청크 종류 번호 (RFC 9260 §3.2, I-DATA 는 RFC 8260 §2.1).
//   libsctp 가 처리하는 종류만 둔다. 여기 없는 번호(SACK, HEARTBEAT, COOKIE 등)는 무시한다.
//   패킷에서 읽은 바이트에는 여기 없는 값도 들어오므로, 읽은 값은 uint8_t 로 두고 이 값들과 비교만 한다
enum sctp_chunk_type
{
    CHUNK_TYPE_DATA = 0,               // 사용자 데이터(F1AP/NGAP 메시지)
    CHUNK_TYPE_INIT = 1,               // 연결 시작 요청. Initiate Tag·Initial TSN 을 담는다
    CHUNK_TYPE_INIT_ACK = 2,           // 연결 시작 응답. INIT 과 같은 값을 담는다
    CHUNK_TYPE_ABORT = 6,              // 연결 강제 종료
    CHUNK_TYPE_SHUTDOWN_COMPLETE = 14, // 정상 종료 완료
    CHUNK_TYPE_IDATA = 64,             // 인터리빙용 사용자 데이터 (협상된 연결에서만 쓰임)
};

/* read_be16: ptr 위치의 2바이트를 빅엔디안(네트워크 순서) 정수로
 *   호출한 쪽이 ptr 부터 2바이트가 캡처 범위 안인지 먼저 확인 필요
 */
static inline uint16_t read_be16(const uint8_t *ptr)
{
    return (uint16_t)(((uint16_t)ptr[0] << 8) | (uint16_t)ptr[1]);
}

/* read_be32: ptr 위치의 4바이트를 빅엔디안(네트워크 순서) 정수로
 *   호출한 쪽이 ptr 부터 4바이트가 캡처 범위 안인지 먼저 확인 필요
 */
static inline uint32_t read_be32(const uint8_t *ptr)
{
    return ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) | ((uint32_t)ptr[2] << 8) | (uint32_t)ptr[3];
}

// fragment: 아직 메시지를 완성하지 못한 DATA 조각 하나(SCTP 메시지 단편).
// 패킷 버퍼는 sctp_input 이 끝나면 사라지므로 바이트 복사
struct fragment
{
    struct fragment *next;     // 목록의 다음 조각. 새 조각을 맨 앞에 넣으므로 TSN·도착 순서와 무관
    uint64_t received_time_ns; // 오래 못 채운 조각을 버리는 기준
    uint32_t tsn;              // 연속 판정
    uint32_t ppid;             // 첫 조각(B)의 값을 메시지 PPID 로 쓴다
    uint16_t stream_id;
    uint16_t ssn;
    uint8_t flags; // DATA 청크의 B·E·U 비트. 메시지 시작·끝, 순서 무관 여부
    size_t len;
    uint8_t data[]; // 조각의 사용자 데이터 복사본
};

// reassembly_queue: 한 방향의 미완성 조각 목록. 메모리 상한을 지키기 위함
struct reassembly_queue
{
    struct fragment *head;
    size_t total_bytes;
    uint32_t fragment_count;
};

// tsn_space: 한 방향의 TSN 중복 판정 창. 재전송된 DATA 를 걸러 같은 메시지를 두 번 넘기지 않기 위함
struct tsn_space
{
    bool has_base;                              // false = 아직 이 방향의 TSN 을 본 적 없음(캡처 도중 합류 포함)
    uint32_t base_tsn;                          // window_bits 의 비트 0 에 해당하는 TSN
    uint64_t window_bits[TSN_WINDOW_BITS / 64]; // 본 TSN 이면 1
    bool has_seen_range;                        // 아래 두 값이 유효한지
    uint32_t lowest_seen_tsn;                   // 이 방향에서 본 가장 앞 TSN
    uint32_t highest_seen_tsn;                  // 이 방향에서 본 가장 뒤 TSN
};

// vtag_state: 한 방향의 vtag 검사 상태. 다른 연결의 패킷이나 위조 패킷을 걸러내기 위함 (RFC 9260 §8.5)
struct vtag_state
{
    bool has_expected;      // false = 아직 기대 vtag 를 모름(검사하지 않음)
    uint32_t expected_vtag; // 이 방향 패킷이 가져야 할 vtag
    uint32_t pending_vtag;  // INIT 을 못 본 채 바뀐 vtag 후보. 재시작인지 확인하는 동안 보관
    uint32_t pending_count; // pending_vtag 가 연속으로 나온 패킷 수
};

// sctp_direction: 한 방향(보내는 끝 → 받는 끝). TSN·조각·vtag 는 방향마다 따로 흘러가므로 방향 단위로 둔다
struct sctp_direction
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    struct tsn_space tsn;
    struct reassembly_queue fragments;
    struct vtag_state vtag;
};

// sctp_assoc_record: 한 연결(양방향 공통). 두 방향의 메시지에 같은 연결 번호를 붙이기 위함
//   두 끝을 (주소, 포트) 사전순으로 정렬해 저장하므로 A→B 와 B→A 패킷이 같은 레코드를 찾는다.
//   비교는 저장된 값 그대로 한다(바이트 순서와 무관하게 양방향에서 같은 결과만 나오면 된다).
struct sctp_assoc_record
{
    uint32_t low_addr; // (주소, 포트)가 작은 쪽 끝
    uint16_t low_port;
    uint32_t high_addr; // (주소, 포트)가 큰 쪽 끝
    uint16_t high_port;
    uint32_t assoc_id; // 0 = 아직 번호 없음. INIT·재시작마다 새 번호
};

// data_chunk: DATA 청크 하나에서 읽은 값 (RFC 9260 §3.3.1). 청크를 읽는 곳과 쓰는 곳 사이에 하나의 개념으로 넘기기 위함
struct data_chunk
{
    uint32_t tsn;
    uint32_t ppid;
    uint16_t stream_id;
    uint16_t ssn;
    uint8_t flags;       // B·E·U 비트
    const uint8_t *data; // 사용자 데이터. 패킷 버퍼 안을 가리킴(호출한 쪽 소유, 복사 아님)
    size_t len;          // data 의 바이트 수
};

// sctp_ctx: libsctp 전체 상태(sctp.h 에서는 이름만 공개). sctp_new 가 만들고 sctp_free 가 해제한다.
// 방향, 연결 표는 상한만큼 sctp_new 에서 한 번에 할당한다. 표가 자라며 옮겨지지 않으므로 레코드 포인터가 바뀌지 않는다.
struct sctp_ctx
{
    sctp_message_callback on_message; // 완성된 메시지를 넘길 함수(NULL 이면 넘기지 않음)
    sctp_assoc_callback on_assoc;     // 연결 시작·끝을 알릴 함수(NULL 이면 알리지 않음)
    void *user;                       // 콜백 첫 인자로 그대로 돌려줄 포인터(호출한 쪽 소유)
    struct sctp_stats stats;

    struct sctp_direction *directions; // 방향 표
    size_t direction_count;
    size_t direction_clock; // 표가 꽉 찼을 때 다음에 밀어낼 칸.

    uint8_t *reassembly_buf;     // 조각을 이어 붙일 버퍼. 메시지마다 할당하지 않으려고 재사용한다
    size_t reassembly_buf_bytes; // reassembly_buf 에 할당된 크기

    struct sctp_assoc_record *assocs; // 연결 표
    size_t assoc_count;
    size_t assoc_clock;     // 표가 꽉 찼을 때 다음에 밀어낼 칸
    uint32_t next_assoc_id; // 다음에 매길 연결 번호. 0 은 '연결 없음' 이라 1부터
};

/* fragments_clear: 조각 목록의 조각을 모두 해제하고 목록을 비운다.
 *   이유: 방향을 해제·초기화·재사용할 때 남은 조각을 한꺼번에 반납해야 누수가 없다.
 */
static void fragments_clear(struct reassembly_queue *queue)
{
    struct fragment *fragment = queue->head;
    while (fragment)
    {
        struct fragment *next = fragment->next;
        free(fragment);
        fragment = next;
    }
    queue->head = NULL;
    queue->total_bytes = 0;
    queue->fragment_count = 0;
}

/* sctp_new: libsctp 상태를 만든다.
 *   이유: 방향·연결 표를 상한만큼 여기서 한 번에 잡아, 처리 중에 표가 옮겨지거나 할당에 실패하는 일을 없앤다.
 *   반환: 새 상태. 하나라도 할당에 실패하면 이미 잡은 것을 해제하고 NULL.
 *   user 는 호출한 쪽 소유. 보관했다가 콜백 첫 인자로 넘기기만 한다.
 */
struct sctp_ctx *sctp_new(sctp_message_callback on_message, sctp_assoc_callback on_assoc, void *user)
{
    struct sctp_ctx *ctx = calloc(1, sizeof(*ctx)); // 통계 포함 전부 0
    if (!ctx)
        return NULL;

    ctx->directions = calloc(DIRECTION_MAX_COUNT, sizeof(*ctx->directions));
    ctx->assocs = calloc(ASSOC_MAX_COUNT, sizeof(*ctx->assocs));
    if (!ctx->directions || !ctx->assocs)
    {
        free(ctx->directions); // 둘 중 하나는 NULL 일 수 있다. free(NULL) 은 아무것도 하지 않는다
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

/* sctp_free: 모든 방향의 남은 조각, 방향·연결 표, 재조립 버퍼, 상태 자신을 해제한다.
 *   ctx 가 NULL 이면 아무것도 하지 않는다.
 */
void sctp_free(struct sctp_ctx *ctx)
{
    if (!ctx)
        return;

    for (size_t i = 0; i < ctx->direction_count; i++)
        fragments_clear(&ctx->directions[i].fragments);
    free(ctx->directions);
    free(ctx->assocs);
    free(ctx->reassembly_buf);
    free(ctx);
}

// sctp_get_stats: 누적 통계의 주소. ctx 가 해제되기 전까지 유효하다. ctx 는 NULL 이면 안 된다.
const struct sctp_stats *sctp_get_stats(const struct sctp_ctx *ctx)
{
    return &ctx->stats;
}

/* deliver_message: 완성된 메시지 하나를 on_message 콜백으로 넘긴다.
 *   이유: 메시지를 내보내는 곳을 한 군데로 모아, 콜백이 없을 때의 처리와 메시지 수 세기를 한 번만 쓴다.
 *   콜백이 NULL 이어도 message_count 는 센다(통계가 콜백 등록 여부와 무관해야 비교할 수 있다).
 *   message 와 그 안의 포인터는 콜백이 돌아오면 무효다. 함께 바뀌는 것: ctx 의 통계, on_message 호출.
 */
static void deliver_message(struct sctp_ctx *ctx, const struct sctp_message *message)
{
    ctx->stats.message_count++;
    if (ctx->on_message)
        ctx->on_message(ctx->user, message);
}

/* sctp_input: 캡처한 패킷 하나를 처리한다.
 *   1) 패킷 수를 세고, 공통 헤더가 없는 패킷은 버리고, 캡처가 잘린 패킷은 표시한다.
 *   2) 공통 헤더 뒤의 청크를 하나씩 읽는다(번들링). 완성된 메시지를 담은 DATA 청크는 바로 전달한다.
 *      메시지 일부만 담은 DATA 청크는 세기만 한다. 그 밖의 청크 종류는 무시한다.
 *   이유: 패킷 바이트는 공격자가 보낸 입력일 수 있으므로, 모든 읽기 전에 캡처된 길이 안인지 확인한다.
 *   record 는 호출한 쪽 소유다. 이 함수가 돌아온 뒤에는 쓰지 않는다.
 *   함께 바뀌는 것: ctx 의 통계, on_message 호출.
 */
void sctp_input(struct sctp_ctx *ctx, const struct cap_record *record)
{
    ctx->stats.packet_count++; // 버리는 패킷까지 세야 다른 통계의 비율 확인 가능

    if (record->captured_len < SCTP_COMMON_HEADER_BYTES)
    {
        ctx->stats.bad_header_count++;
        return;
    }

    // 잘린 패킷도 앞쪽 청크는 온전할 수 있으므로 버리지 않고 표시
    if (record->captured_len < record->packet_len)
        ctx->stats.truncated_packet_count++;

    const uint8_t *packet_bytes = record->sctp_packet;
    size_t captured_len = record->captured_len;
    size_t offset = SCTP_COMMON_HEADER_BYTES; // 첫 청크는 공통 헤더 바로 뒤. size_t 라 아래 덧셈이 넘치지 않는다

    while (offset + CHUNK_HEADER_BYTES <= captured_len)
    {
        const uint8_t *chunk_bytes = packet_bytes + offset;
        uint8_t chunk_type = chunk_bytes[0];
        uint8_t chunk_flags = chunk_bytes[1];
        uint16_t chunk_len = read_be16(chunk_bytes + 2); // 청크 헤더를 포함한 길이, 패딩 제외

        if (chunk_len < CHUNK_HEADER_BYTES)
        {
            ctx->stats.bad_header_count++; // 길이를 믿을 수 없으니 다음 청크 위치도 알 수 없음
            break;
        }
        ctx->stats.chunk_count++;

        bool is_partial = offset + chunk_len > captured_len; // 청크 끝이 캡처 범위 밖

        // 청크 종류별 처리. 각 case 안의 break 는 그 청크 처리만 끝내고, 아래의 다음 청크 이동으로 간다
        switch (chunk_type)
        {
        case CHUNK_TYPE_DATA:
        {
            ctx->stats.data_chunk_count++;
            if (chunk_len < DATA_CHUNK_HEADER_BYTES)
            {
                ctx->stats.bad_header_count++; // 이 청크만 건너뛰고 다음 청크로
                break;
            }
            if (is_partial)
            {
                ctx->stats.partial_chunk_count++; // 잘린 청크는 읽지 않는다
                break;
            }

            struct data_chunk chunk = {
                .tsn = read_be32(chunk_bytes + 4),
                .stream_id = read_be16(chunk_bytes + 8),
                .ssn = read_be16(chunk_bytes + 10),
                .ppid = read_be32(chunk_bytes + 12),
                .flags = chunk_flags,
                .data = chunk_bytes + DATA_CHUNK_HEADER_BYTES,
                .len = (size_t)chunk_len - DATA_CHUNK_HEADER_BYTES,
            };
            bool is_whole_message = (chunk.flags & DATA_FLAG_BEGIN) && (chunk.flags & DATA_FLAG_END);
            if (!is_whole_message)
            {
                ctx->stats.fragment_chunk_count++; // 메시지 일부만 담은 조각. 아직 조립하지 않고 세기만 한다
                break;
            }

            struct sctp_message message = {
                .record = record,
                .assoc_id = 0, // 연결 번호는 아직 매기지 않는다
                .ppid = chunk.ppid,
                .stream_id = chunk.stream_id,
                .tsn = chunk.tsn,
                .fragment_count = 1,
                .data = chunk.data,
                .len = chunk.len,
            };
            deliver_message(ctx, &message);
            break;
        }
        default:
            break; // 처리하지 않는 청크(SACK, HEARTBEAT 등)는 메시지가 없으므로 무시한다
        }

        if (is_partial)
            break; // 캡처가 이 청크 중간에서 끝났으니 뒤에 읽을 청크가 없음

        // 다음 청크는 이 청크를 CHUNK_ALIGN_BYTES 의 배수로 패딩한 뒤에서 시작
        size_t padded_len = ((size_t)chunk_len + CHUNK_ALIGN_BYTES - 1) / CHUNK_ALIGN_BYTES * CHUNK_ALIGN_BYTES;
        offset += padded_len;
    }
}
