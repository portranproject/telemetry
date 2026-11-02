#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libcap/cap.h"
#include "sctp.h"

// TSN 하나당 1비트. 재전송은 최근 TSN 에서 오므로 이 범위면 중복을 가려낸다. uint64_t 배열이라 64 의 배수여야 한다
#define TSN_WINDOW_BITS 4096
// window_bits 한 칸(uint64_t)의 비트 수. 창 안 위치를 (몇 번째 칸, 칸 안 몇 번째 비트)로 바꿀 때 쓴다
#define TSN_WINDOW_WORD_BITS 64
// 창을 밀 때 꼭 필요한 만큼에 더해 더 미는 비트 수(창의 1/4). 여유 없이 밀면 순서대로 오는 새 TSN 마다 창을 다시 민다
#define TSN_SHIFT_SLACK_BITS (TSN_WINDOW_BITS / 4)

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
    bool has_base;                                                // false = 아직 이 방향의 TSN 을 본 적 없음(캡처 도중 합류 포함)
    uint32_t base_tsn;                                            // window_bits 의 비트 0 에 해당하는 TSN
    uint64_t window_bits[TSN_WINDOW_BITS / TSN_WINDOW_WORD_BITS]; // 본 TSN 이면 1
    bool has_seen_range;                                          // 아래 두 값이 유효한지
    uint32_t lowest_seen_tsn;                                     // 이 방향에서 본 가장 앞 TSN
    uint32_t highest_seen_tsn;                                    // 이 방향에서 본 가장 뒤 TSN
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

/* sctp_free: 모든 방향의 남은 조각, 방향·연결 표, 재조립 버퍼, 상태 자신을 해제
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

/* direction_get: 패킷의 방향(출발 → 도착) 레코드를 방향 표에서 찾고, 없으면 새로 만든다.
 *   이유: TSN 창·조각·vtag 는 방향마다 따로 흘러가므로, 패킷마다 자기 방향의 상태를 찾아 써야 한다.
 *   키는 패킷의 (출발 주소, 도착 주소, 출발 포트, 도착 포트) 그대로다. 반대 방향은 다른 레코드다.
 *   반환: 방향 레코드(표 안을 가리킴, sctp_free 전까지 주소가 바뀌지 않음). 표가 꽉 찼으면 NULL.
 *   함께 바뀌는 것: 새로 만들면 ctx 의 direction_count.
 */
static struct sctp_direction *direction_get(struct sctp_ctx *ctx, const struct cap_record *record)
{
    for (size_t i = 0; i < ctx->direction_count; i++)
    {
        struct sctp_direction *direction = &ctx->directions[i];
        bool is_same_direction = direction->src_addr == record->src_addr
                              && direction->dst_addr == record->dst_addr
                              && direction->src_port == record->src_port
                              && direction->dst_port == record->dst_port;
        if (is_same_direction)
            return direction;
    }

    if (ctx->direction_count >= DIRECTION_MAX_COUNT)
        return NULL; // 표가 꽉 참. 밀어낼 칸을 고르는 기능은 아직 없다

    struct sctp_direction *direction = &ctx->directions[ctx->direction_count];
    ctx->direction_count++;

    // 키만 넣고 나머지(TSN 창·조각·vtag)는 0 으로 시작한다. 0 은 "아직 본 것 없음"을 뜻한다
    *direction = (struct sctp_direction){
        .src_addr = record->src_addr,
        .dst_addr = record->dst_addr,
        .src_port = record->src_port,
        .dst_port = record->dst_port,
    };
    return direction;
}

/* tsn_window_shift: TSN 창을 shift_bits 비트만큼 앞으로 민다. 맨 앞(오래된 TSN)의 비트는 버리고, 뒤에 새로 생기는 비트는 0 이다.
 *   이유: 창 끝보다 앞선 TSN 이 오면 창을 옮겨야 그 TSN 을 표시할 수 있다. base_tsn 은 호출한 쪽이 같이 옮긴다.
 *   창 위치 k 의 비트는 window_bits[k / 64] 의 (k % 64)번 비트다. 밀고 나면 새 위치 k 의 비트 = 옛 위치 k + shift_bits 의 비트.
 */
static void tsn_window_shift(struct tsn_space *space, uint32_t shift_bits)
{
    if (shift_bits >= TSN_WINDOW_BITS)
    {
        memset(space->window_bits, 0, sizeof(space->window_bits)); // 옛 비트가 하나도 창에 남지 않는다
        return;
    }

    size_t word_count = TSN_WINDOW_BITS / TSN_WINDOW_WORD_BITS;
    size_t word_shift = shift_bits / TSN_WINDOW_WORD_BITS;  // 칸 단위로 옮길 수
    unsigned bit_shift = shift_bits % TSN_WINDOW_WORD_BITS; // 칸 안에서 더 옮길 비트 수

    // 앞 칸부터 채운다. 읽는 칸(i + word_shift 이상)은 아직 덮어쓰지 않은 칸이라 제자리에서 옮길 수 있다
    for (size_t i = 0; i < word_count; i++)
    {
        // 새 칸 i = 옛 칸 i + word_shift 의 윗부분 + 그 다음 칸의 아랫부분. 창 밖의 옛 칸은 0 으로 본다
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

// tsn_result: tsn_mark 의 판정 결과
enum tsn_result
{
    TSN_NEW,       // 처음 본 TSN. 창에 표시했다
    TSN_DUPLICATE, // 이미 본 TSN(재전송)
    TSN_TOO_OLD,   // 창보다 오래되어 처음인지 알 수 없음
};

/* tsn_mark: 받은 DATA 청크의 TSN 을 처음 본 것인지 판정하고, 처음이면 창에 표시한다.
 *   이유: 수동 관측자는 재전송된 DATA 도 그대로 보므로, 중복을 걸러야 같은 메시지를 상위로 두 번 넘기지 않는다.
 *   TSN 은 2^32 다음에 0 으로 돌아온다. 그래서 뺄셈 결과를 부호 있는 값으로 보고 앞뒤를 정한다(직렬번호 산술, RFC 9260 §1.6).
 *   반환: TSN_NEW / TSN_DUPLICATE / TSN_TOO_OLD.
 *   함께 바뀌는 것: space 의 창·base_tsn. ctx 는 유실 추정(F10)에서 통계를 쓰려고 미리 받는다.
 */
static enum tsn_result tsn_mark(struct sctp_ctx *ctx, struct tsn_space *space, uint32_t tsn)
{
    if (!space->has_base)
    {
        // 이 방향의 첫 TSN(캡처 도중 합류 포함). 창 가운데에 두어, 이보다 앞선 TSN 이 늦게 와도 처음 본 것으로 받는다
        space->has_base = true;
        space->base_tsn = tsn - TSN_WINDOW_BITS / 2;
        memset(space->window_bits, 0, sizeof(space->window_bits));
    }

    int32_t window_offset = (int32_t)(tsn - space->base_tsn); // 창 안 위치. 음수면 창 시작보다 앞
    if (window_offset < 0)
        return TSN_TOO_OLD;

    if (window_offset >= TSN_WINDOW_BITS)
    {
        // tsn 이 창 마지막 비트에 오는 최소 이동(window_offset - TSN_WINDOW_BITS + 1)에 여유를 더한다
        uint32_t shift_bits = (uint32_t)window_offset - TSN_WINDOW_BITS + 1 + TSN_SHIFT_SLACK_BITS;
        tsn_window_shift(space, shift_bits);
        space->base_tsn += shift_bits;
        window_offset -= (int32_t)shift_bits;
    }

    size_t word_index = (size_t)window_offset / TSN_WINDOW_WORD_BITS;
    uint64_t bit_mask = (uint64_t)1 << ((size_t)window_offset % TSN_WINDOW_WORD_BITS);
    if (space->window_bits[word_index] & bit_mask)
        return TSN_DUPLICATE;

    space->window_bits[word_index] |= bit_mask;
    return TSN_NEW;
}

/* sctp_input: 캡처한 패킷 하나를 처리한다.
 *   1) 패킷 수를 세고, 공통 헤더가 없는 패킷은 버리고, 캡처가 잘린 패킷은 표시한다.
 *   2) 패킷 방향의 레코드를 찾는다(없으면 만든다). 방향 표가 꽉 차면 이 패킷은 처리하지 않는다.
 *   3) 공통 헤더 뒤의 청크를 하나씩 읽는다(번들링). DATA 청크는 먼저 TSN 을 판정해, 이미 본 것(재전송)이나
 *      창보다 오래된 것은 세고 버린다. 완성된 메시지를 담은 DATA 청크는 바로 전달한다.
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

    // 이 패킷 방향의 상태(TSN 창·조각·vtag)를 담을 레코드. 지금은 TSN 창만 쓴다
    struct sctp_direction *direction = direction_get(ctx, record);
    if (!direction)
        return; // 방향 표가 꽉 차 상태를 둘 곳이 없다

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

            // 조각 청크도 자기 TSN 이 있다. 완성 메시지인지 가르기 전에 판정해야 재전송된 조각도 걸러진다
            enum tsn_result mark_result = tsn_mark(ctx, &direction->tsn, chunk.tsn);
            if (mark_result == TSN_DUPLICATE)
            {
                ctx->stats.duplicate_chunk_count++; // 재전송. 처음 온 청크를 이미 처리했다
                break;
            }
            if (mark_result == TSN_TOO_OLD)
            {
                ctx->stats.too_old_chunk_count++; // 중복인지 알 수 없다. 두 번 넘길 수 있으므로 넘기지 않는다
                break;
            }

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
