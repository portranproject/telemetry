#include "libsink/sink.h"

#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

// MARK: - 상수

#define NELEM(array) (sizeof(array) / sizeof((array)[0]))

#define JSON_VERSION 1 // 탐지 명세 §3 의 ver. 다른 값이면 줄을 버림

// 세션 문자열 "YYYYMMDDTHHMMSSZ" 16자 + NUL. 탐지 명세 §3 — 기동 시각 UTC, 기동마다 새로
#define SESSION_BYTES 17

// hello 에 싣는 설정 문자열(producer·node_id) 상한. 이스케이프 최악(바이트마다 \u00XX 6배)에도 hello 버퍼에 들어가게 — gethostname 은 64 이하
#define HELLO_STRING_MAX_BYTES 128
// hello 줄 버퍼. 고정 부분 약 220 B + 문자열 둘 × 128 × 6. 줄 버퍼(line)는 보낼 줄이 들어 있어 hello 를 거기 만들 수 없음
#define HELLO_LINE_CAP 2048

// 줄 안 중첩 깊이 상한(객체·배열). 탐지 줄은 kpm2 의 {cc:{카운터:{}}} 로 깊이 3 이 최대 — 넘으면 코드 버그라 줄을 버림
#define LINE_DEPTH_MAX 8

// NAS 확장 프로토콜 판별자 5GMM(TS 24.501 9.2). ue_evt 이름표의 키 — 5GSM(0x2e)은 탐지 명세 §6.4 에 없어 줄을 내지 않음.
//   libnas 에 같은 상수가 있지만 sink 는 해석기 헤더를 include 하지 않음(공용 헤더 규칙)
#define NAS_EPD_5GMM 0x7e

// S-TMSI 값의 비트 폭(TS 23.003 2.10.1: 5G-S-TMSI 48 = AMF Set ID 10 + AMF Pointer 6 + 5G-TMSI 32). 탐지 명세 §6.4 의 hex 자릿수 12·10·3 의 근거
#define S_TMSI_BITS 48
#define S_TMSI_PART1_BITS 39 // RRCSetupRequest ng-5G-S-TMSI-Part1(TS 38.331 6.2.2) — 하위 39비트
#define S_TMSI_PART2_BITS 9  // RRCSetupComplete ng-5G-S-TMSI-Part2 — 상위 9비트

// sht(바깥 보안 헤더 유형, TS 24.501 9.3.1)의 최댓값. 0 평문 ~ 4 새 보안 문맥·암호. 엔진은 4 를 넘으면 줄을 버림
#define NAS_SHT_MAX 4

// MARK: - 자료구조

// line_buf: JSON 한 줄을 만드는 버퍼. 넘치면 is_overflowed 만 켜고 더 쓰지 않아, 다 만든 뒤 한 번만 검사하면 됨
struct line_buf {
    char *data;
    size_t cap;
    size_t len;
    bool is_overflowed;
    int depth;                     // 지금 열려 있는 객체·배열 수
    bool has_item[LINE_DEPTH_MAX]; // 깊이마다 앞에 항목이 있어 ',' 가 필요한지
    bool is_after_key;             // 바로 앞이 "key": 라 다음 값 앞에 ',' 를 안 붙임
};

struct sink {
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    bool has_producer;
    char producer[HELLO_STRING_MAX_BYTES + 1];
    bool has_node_id;
    char node_id[HELLO_STRING_MAX_BYTES + 1];
    FILE *record_file; // 빌려 씀. sink_free 가 닫지 않음
    uint64_t record_max_bytes;
    uint32_t period_ms;
    uint32_t noreply_timeout_ms;

    char session[SESSION_BYTES];
    uint64_t seq; // 마지막으로 만든 줄의 번호. 줄을 만들면 하나 올림 — 못 보낸 줄의 번호는 건너뛰어 엔진이 유실을 seq_gap 으로 봄

    int fd;                           // 소켓. 끊겨 있으면 -1
    bool has_attempted_connect;       // 첫 시도는 간격 규칙 없이 바로
    uint64_t last_connect_attempt_ms; // CLOCK_MONOTONIC. 재접속 1초 간격의 기준(끊김을 안 시각도 여기에)

    char line[SINK_LINE_MAX_BYTES + 1]; // 객체 65,536 B(탐지 명세 §2, 줄바꿈 제외) + '\n'
    char hello_line[HELLO_LINE_CAP];
    struct sink_stats stats;
};

// MARK: - 시각

/* monotonic_ms: 재접속 간격을 재는 시계. 캡처 시각이 아닌 이유: 재생 때 캡처 시각은 실제 시간과 다름 */
static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

/* session_now: 지금 UTC 시각을 탐지 명세 §3 모양 "YYYYMMDDTHHMMSSZ" 로. 실패면 false */
static bool session_now(char out[SESSION_BYTES]) {
    time_t now = time(NULL);
    struct tm utc;
    if (!gmtime_r(&now, &utc)) {
        return false;
    }
    return strftime(out, SESSION_BYTES, "%Y%m%dT%H%M%SZ", &utc) == SESSION_BYTES - 1;
}

// MARK: - 설정 문자열 검사

/* is_valid_utf8: RFC 3629 모양인지(길이·이어지는 바이트·overlong·서로게이트·U+10FFFF 초과).
 *   이유: 탐지 엔진은 UTF-8 이 깨진 줄을 버리고, hello 가 버려지면 그 뒤 세션 전체가 죽음 — 설정 단계에서 막음.
 *   NUL 에서 멈추므로 끝을 넘어 읽지 않음(이어지는 바이트 검사가 NUL 을 틀린 바이트로 봄).
 */
static bool is_valid_utf8(const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;
    while (*cursor) {
        unsigned char lead = *cursor;
        size_t seq_len;
        if (lead < 0x80) {
            seq_len = 1;
        } else if (lead >= 0xC2 && lead <= 0xDF) {
            seq_len = 2;
        } else if (lead >= 0xE0 && lead <= 0xEF) {
            seq_len = 3;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            seq_len = 4;
        } else {
            return false;
        }
        for (size_t i = 1; i < seq_len; i++) {
            if ((cursor[i] & 0xC0) != 0x80) {
                return false;
            }
        }
        bool is_overlong_3 = seq_len == 3 && lead == 0xE0 && cursor[1] < 0xA0;
        bool is_surrogate = seq_len == 3 && lead == 0xED && cursor[1] >= 0xA0;
        bool is_overlong_4 = seq_len == 4 && lead == 0xF0 && cursor[1] < 0x90;
        bool is_over_max = seq_len == 4 && lead == 0xF4 && cursor[1] >= 0x90;
        if (is_overlong_3 || is_surrogate || is_overlong_4 || is_over_max) {
            return false;
        }
        cursor += seq_len;
    }
    return true;
}

// MARK: - JSON 줄 만들기

static void line_reset(struct line_buf *line) {
    line->len = 0;
    line->is_overflowed = false;
    line->depth = 0;
    line->has_item[0] = false;
    line->is_after_key = false;
}

/* line_put_bytes: 바이트 n 개를 붙임. 상한을 넘으면 is_overflowed 를 켜고 그 뒤로는 아무것도 쓰지 않음 */
static void line_put_bytes(struct line_buf *line, const char *bytes, size_t n) {
    if (line->is_overflowed) {
        return;
    }
    if (line->len + n > line->cap) {
        line->is_overflowed = true;
        return;
    }
    memcpy(line->data + line->len, bytes, n);
    line->len += n;
}

static void line_put_char(struct line_buf *line, char c) {
    line_put_bytes(line, &c, 1);
}

/* line_put_escaped: 문자열을 따옴표 없이 이스케이프해 붙임. 따옴표 안에 여러 조각을 이어 쓸 때(F1AP cause "<범주>:<값>") 씀.
 *   탐지 명세 부록 B: "·\·제어 문자. \n·\r·\t 는 그 이름으로, 나머지 제어 문자는 \u00XX. 0x20 이상은 그대로(UTF-8 은 설정 때 검사함)
 */
static void line_put_escaped(struct line_buf *line, const char *text) {
    static const char hex_digits[] = "0123456789abcdef";
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor; cursor++) {
        unsigned char c = *cursor;
        if (c == '"') {
            line_put_bytes(line, "\\\"", 2);
        } else if (c == '\\') {
            line_put_bytes(line, "\\\\", 2);
        } else if (c == '\n') {
            line_put_bytes(line, "\\n", 2);
        } else if (c == '\r') {
            line_put_bytes(line, "\\r", 2);
        } else if (c == '\t') {
            line_put_bytes(line, "\\t", 2);
        } else if (c < 0x20) {
            char escaped[6] = {'\\', 'u', '0', '0', hex_digits[c >> 4], hex_digits[c & 0x0f]};
            line_put_bytes(line, escaped, sizeof escaped);
        } else {
            line_put_char(line, (char)c);
        }
    }
}

/* line_put_quoted: 문자열을 따옴표로 싸서 이스케이프해 붙임 */
static void line_put_quoted(struct line_buf *line, const char *text) {
    line_put_char(line, '"');
    line_put_escaped(line, text);
    line_put_char(line, '"');
}

/* line_value_start: 값 하나를 쓰기 전에 ',' 가 필요한지 정함. "key": 바로 뒤면 안 붙이고, 같은 깊이에 앞 항목이 있으면 붙임 */
static void line_value_start(struct line_buf *line) {
    if (line->is_after_key) {
        line->is_after_key = false;
        return;
    }
    if (line->has_item[line->depth]) {
        line_put_char(line, ',');
    }
    line->has_item[line->depth] = true;
}

static void line_key(struct line_buf *line, const char *key) {
    line_value_start(line);
    line_put_quoted(line, key);
    line_put_char(line, ':');
    line->is_after_key = true;
}

static void line_string(struct line_buf *line, const char *text) {
    line_value_start(line);
    line_put_quoted(line, text);
}

static void line_u64(struct line_buf *line, uint64_t value) {
    char digits[21]; // 2^64 는 20자리 + NUL
    int n = snprintf(digits, sizeof digits, "%llu", (unsigned long long)value);
    line_value_start(line);
    line_put_bytes(line, digits, (size_t)n);
}

static void line_bool(struct line_buf *line, bool value) {
    line_value_start(line);
    if (value) {
        line_put_bytes(line, "true", 4);
    } else {
        line_put_bytes(line, "false", 5);
    }
}

static void line_null(struct line_buf *line) {
    line_value_start(line);
    line_put_bytes(line, "null", 4);
}

/* line_open: 객체('{') 또는 배열('[') 을 엶. 깊이 상한을 넘으면 코드 버그라 넘침으로 처리해 줄을 버림 */
static void line_open(struct line_buf *line, char bracket) {
    line_value_start(line);
    line_put_char(line, bracket);
    if (line->depth + 1 >= LINE_DEPTH_MAX) {
        line->is_overflowed = true;
        return;
    }
    line->depth++;
    line->has_item[line->depth] = false;
}

static void line_close(struct line_buf *line, char bracket) {
    if (line->depth == 0) {
        line->is_overflowed = true;
        return;
    }
    line->depth--;
    line_put_char(line, bracket);
}

/* line_common_head: 모든 줄의 앞 네 키(탐지 명세 §3). 한 곳에서 써야 session·ver 가 줄 종류마다 어긋나지 않음 */
static void line_common_head(struct line_buf *line, const struct sink *sink, const char *type, uint64_t seq) {
    line_key(line, "type");
    line_string(line, type);
    line_key(line, "ver");
    line_u64(line, JSON_VERSION);
    line_key(line, "session");
    line_string(line, sink->session);
    line_key(line, "seq");
    line_u64(line, seq);
}

/* line_finish: 객체를 닫고 '\n'. 열린 것이 하나(맨 바깥 객체)가 아니면 코드 버그라 넘침으로 */
static void line_finish(struct line_buf *line) {
    if (line->depth != 1) {
        line->is_overflowed = true;
        return;
    }
    line_close(line, '}');
    line_put_char(line, '\n');
}

// MARK: - 녹화·소켓

/* record_write: 보낸 줄을 녹화 파일에도. 상한을 넘거나 쓰기가 실패하면 녹화만 멈춤(소켓 전송은 영향 없음).
 *   줄마다 fflush 하는 이유: 프로그램이 죽어도 그때까지 보낸 줄이 파일에 남게
 */
static void record_write(struct sink *sink, const char *data, size_t len) {
    if (!sink->record_file || sink->stats.is_record_stopped) {
        return;
    }
    bool is_over_cap = sink->record_max_bytes != 0 && sink->stats.record_bytes + len > sink->record_max_bytes;
    if (is_over_cap) {
        sink->stats.is_record_stopped = true;
        return;
    }
    if (fwrite(data, 1, len, sink->record_file) != len || fflush(sink->record_file) != 0) {
        sink->stats.is_record_stopped = true;
        return;
    }
    sink->stats.record_bytes += len;
}

/* send_all: 줄 전체를 보냄. 끊겼거나 SO_SNDTIMEO 안에 못 보내면 false(그 사이 일부가 나갔을 수 있음 — 부르는 쪽이 소켓을 닫음).
 *   MSG_NOSIGNAL: 상대가 닫힌 소켓에 쓰면 SIGPIPE 로 프로그램이 죽으므로 EPIPE 오류로 받음
 */
static bool send_all(int fd, const char *data, size_t len) {
    while (len > 0) {
        ssize_t sent = send(fd, data, len, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0) {
            return false;
        }
        data += sent;
        len -= (size_t)sent;
    }
    return true;
}

/* connection_close: 소켓을 닫고 끊긴 시각을 남김 — 다음 접속 시도는 SINK_RECONNECT_INTERVAL_MS 뒤 */
static void connection_close(struct sink *sink) {
    if (sink->fd >= 0) {
        close(sink->fd);
        sink->fd = -1;
    }
    sink->last_connect_attempt_ms = monotonic_ms();
}

/* socket_connect: 소켓을 만들어 보내기 상한을 걸고 접속. 실패면 -1 */
static int socket_connect(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    struct timeval send_timeout = {
        .tv_sec = SINK_SEND_TIMEOUT_MS / 1000,
        .tv_usec = (SINK_SEND_TIMEOUT_MS % 1000) * 1000,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof send_timeout) < 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    memcpy(addr.sun_path, path, strlen(path) + 1); // 길이는 sink_new 가 검사함
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* hello_send: 접속 직후 hello 한 줄(탐지 명세 §4). 접속마다 첫 줄이어야 그 뒤 줄이 받아들여짐.
 *   cells 는 넣지 않음(선택 필드 — 셀이 늘면 목록이 바뀌어 엔진이 처음부터 다시 시작하므로). si_sample_ms 는 period_ms 와 같은 값.
 *   부작용: seq 하나, 통계, 녹화. 반환: 보냈으면 true
 */
static bool hello_send(struct sink *sink) {
    struct line_buf line = {.data = sink->hello_line, .cap = sizeof sink->hello_line};
    line_reset(&line);
    sink->seq++;
    line_open(&line, '{');
    line_common_head(&line, sink, "hello", sink->seq);
    if (sink->has_producer) {
        line_key(&line, "producer");
        line_string(&line, sink->producer);
    }
    if (sink->has_node_id) {
        line_key(&line, "node_id");
        line_string(&line, sink->node_id);
    }
    line_key(&line, "period_ms");
    line_u64(&line, sink->period_ms);
    line_key(&line, "noreply_timeout_ms");
    line_u64(&line, sink->noreply_timeout_ms);
    line_key(&line, "si_sample_ms");
    line_u64(&line, sink->period_ms);
    line_key(&line, "clock");
    line_string(&line, "realtime");
    line_key(&line, "ue_evt");
    line_bool(&line, true);
    line_finish(&line);
    if (line.is_overflowed) {
        return false; // 문자열 상한을 지켰으면 생길 수 없음
    }
    if (!send_all(sink->fd, line.data, line.len)) {
        sink->stats.write_error_count++;
        return false;
    }
    sink->stats.line_count++;
    sink->stats.hello_count++;
    record_write(sink, line.data, line.len);
    return true;
}

/* connection_ensure: 접속돼 있으면 그대로 true. 아니면 간격 규칙(첫 시도는 바로, 그 뒤 1초) 안에서 한 번 접속해 hello 를 보냄.
 *   접속을 첫 줄 때까지 미루는 이유: 탐지 엔진이 늦게 떠도 sink_new 가 실패하지 않고, 끊김과 같은 재접속 규칙 하나로 처리됨.
 *   반환: 이 줄을 보낼 수 있는 상태면 true
 */
static bool connection_ensure(struct sink *sink) {
    if (sink->fd >= 0) {
        return true;
    }
    uint64_t now_ms = monotonic_ms();
    bool is_too_soon = sink->has_attempted_connect && now_ms - sink->last_connect_attempt_ms < SINK_RECONNECT_INTERVAL_MS;
    if (is_too_soon) {
        return false;
    }
    sink->has_attempted_connect = true;
    sink->last_connect_attempt_ms = now_ms;
    int fd = socket_connect(sink->socket_path);
    if (fd < 0) {
        return false;
    }
    sink->fd = fd;
    if (sink->stats.hello_count > 0) {
        sink->stats.reconnect_count++;
    }
    if (!hello_send(sink)) {
        connection_close(sink);
        return false;
    }
    return true;
}

/* line_emit: 다 만든 줄을 보냄. 넘침·끊김·쓰기 실패는 이유별로 세고 돌려줌.
 *   쓰기 실패 뒤 소켓을 닫는 이유: 줄이 반쯤 나갔을 수 있어, 닫아야 엔진이 반쪽 줄을 버리고 다음 hello 부터 새로 읽음
 */
static enum sink_result line_emit(struct sink *sink, const struct line_buf *line, bool is_connected) {
    if (line->is_overflowed) {
        sink->stats.too_long_drop_count++;
        return SINK_DROPPED_TOO_LONG;
    }
    if (!is_connected) {
        sink->stats.disconnected_drop_count++;
        return SINK_DROPPED_DISCONNECTED;
    }
    if (!send_all(sink->fd, line->data, line->len)) {
        sink->stats.write_error_count++;
        connection_close(sink);
        return SINK_DROPPED_WRITE_FAILED;
    }
    sink->stats.line_count++;
    record_write(sink, line->data, line->len);
    return SINK_OK;
}

// MARK: - 생성·해제·통계

struct sink *sink_new(const struct sink_cfg *cfg) {
    if (!cfg) {
        return NULL;
    }
    // 탐지 명세 §4: period_ms·noreply_timeout_ms 는 1 이상 정수. 0 이면 hello 가 버려져 세션 전체가 죽음
    if (cfg->period_ms == 0 || cfg->noreply_timeout_ms == 0) {
        return NULL;
    }
    const char *socket_path = cfg->socket_path ? cfg->socket_path : SINK_DEFAULT_SOCKET_PATH;
    if (strlen(socket_path) >= sizeof(((struct sink *)0)->socket_path)) {
        return NULL;
    }
    bool is_producer_ok = !cfg->producer || (strlen(cfg->producer) <= HELLO_STRING_MAX_BYTES && is_valid_utf8(cfg->producer));
    bool is_node_id_ok = !cfg->node_id || (strlen(cfg->node_id) <= HELLO_STRING_MAX_BYTES && is_valid_utf8(cfg->node_id));
    if (!is_producer_ok || !is_node_id_ok) {
        return NULL;
    }
    struct sink *sink = calloc(1, sizeof *sink);
    if (!sink) {
        return NULL;
    }
    memcpy(sink->socket_path, socket_path, strlen(socket_path) + 1);
    if (cfg->producer) {
        sink->has_producer = true;
        memcpy(sink->producer, cfg->producer, strlen(cfg->producer) + 1);
    }
    if (cfg->node_id) {
        sink->has_node_id = true;
        memcpy(sink->node_id, cfg->node_id, strlen(cfg->node_id) + 1);
    }
    sink->record_file = cfg->record_file;
    sink->record_max_bytes = cfg->record_max_bytes;
    sink->period_ms = cfg->period_ms;
    sink->noreply_timeout_ms = cfg->noreply_timeout_ms;
    sink->fd = -1;
    if (!session_now(sink->session)) {
        free(sink);
        return NULL;
    }
    return sink;
}

const struct sink_stats *sink_get_stats(const struct sink *sink) {
    return sink ? &sink->stats : NULL;
}

void sink_free(struct sink *sink) {
    if (!sink) {
        return;
    }
    if (sink->fd >= 0) {
        close(sink->fd);
    }
    free(sink);
}

// MARK: - f1_evt

/* f1_kind_name: 탐지 명세 §6.7 의 두 값. 그 밖은 NULL(줄을 버림 — 엔진도 다른 값은 버림) */
static const char *f1_kind_name(enum report_f1_kind kind) {
    if (kind == REPORT_F1_KIND_SETUP) {
        return "F1SetupRequest";
    }
    if (kind == REPORT_F1_KIND_RESET) {
        return "F1Reset";
    }
    return NULL;
}

enum sink_result sink_on_f1_event(struct sink *sink, const struct report_f1_event *event) {
    if (!sink) {
        return SINK_DROPPED_INVALID;
    }
    const char *msg_name = event ? f1_kind_name(event->kind) : NULL;
    bool is_cells_valid = event && (!event->cells_known || event->cell_count == 0 || event->cell_ids);
    bool is_du_ue_ids_valid = event && (event->du_ue_id_count == 0 || event->du_ue_ids);
    bool is_count_valid = event && event->cell_count >= 0 && event->du_ue_id_count >= 0;
    if (!msg_name || !is_cells_valid || !is_du_ue_ids_valid || !is_count_valid) {
        sink->stats.invalid_drop_count++;
        return SINK_DROPPED_INVALID;
    }
    // 접속(필요하면 hello)을 줄을 만들기 전에 — hello 가 이 줄보다 작은 seq 를 받아야 엔진이 이 줄을 역행으로 버리지 않음
    bool is_connected = connection_ensure(sink);
    struct line_buf line = {.data = sink->line, .cap = sizeof sink->line};
    line_reset(&line);
    sink->seq++;
    line_open(&line, '{');
    line_common_head(&line, sink, "f1_evt", sink->seq);
    line_key(&line, "t_ms");
    line_u64(&line, event->t_ms);
    line_key(&line, "msg");
    line_string(&line, msg_name);
    line_key(&line, "cells"); // 키는 늘 — 없으면 엔진이 줄을 버림. 모르면 null(= 모든 셀), [] 는 아무것도 닫지 않음
    if (!event->cells_known) {
        line_null(&line);
    } else {
        line_open(&line, '[');
        for (int i = 0; i < event->cell_count; i++) {
            line_u64(&line, event->cell_ids[i]);
        }
        line_close(&line, ']');
    }
    if (event->du_ue_id_count > 0) {
        line_key(&line, "du_ue_ids");
        line_open(&line, '[');
        for (int i = 0; i < event->du_ue_id_count; i++) {
            line_u64(&line, event->du_ue_ids[i]);
        }
        line_close(&line, ']');
    }
    line_finish(&line);
    return line_emit(sink, &line, is_connected);
}

// MARK: - kpm2

/* line_real: 실수 값. 정수면 정수로 찍음(탐지 명세 §5.3 "정수도 됨", 참조 샘플도 정수), 아니면 소수 3자리.
 *   유한하지 않은 값(nan·무한대)은 JSON 에 없어 부르는 쪽이 null 로 — 여기에 오면 안 됨
 */
static void line_real(struct line_buf *line, double value) {
    bool is_integral = value >= 0 && value < 1e15 && (double)(uint64_t)value == value;
    if (is_integral) {
        line_u64(line, (uint64_t)value);
        return;
    }
    char digits[64];
    int n = snprintf(digits, sizeof digits, "%.3f", value);
    line_value_start(line);
    line_put_bytes(line, digits, (size_t)n);
}

// counter_check 결과. INVALID 는 엔진이 줄을 버리는 모양, WARNING 은 엔진이 경고만 내고 받는 모양(원인 합 ≠ total)
enum counter_check_result { COUNTER_OK,
                            COUNTER_WARNING,
                            COUNTER_INVALID };

/* counter_check: 원인별 카운터 입력 검사. 원인 이름이 없거나 "total" 이면 줄이 깨지므로 INVALID(엔진: "total" 을 뺀 모든 키를 원인으로 봄).
 *   0 인 원인은 쓰지 않으므로 합에서도 뺌 — 엔진은 받은 원인만 더해 total 과 대조하고, 다르면 경고 뒤 total 을 씀
 */
static enum counter_check_result counter_check(const struct report_counter *counter) {
    if (!counter->is_counted) {
        return COUNTER_OK;
    }
    bool is_array_valid = counter->cause_count >= 0 && (counter->cause_count == 0 || counter->causes);
    if (!is_array_valid) {
        return COUNTER_INVALID;
    }
    uint64_t sum = 0;
    bool has_nonzero_cause = false;
    for (int i = 0; i < counter->cause_count; i++) {
        const struct report_cause_count *cause = &counter->causes[i];
        bool is_name_valid = cause->name && cause->name[0] != '\0' && strcmp(cause->name, "total") != 0;
        if (!is_name_valid) {
            return COUNTER_INVALID;
        }
        if (cause->count == 0) {
            continue;
        }
        has_nonzero_cause = true;
        sum += cause->count;
    }
    if (has_nonzero_cause && sum != counter->total) {
        return COUNTER_WARNING;
    }
    return COUNTER_OK;
}

/* counter_write: "키":{"total":n,"<원인>":m,…} 또는 null. 0 인 원인은 쓰지 않음(탐지 명세 §5.1: 0 이 아닌 원인만, 합 = total) */
static void counter_write(struct line_buf *line, const char *key, const struct report_counter *counter) {
    line_key(line, key);
    if (!counter->is_counted) {
        line_null(line);
        return;
    }
    line_open(line, '{');
    line_key(line, "total");
    line_u64(line, counter->total);
    for (int i = 0; i < counter->cause_count; i++) {
        if (counter->causes[i].count == 0) {
            continue;
        }
        line_key(line, counter->causes[i].name);
        line_u64(line, counter->causes[i].count);
    }
    line_close(line, '}');
}

/* inferred_write: "키":n 또는 null — 그 카운터의 추정분. 세지 못한 카운터는 추정분도 없음 */
static void inferred_write(struct line_buf *line, const char *key, const struct report_counter *counter) {
    line_key(line, key);
    if (counter->is_counted) {
        line_u64(line, counter->inferred);
    } else {
        line_null(line);
    }
}

/* optional_u64_write: "키":n 또는 null. 세지 못한 지표는 null(0 은 '셌고 0건' 이라 따로 — 탐지 명세 §5.3) */
static void optional_u64_write(struct line_buf *line, const char *key, bool has_value, uint64_t value) {
    line_key(line, key);
    if (has_value) {
        line_u64(line, value);
    } else {
        line_null(line);
    }
}

/* optional_real_write: 위와 같되 실수. 유한하지 않으면 null(JSON 에 nan 이 없어 줄 전체가 깨짐) */
static void optional_real_write(struct line_buf *line, const char *key, bool has_value, double value) {
    line_key(line, key);
    if (has_value && isfinite(value)) {
        line_real(line, value);
    } else {
        line_null(line);
    }
}

/* kpm2_cc_write: cc 객체. 키 순서는 탐지 명세 §5 참조 샘플과 같게(엔진은 순서를 안 보지만 사람이 diff 로 보게) */
static void kpm2_cc_write(struct line_buf *line, const struct report_period *period) {
    line_key(line, "cc");
    line_open(line, '{');
    counter_write(line, "RRC.ConnEstabAtt", &period->conn_estab_att);
    counter_write(line, "RRC.ConnEstabSucc", &period->conn_estab_succ);
    line_key(line, "RRC.ConnEstabFailCause"); // 셋을 한 객체로, 탐지 명세 §5.1 은 셋 다 넣음. NoReply 가 없으면 1단계가 축소 판정
    if (period->has_fail_cause) {
        line_open(line, '{');
        line_key(line, "NetworkReject");
        line_u64(line, period->network_reject);
        line_key(line, "NoReply");
        line_u64(line, period->no_reply);
        line_key(line, "Other");
        line_u64(line, period->other);
        line_close(line, '}');
    } else {
        line_null(line);
    }
    optional_u64_write(line, "RRC.RelWithoutSuspendConfig", period->has_rel_without_suspend, period->rel_without_suspend);
    counter_write(line, "UECNTX.ConnEstabAtt", &period->uectx_estab_att);
    counter_write(line, "UECNTX.ConnEstabSucc", &period->uectx_estab_succ);
    optional_u64_write(line, "RRC.ReEstabAtt", period->has_reestab, period->reestab_att);
    optional_u64_write(line, "RRC.ReEstabSuccWithUeContext", period->has_reestab, period->reestab_succ);
    counter_write(line, "RRC.ResumeAtt", &period->resume_att);
    counter_write(line, "RRC.ResumeSucc", &period->resume_succ);
    line_close(line, '}');
}

/* kpm2_si_write: si 객체. 주기 안 축출로 상한이 유효하지 않으면 Mean·Max 를 null — 최댓값이 실제보다 작게 나가면 유령 정리 기준이 틀림 */
static void kpm2_si_write(struct line_buf *line, const struct report_period *period) {
    bool has_conn = period->has_conn_si && period->is_conn_upper_valid;
    bool has_inactive = period->has_inactive_si && period->is_inactive_upper_valid;
    line_key(line, "si");
    line_open(line, '{');
    optional_real_write(line, "RRC.ConnMean", has_conn, period->conn_mean);
    optional_u64_write(line, "RRC.ConnMax", has_conn, period->conn_max);
    optional_real_write(line, "RRC.InactiveConnMean", has_inactive, period->inactive_mean);
    optional_u64_write(line, "RRC.InactiveConnMax", has_inactive, period->inactive_max);
    line_close(line, '}');
}

/* kpm2_ext_write: ext 객체(탐지 명세 §5.4). UeCtxMax 는 경보 심각도에 씀 */
static void kpm2_ext_write(struct line_buf *line, const struct report_period *period) {
    line_key(line, "ext");
    line_open(line, '{');
    optional_u64_write(line, "UeCtxMax", period->has_ue_ctx_max, period->ue_ctx_max);
    optional_u64_write(line, "DuCannotServe", period->has_du_cannot_serve, period->du_cannot_serve);
    optional_u64_write(line, "CrntiAlloc", period->has_crnti_alloc, period->crnti_alloc);
    line_close(line, '}');
}

/* kpm2_inferred_write: cc 의 형제 칸 "inferred" — 카운터마다 추정으로 메운 수.
 *   cc 안(원인별 객체)에 넣으면 엔진이 원인으로 더해 total ≠ 합 경고가 남. 맨 위 모르는 키는 엔진이 무시(탐지 명세 §5.3·§6.3 계약) — 기록용
 */
static void kpm2_inferred_write(struct line_buf *line, const struct report_period *period) {
    line_key(line, "inferred");
    line_open(line, '{');
    inferred_write(line, "RRC.ConnEstabAtt", &period->conn_estab_att);
    inferred_write(line, "RRC.ConnEstabSucc", &period->conn_estab_succ);
    inferred_write(line, "UECNTX.ConnEstabAtt", &period->uectx_estab_att);
    inferred_write(line, "UECNTX.ConnEstabSucc", &period->uectx_estab_succ);
    inferred_write(line, "RRC.ResumeAtt", &period->resume_att);
    inferred_write(line, "RRC.ResumeSucc", &period->resume_succ);
    line_close(line, '}');
}

enum sink_result sink_on_period(struct sink *sink, const struct report_period *period) {
    if (!sink) {
        return SINK_DROPPED_INVALID;
    }
    if (!period) {
        sink->stats.invalid_drop_count++;
        return SINK_DROPPED_INVALID;
    }
    const struct report_counter *counters[] = {
        &period->conn_estab_att,
        &period->conn_estab_succ,
        &period->uectx_estab_att,
        &period->uectx_estab_succ,
        &period->resume_att,
        &period->resume_succ,
    };
    bool is_counter_valid = true;
    bool has_warning = false;
    for (size_t i = 0; i < NELEM(counters); i++) {
        enum counter_check_result check = counter_check(counters[i]);
        if (check == COUNTER_INVALID) {
            is_counter_valid = false;
        }
        if (check == COUNTER_WARNING) {
            has_warning = true;
        }
    }
    // 엔진이 줄을 버리는 모양: t_end ≤ t_start, 음수 평균. 경고만 내고 받는 모양(원인 합 ≠ total, 칸 길이 ≠ period_ms)은 보내고 셈 —
    //   줄을 버리면 칸이 비어 엔진이 그 구간을 보류하므로(탐지 명세 §5.6) 경고 하나보다 손해가 큼
    bool is_time_valid = period->t_end_ms > period->t_start_ms;
    bool is_mean_valid = !(period->has_conn_si && period->conn_mean < 0) && !(period->has_inactive_si && period->inactive_mean < 0);
    if (!is_time_valid || !is_mean_valid || !is_counter_valid) {
        sink->stats.invalid_drop_count++;
        return SINK_DROPPED_INVALID;
    }
    bool is_period_mismatch = period->t_end_ms - period->t_start_ms != sink->period_ms;
    if (has_warning || is_period_mismatch) {
        sink->stats.spec_warning_count++;
    }
    bool is_connected = connection_ensure(sink);
    struct line_buf line = {.data = sink->line, .cap = sizeof sink->line};
    line_reset(&line);
    sink->seq++;
    line_open(&line, '{');
    line_common_head(&line, sink, "kpm2", sink->seq);
    line_key(&line, "cell_id");
    line_u64(&line, period->cell_id);
    line_key(&line, "t_start_ms");
    line_u64(&line, period->t_start_ms);
    line_key(&line, "t_end_ms");
    line_u64(&line, period->t_end_ms);
    if (period->is_capture_alive) {
        kpm2_cc_write(&line, period);
        kpm2_si_write(&line, period);
        kpm2_ext_write(&line, period);
        kpm2_inferred_write(&line, period);
    } else {
        // 캡처가 멈췄거나 살아 있는지 확인되지 않은 칸: 0 으로 채우면 엔진이 조용한 정상 셀로 봄(탐지 명세 §5.3)
        line_key(&line, "cc");
        line_null(&line);
        line_key(&line, "si");
        line_null(&line);
        line_key(&line, "ext");
        line_null(&line);
        line_key(&line, "inferred");
        line_null(&line);
    }
    line_key(&line, "ue_evt_lost"); // 늘 빈 배열 — 없으면 엔진이 그 칸을 양방향 로스로 봐 2·3단계 판정을 보류(탐지 명세 §5.5)
    line_open(&line, '[');
    line_close(&line, ']');
    line_finish(&line);
    enum sink_result result = line_emit(sink, &line, is_connected);
    if (result != SINK_OK || !period->is_capture_alive) {
        return result;
    }
    for (size_t i = 0; i < NELEM(counters); i++) {
        if (counters[i]->is_counted) {
            sink->stats.inferred_count += counters[i]->inferred;
        }
    }
    return result;
}

// MARK: - ue_evt

/* line_hex: "0x" + 소문자 16진수 문자열. bits 비트를 담는 자릿수로 앞을 0 으로 채움(48 → 12자리, 39 → 10자리, 9 → 3자리 — 탐지 명세 §6.4).
 *   JSON 숫자로 보내면 엔진이 줄을 버림(opt_hex 는 문자열만)
 */
static void line_hex(struct line_buf *line, uint64_t value, int bits) {
    int digits = (bits + 3) / 4;
    char text[2 + 16 + 1]; // "0x" + 64비트 최대 16자리 + NUL
    int n = snprintf(text, sizeof text, "0x%0*llx", digits, (unsigned long long)value);
    line_value_start(line);
    line_put_char(line, '"');
    line_put_bytes(line, text, (size_t)n);
    line_put_char(line, '"');
}

/* nas_msg_detect_name: 5GMM 메시지 타입(TS 24.501 표 9.7.1) → 탐지 명세 §6.4 철자. 명세에 없는 메시지는 같은 꼴(띄어쓰기 없는 CamelCase)로 —
 *   엔진은 모르는 이름도 받아 이력에만 남김(parse_ue_evt). 발신 쪽이 다른 같은 메시지(0x45·0x47)는 한 이름 — 명세가 dir 로 가름.
 *   반환: 표에 없는 타입이면 NULL(줄을 버림 — "ProtectedNAS" 로 뭉개면 엔진이 인증 응답으로 인정해 버림)
 */
static const char *nas_msg_detect_name(int msg_type) {
    static const struct {
        int msg_type;
        const char *name;
    } names[] = {
        {0x41, "RegistrationRequest"},
        {0x42, "RegistrationAccept"},
        {0x43, "RegistrationComplete"},
        {0x44, "RegistrationReject"},
        {0x45, "DeregistrationRequest"}, // UE 발신
        {0x46, "DeregistrationAccept"},  // UE 발신에 대한 수락
        {0x47, "DeregistrationRequest"}, // 망 발신
        {0x48, "DeregistrationAccept"},  // 망 발신에 대한 수락
        {0x4c, "ServiceRequest"},
        {0x4d, "ServiceReject"},
        {0x4e, "ServiceAccept"},
        {0x4f, "ControlPlaneServiceRequest"},
        {0x50, "NetworkSliceSpecificAuthenticationCommand"},
        {0x51, "NetworkSliceSpecificAuthenticationComplete"},
        {0x52, "NetworkSliceSpecificAuthenticationResult"},
        {0x54, "ConfigurationUpdateCommand"},
        {0x55, "ConfigurationUpdateComplete"},
        {0x56, "AuthenticationRequest"},
        {0x57, "AuthenticationResponse"},
        {0x58, "AuthenticationReject"},
        {0x59, "AuthenticationFailure"},
        {0x5a, "AuthenticationResult"},
        {0x5b, "IdentityRequest"},
        {0x5c, "IdentityResponse"},
        {0x5d, "SecurityModeCommand"},
        {0x5e, "SecurityModeComplete"},
        {0x5f, "SecurityModeReject"},
        {0x64, "5GMMStatus"},
        {0x65, "Notification"},
        {0x66, "NotificationResponse"},
        {0x67, "ULNASTransport"},
        {0x68, "DLNASTransport"},
        {0x69, "RelayKeyRequest"},
        {0x6a, "RelayKeyAccept"},
        {0x6b, "RelayKeyReject"},
        {0x6c, "RelayAuthenticationRequest"},
        {0x6d, "RelayAuthenticationResponse"},
    };
    for (size_t i = 0; i < NELEM(names); i++) {
        if (names[i].msg_type == msg_type) {
            return names[i].name;
        }
    }
    return NULL;
}

/* reg_type_name: 5GS registration type 값(TS 24.501 9.11.3.7 하위 3비트) → 탐지 명세 §6.4 철자.
 *   표 9.11.3.7.1: 1 initial·2 mobility·3 periodic·4 emergency, 7 예약, 그 밖(0·5·6)은 "망이 받으면 initial 로 해석" → initial.
 *   반환: 예약·범위 밖이면 NULL(키 뺌)
 */
static const char *reg_type_name(int reg_type) {
    switch (reg_type) {
    case 0:
    case 1:
    case 5:
    case 6:
        return "initial";
    case 2:
        return "mobility";
    case 3:
        return "periodic";
    case 4:
        return "emergency";
    default:
        return NULL;
    }
}

/* id_type_name: 5GS mobile identity 종류(TS 24.501 표 9.11.3.4.1) → 탐지 명세 §6.4 의 넷. 그 밖(0 없음·4 5G-S-TMSI·6 MAC·7 EUI-64·-1 못 읽음)은 NULL(키 뺌) */
static const char *id_type_name(int id_type) {
    switch (id_type) {
    case 1:
        return "SUCI";
    case 2:
        return "5G-GUTI";
    case 3:
        return "IMEI";
    case 5:
        return "IMEISV";
    default:
        return NULL;
    }
}

/* nas_algorithm_name: NAS 보안 알고리즘 니블(TS 24.501 9.11.3.34) → "5G-EA0"~"5G-EA3" / "5G-IA0"~"5G-IA3". 4~7 은 예약이라 NULL(키 뺌) */
static const char *nas_algorithm_name(bool is_ciphering, int algorithm) {
    static const char *const ciphering_names[] = {"5G-EA0", "5G-EA1", "5G-EA2", "5G-EA3"};
    static const char *const integrity_names[] = {"5G-IA0", "5G-IA1", "5G-IA2", "5G-IA3"};
    if (algorithm < 0 || algorithm > 3) {
        return NULL;
    }
    return is_ciphering ? ciphering_names[algorithm] : integrity_names[algorithm];
}

/* ue_msg_name: 줄의 msg. RRC·F1AP 는 해석기 이름 그대로(탐지 철자와 같고, 엔진은 명세 표 밖 이름도 받음). NAS 는 안쪽을 못 읽었으면
 *   "ProtectedNAS"(탐지 명세 §6.2), 아니면 5GMM 이름표. 반환: 이름이 없으면 NULL(msg 는 필수라 줄을 버림)
 */
static const char *ue_msg_name(const struct report_ue_event *event) {
    if (event->proto == REPORT_PROTO_NAS) {
        if (event->nas_msg_type < 0) {
            return "ProtectedNAS";
        }
        if (event->nas_epd != NAS_EPD_5GMM) {
            return NULL;
        }
        return nas_msg_detect_name(event->nas_msg_type);
    }
    bool has_name = event->msg_name && event->msg_name[0] != '\0';
    return has_name ? event->msg_name : NULL;
}

/* ue_event_check: 공통 필드가 엔진이 버리는 모양인지(탐지 명세 §6.3, parse_ue_evt): dir·proto 없음, NAS 인데 via 없음·sht 범위 밖,
 *   du_ue_id 없음(NGAP 에서만 본 NAS 줄은 됨). 반환: 낼 수 있으면 true
 */
static bool ue_event_check(const struct report_ue_event *event) {
    bool is_direction_valid = event->direction == REPORT_DIRECTION_UL || event->direction == REPORT_DIRECTION_DL;
    bool is_proto_valid = event->proto == REPORT_PROTO_RRC || event->proto == REPORT_PROTO_NAS || event->proto == REPORT_PROTO_F1AP;
    bool is_nas = event->proto == REPORT_PROTO_NAS;
    bool is_via_valid = !is_nas || event->via == REPORT_NAS_VIA_F1 || event->via == REPORT_NAS_VIA_NGAP;
    bool is_sht_valid = !is_nas || (event->sht >= 0 && event->sht <= NAS_SHT_MAX);
    bool is_ngap_nas = is_nas && event->via == REPORT_NAS_VIA_NGAP;
    bool is_du_ue_id_valid = event->has_du_ue_id || is_ngap_nas;
    return is_direction_valid && is_proto_valid && is_via_valid && is_sht_valid && is_du_ue_id_valid;
}

// ue_f_keys: 이 줄의 f 에 실제로 쓸 키와 이름표를 거친 값. 쓰기 전에 정하는 이유: 하나도 없으면 f 키 자체를 빼야 하고(탐지 명세 §6.3),
//   메시지별 규칙(s_tmsi 는 네 메시지만, id_type 은 RegistrationRequest 만)이 한 곳에 보이게. 포인터는 event 의 것을 빌림
struct ue_f_keys {
    bool has_est_cause;
    bool has_ue_identity;
    bool has_wait_time;
    const char *cipher_name;    // RRC 는 해석기 이름 그대로, NAS 는 이름표. NULL 이면 키 뺌
    const char *integrity_name; // 같음
    bool has_suspend;
    const char *reg_type_name; // NULL 이면 키 뺌
    const char *id_type_name;  // 같음
    bool has_s_tmsi;
    bool has_s_tmsi_part2;
    bool has_nas_cause;
    bool has_f1ap_cause;
    bool has_switch_off;
};

/* ue_f_keys_decide: f 에 쓸 키를 정함. 값이 없거나(has_ 거짓, 포인터 NULL·빈 문자열, 이름표 밖 번호, 음수 원인) 그 메시지에 쓰지 않는 키면 뺌 —
 *   엔진은 없는 키를 받지만 타입이 틀린 값은 줄 전체를 버리므로, 애매한 값은 키를 빼는 쪽이 상태 추적을 지킴(탐지 명세 §6.3·§6.4).
 *   반환: 쓸 hex 값이 비트 폭을 넘으면 false(엔진 opt_hex 가 줄을 버림 — 해석기가 폭을 지키므로 생기면 상위 버그)
 */
static bool ue_f_keys_decide(const struct report_ue_event *event, const char *msg_name, struct ue_f_keys *keys) {
    const struct report_ue_fields *f = &event->fields;
    bool is_rrc = event->proto == REPORT_PROTO_RRC;
    bool is_nas = event->proto == REPORT_PROTO_NAS;
    bool is_f1ap = event->proto == REPORT_PROTO_F1AP;
    bool is_ul = event->direction == REPORT_DIRECTION_UL;
    bool is_setup_complete = is_rrc && is_ul && strcmp(msg_name, "RRCSetupComplete") == 0;
    bool is_registration_request = is_nas && is_ul && strcmp(msg_name, "RegistrationRequest") == 0;
    bool is_service_request = is_nas && is_ul && strcmp(msg_name, "ServiceRequest") == 0;
    bool is_registration_accept = is_nas && !is_ul && strcmp(msg_name, "RegistrationAccept") == 0;
    // 탐지 명세 §6.4: s_tmsi 는 이 네 메시지에서만 읽음. Part2 는 RRCSetupComplete 의 폴백
    bool reads_s_tmsi = is_setup_complete || is_registration_request || is_service_request || is_registration_accept;
    bool has_f1ap_cause_names = f->f1ap_cause_group && f->f1ap_cause_group[0] && f->f1ap_cause_value && f->f1ap_cause_value[0];

    *keys = (struct ue_f_keys){0};
    keys->has_est_cause = f->has_est_cause && f->est_cause && f->est_cause[0];
    keys->has_ue_identity = f->has_ue_identity;
    keys->has_wait_time = f->has_wait_time;
    if (is_rrc && f->has_rrc_algorithm) {
        keys->cipher_name = f->cipher && f->cipher[0] ? f->cipher : NULL;
        keys->integrity_name = f->integrity && f->integrity[0] ? f->integrity : NULL;
    }
    if (is_nas && f->has_nas_algorithm) {
        keys->cipher_name = nas_algorithm_name(true, f->nas_ciphering_algorithm);
        keys->integrity_name = nas_algorithm_name(false, f->nas_integrity_algorithm);
    }
    keys->has_suspend = f->has_suspend;
    keys->reg_type_name = f->has_reg_type ? reg_type_name(f->reg_type) : NULL;
    keys->id_type_name = is_registration_request ? id_type_name(f->id_type) : NULL;
    keys->has_s_tmsi = reads_s_tmsi && f->has_s_tmsi;
    keys->has_s_tmsi_part2 = is_setup_complete && f->has_s_tmsi_part2;
    keys->has_nas_cause = is_nas && f->has_nas_cause && f->nas_cause >= 0;
    keys->has_f1ap_cause = is_f1ap && f->has_f1ap_cause && has_f1ap_cause_names;
    keys->has_switch_off = f->has_switch_off;

    bool is_part1_too_wide = keys->has_ue_identity && f->is_ue_identity_part1 && (f->ue_identity_part1 >> S_TMSI_PART1_BITS) != 0;
    bool is_s_tmsi_too_wide = keys->has_s_tmsi && (f->s_tmsi >> S_TMSI_BITS) != 0;
    bool is_part2_too_wide = keys->has_s_tmsi_part2 && (f->s_tmsi_part2 >> S_TMSI_PART2_BITS) != 0;
    return !is_part1_too_wide && !is_s_tmsi_too_wide && !is_part2_too_wide;
}

static bool ue_f_keys_has_any(const struct ue_f_keys *keys) {
    return keys->has_est_cause || keys->has_ue_identity || keys->has_wait_time || keys->cipher_name || keys->integrity_name || keys->has_suspend || keys->reg_type_name || keys->id_type_name || keys->has_s_tmsi || keys->has_s_tmsi_part2 || keys->has_nas_cause || keys->has_f1ap_cause || keys->has_switch_off;
}

/* ue_f_write: "f":{…}. 키 순서는 탐지 명세 §6.4 표의 메시지 순서(참조 샘플과 같게 — 엔진은 순서를 안 봄) */
static void ue_f_write(struct line_buf *line, const struct report_ue_event *event, const struct ue_f_keys *keys) {
    const struct report_ue_fields *f = &event->fields;
    line_key(line, "f");
    line_open(line, '{');
    if (keys->has_est_cause) {
        line_key(line, "est_cause");
        line_string(line, f->est_cause);
    }
    if (keys->has_ue_identity) {
        line_key(line, "ue_identity");
        line_open(line, '{');
        line_key(line, "type");
        if (f->is_ue_identity_part1) {
            line_string(line, "ng-5G-S-TMSI-Part1");
            line_key(line, "value");
            line_hex(line, f->ue_identity_part1, S_TMSI_PART1_BITS);
        } else {
            line_string(line, "randomValue"); // 값은 보내지 않음 — 엔진이 읽지 않고, 무작위 값은 UE 를 잇는 데 못 씀
        }
        line_close(line, '}');
    }
    if (keys->has_wait_time) {
        line_key(line, "wait_time");
        line_u64(line, f->wait_time_s);
    }
    if (keys->cipher_name) {
        line_key(line, "cipher");
        line_string(line, keys->cipher_name);
    }
    if (keys->integrity_name) {
        line_key(line, "integrity");
        line_string(line, keys->integrity_name);
    }
    if (keys->has_suspend) {
        line_key(line, "suspend");
        line_bool(line, f->suspend);
    }
    if (keys->reg_type_name) {
        line_key(line, "reg_type");
        line_string(line, keys->reg_type_name);
    }
    if (keys->id_type_name) {
        line_key(line, "id_type");
        line_string(line, keys->id_type_name);
    }
    if (keys->has_s_tmsi) {
        line_key(line, "s_tmsi");
        line_hex(line, f->s_tmsi, S_TMSI_BITS);
    }
    if (keys->has_s_tmsi_part2) {
        line_key(line, "s_tmsi_part2");
        line_hex(line, f->s_tmsi_part2, S_TMSI_PART2_BITS);
    }
    if (keys->has_nas_cause) {
        line_key(line, "cause"); // NAS 는 5GMM 원인 정수(AuthenticationFailure 21 = 동기 실패)
        line_u64(line, (uint64_t)f->nas_cause);
    }
    if (keys->has_f1ap_cause) {
        line_key(line, "cause"); // F1AP 는 "<선택지>:<값 이름>" 한 문자열(탐지 명세 §6.4)
        line_value_start(line);
        line_put_char(line, '"');
        line_put_escaped(line, f->f1ap_cause_group);
        line_put_char(line, ':');
        line_put_escaped(line, f->f1ap_cause_value);
        line_put_char(line, '"');
    }
    if (keys->has_switch_off) {
        line_key(line, "switch_off");
        line_bool(line, f->switch_off);
    }
    line_close(line, '}');
}

enum sink_result sink_on_ue_event(struct sink *sink, const struct report_ue_event *event) {
    if (!sink) {
        return SINK_DROPPED_INVALID;
    }
    const char *msg_name = event ? ue_msg_name(event) : NULL;
    struct ue_f_keys keys;
    bool is_valid = msg_name && ue_event_check(event) && ue_f_keys_decide(event, msg_name, &keys);
    if (!is_valid) {
        sink->stats.invalid_drop_count++;
        return SINK_DROPPED_INVALID;
    }
    bool is_nas = event->proto == REPORT_PROTO_NAS;
    const char *proto_name = "F1AP";
    if (is_nas) {
        proto_name = "NAS";
    } else if (event->proto == REPORT_PROTO_RRC) {
        proto_name = "RRC";
    }
    bool is_connected = connection_ensure(sink);
    struct line_buf line = {.data = sink->line, .cap = sizeof sink->line};
    line_reset(&line);
    sink->seq++;
    line_open(&line, '{');
    line_common_head(&line, sink, "ue_evt", sink->seq);
    line_key(&line, "t_ms");
    line_u64(&line, event->t_ms);
    line_key(&line, "cell_id");
    line_u64(&line, event->cell_id);
    line_key(&line, "du_ue_id"); // null 은 NGAP 에서만 본 NAS 줄만(ue_event_check 가 확인). 0 도 정상 ID 라 0 으로 채우지 않음
    if (event->has_du_ue_id) {
        line_u64(&line, event->du_ue_id);
    } else {
        line_null(&line);
    }
    line_key(&line, "crnti"); // 키는 늘 — 없으면 엔진이 줄을 버림. 모르면 null
    if (event->has_crnti) {
        line_u64(&line, event->crnti);
    } else {
        line_null(&line);
    }
    if (event->has_cu_ue_id) { // CU 가 정하기 전(RRCSetupRequest 줄)에는 키를 뺌
        line_key(&line, "cu_ue_id");
        line_u64(&line, event->cu_ue_id);
    }
    line_key(&line, "dir");
    line_string(&line, event->direction == REPORT_DIRECTION_UL ? "UL" : "DL");
    line_key(&line, "proto");
    line_string(&line, proto_name);
    line_key(&line, "msg");
    line_string(&line, msg_name);
    if (is_nas) { // NAS 줄만: 본 경로와 바깥 보안 헤더 유형(탐지 명세 §6.3)
        line_key(&line, "via");
        line_string(&line, event->via == REPORT_NAS_VIA_F1 ? "F1" : "NGAP");
        line_key(&line, "sht");
        line_u64(&line, (uint64_t)event->sht);
    }
    if (ue_f_keys_has_any(&keys)) {
        ue_f_write(&line, event, &keys);
    }
    line_finish(&line);
    return line_emit(sink, &line, is_connected);
}
