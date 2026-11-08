#include "libsink/sink.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

// MARK: - 상수

#define JSON_VERSION 1 // 탐지 명세 §3 의 ver. 다른 값이면 줄을 버림

// 세션 문자열 "YYYYMMDDTHHMMSSZ" 16자 + NUL. 탐지 명세 §3 — 기동 시각 UTC, 기동마다 새로
#define SESSION_BYTES 17

// hello 에 싣는 설정 문자열(producer·node_id) 상한. 이스케이프 최악(바이트마다 \u00XX 6배)에도 hello 버퍼에 들어가게 — gethostname 은 64 이하
#define HELLO_STRING_MAX_BYTES 128
// hello 줄 버퍼. 고정 부분 약 220 B + 문자열 둘 × 128 × 6. 줄 버퍼(line)는 보낼 줄이 들어 있어 hello 를 거기 만들 수 없음
#define HELLO_LINE_CAP 2048

// 줄 안 중첩 깊이 상한(객체·배열). 탐지 줄은 kpm2 의 {cc:{카운터:{}}} 로 깊이 3 이 최대 — 넘으면 코드 버그라 줄을 버림
#define LINE_DEPTH_MAX 8

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

/* line_put_quoted: 문자열을 따옴표로 싸서 이스케이프해 붙임.
 *   탐지 명세 부록 B: "·\·제어 문자. \n·\r·\t 는 그 이름으로, 나머지 제어 문자는 \u00XX. 0x20 이상은 그대로(UTF-8 은 설정 때 검사함)
 */
static void line_put_quoted(struct line_buf *line, const char *text) {
    static const char hex_digits[] = "0123456789abcdef";
    line_put_char(line, '"');
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
