#ifndef TELEMETRY_SINK_H
#define TELEMETRY_SINK_H

// 출력 층. 집계 층이 넘긴 report_* 값을 탐지 명세의 JSON Lines 한 줄로 바꿔 Unix 도메인 소켓으로 보낸다.
//   세지 않고, 판정하지 않고, UE 를 기억하지 않는다 — 입력을 검사하고 형식만 책임진다.
//   한 스레드에서 부른다(obs·tr 콜백과 같은 스레드). 스레드 안전하지 않음.

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "common/report.h"

#define SINK_DEFAULT_SOCKET_PATH "/run/ran-detect/kpm.sock" // 탐지 명세 §2 의 통로. cfg.socket_path 가 NULL 일 때
#define SINK_LINE_MAX_BYTES 65536                           // 탐지 명세 §2: 한 줄 상한. 넘는 줄은 내지 않고 셈 — 탐지 엔진이 버릴 줄을 만들지 않음
#define SINK_RECONNECT_INTERVAL_MS 1000                     // 탐지 명세 §2: 끊기면 1초 간격 재접속. 콜백 안에서 connect 하므로 더 짧으면 처리 시간만 먹음
#define SINK_SEND_TIMEOUT_MS 100                            // 한 줄 보내기 상한(SO_SNDTIMEO). 탐지 엔진이 읽기를 멈춰 커널 송신 버퍼가 찬 뒤에만 걸림 — 기본 208 KB 지만 줄마다
                                                            //   skb 오버헤드 약 1.2 KB 가 붙어 실제로는 약 120줄(CU 에서 잼: 한가한 셀 하나 약 12초, 등록 폭주 땐 1초 안팎).
                                                            //   칸 길이(period_ms)와 같은 값 — 그 이상 기다려도 그 줄이 속한 칸은 지나감. 걸리면 줄을 버리고 소켓을 닫아(반쪽 줄을 엔진이 버리게)
                                                            //   1초 뒤 재접속하므로 최악에도 캡처 처리는 10 % 만 멈춤

// sink_cfg: 생성 설정. 문자열은 sink_new 가 복사하므로 돌아온 뒤 해제해도 됨. record_file 은 빌려 씀(sink 가 닫지 않음)
struct sink_cfg {
    const char *socket_path;     // NULL 이면 SINK_DEFAULT_SOCKET_PATH
    FILE *record_file;           // 보낸 줄을 그대로 남길 곳. NULL 이면 안 남김(기본, 운영). 형식 확인·첫 녹화 같은 짧은 시험 때만 켬
    uint64_t record_max_bytes;   // 녹화 상한. 넘으면 녹화만 멈추고 is_record_stopped(소켓 전송은 계속). 0 이면 상한 없음. 셀 하나 1시간 약 23 MB
    uint32_t period_ms;          // hello 의 period_ms·si_sample_ms. 칸을 만드는 tr 과 같은 출처(tr 헤더 상수)를 넘길 것 — 탐지 엔진은 광고값으로 칸 길이를 검사
    uint32_t noreply_timeout_ms; // hello 의 noreply_timeout_ms(탐지 명세 §4: 1000). 위와 같이 tr 과 같은 값
    const char *producer;        // hello 기록용(예 "telemetry 0.1"). NULL 이면 키 뺌(선택 필드)
    const char *node_id;         // hello 기록용. 실행 옵션 또는 gethostname 으로 main 이 정함. NULL 이면 키 뺌
};

// sink_result: 호출 하나의 결과. 버린 줄은 sink_stats 에도 셈
enum sink_result {
    SINK_OK = 0,
    SINK_DROPPED_INVALID,      // 입력이 탐지 엔진이 버리는 모양(열거형 0, 필수 값 없음, 이름표에 없는 번호 등). 줄을 내지 않음
    SINK_DROPPED_DISCONNECTED, // 소켓이 끊겨 있고 재접속도 안 됨. 줄은 버리되 seq 는 올림(탐지 명세 §2·§3 이 허용)
    SINK_DROPPED_TOO_LONG,     // 줄이 SINK_LINE_MAX_BYTES 를 넘음
    SINK_DROPPED_WRITE_FAILED, // write 가 실패함. 끊긴 것으로 보고 다음 줄부터 재접속
};

// sink_stats: 누적 통계. sink 가 갱신하고 호출자는 빌려 읽기만 함
struct sink_stats {
    uint64_t line_count;              // 소켓에 보낸 줄 수(hello 포함)
    uint64_t hello_count;             // 보낸 hello 수 = 접속 성공 수
    uint64_t reconnect_count;         // 첫 접속 뒤 다시 접속한 수. 잦으면 줄을 모아 두는 방식을 검토(지금은 버림)
    uint64_t invalid_drop_count;      // SINK_DROPPED_INVALID
    uint64_t disconnected_drop_count; // SINK_DROPPED_DISCONNECTED
    uint64_t too_long_drop_count;     // SINK_DROPPED_TOO_LONG
    uint64_t write_error_count;       // SINK_DROPPED_WRITE_FAILED
    uint64_t spec_warning_count;      // 보내긴 했지만 탐지 엔진이 경고를 낼 모양이었던 줄 수(원인 합 ≠ total, 칸 길이 ≠ period_ms). 집계 층 계산이 어긋난 흔적 — 줄을 버리면 칸이 비어 판정이 멈추므로 보내고 셈
    uint64_t inferred_count;          // 낸 kpm2 카운터의 inferred 합. 탐지 명세에 이 값을 받는 키가 없어 줄에는 안 나가고, 실행 끝에 사람이 보는 자리는 여기뿐(main 이 출력)
    uint64_t record_bytes;            // 녹화 파일에 쓴 바이트
    bool is_record_stopped;           // record_max_bytes 를 넘었거나 파일 쓰기가 실패해 녹화를 멈춤. 소켓 전송은 계속
};

struct sink;

/* sink_new: 설정으로 sink 를 만든다. 세션 이름(기동 시각 UTC)과 seq 0 을 잡고, 접속은 첫 줄을 낼 때 한다.
 *   이유: 접속을 미루면 탐지 엔진이 늦게 떠도 생성이 실패하지 않아, 끊김과 같은 재접속 규칙 하나로 처리된다.
 *   반환: 실패(할당, 설정값이 탐지 명세 §4 의 타입을 어김 — period_ms 0, 소켓 경로가 너무 긺 등)면 NULL.
 */
struct sink *sink_new(const struct sink_cfg *cfg);

/* sink_on_ue_event: ue_evt 한 줄을 보낸다. 입력을 검사해 탐지 엔진이 버리는 모양이면 내지 않고 센다.
 *   부작용: 접속·재접속 시도, hello 선행, seq 증가, 녹화, 통계. event 와 그 안의 포인터는 빌려 읽기만 하고 돌아온 뒤 가리키지 않는다.
 *   반환: SINK_OK 또는 버린 이유.
 */
enum sink_result sink_on_ue_event(struct sink *sink, const struct report_ue_event *event);

/* sink_on_f1_event: f1_evt 한 줄. 부작용·반환은 sink_on_ue_event 와 같다. */
enum sink_result sink_on_f1_event(struct sink *sink, const struct report_f1_event *event);

/* sink_on_period: kpm2 한 줄. 부작용·반환은 sink_on_ue_event 와 같다. 같은 칸의 ue_evt 를 먼저 넘기고 부를 것(탐지 명세 §6.5). */
enum sink_result sink_on_period(struct sink *sink, const struct report_period *period);

const struct sink_stats *sink_get_stats(const struct sink *sink);

/* sink_free: 소켓을 닫고 해제한다. record_file 은 닫지 않는다(빌려 쓰므로). NULL 이면 아무것도 안 한다. */
void sink_free(struct sink *sink);

#endif /* TELEMETRY_SINK_H */
