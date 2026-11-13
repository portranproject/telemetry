#ifndef TELEMETRY_HOST_H
#define TELEMETRY_HOST_H

// 호스트 자원 측정 층. procfs 를 읽어 이 노드와 이 프로세스가 창 하나 동안 쓴 CPU 와 메모리를 냄.
//   세지 않고 판정하지 않음 - 읽은 값과 읽지 못한 사실만 전달함.
//   한 스레드에서 부름(main 의 폴링 루프). 스레드 안전하지 않음.
//
// [1] CPU 는 누적값이라 창 평균이 양끝 두 번의 읽기로 정확히 나옴. 중간 표본이 필요 없음.
//     메모리는 순간값이라 창 끝의 한 점임.
//
//       창 시작                                            창 끝
//         |                                                 |
//         +-- busy_ticks(t0), process_ticks(t0) -------------+-- busy_ticks(t1), process_ticks(t1)
//         |                                                 |   메모리는 여기서만 읽음
//         |<----------- monotonic 경과 시간 --------------->|
//
//       코어 수 = (busy_ticks(t1) - busy_ticks(t0)) / clk_tck / 경과초
//
// [2] 분모를 CLOCK_MONOTONIC 으로 재는 이유: 벽시계는 NTP 로 뒤로 갈 수 있어 경과 시간이
//     0 이나 음수가 되고, 그러면 코어 수가 무한대나 음수로 나감.
//
// [3] 파일 넷을 열어 두고 pread(fd, buf, n, 0) 으로 다시 읽음. 창마다 open/close 하면
//     창당 8회의 추가 syscall 이 됨.
//
//       /proc/stat        첫 줄 cpu 합계      노드가 바쁘게 돈 시간(tick)
//       /proc/self/stat   utime + stime       이 프로세스가 쓴 시간(tick)
//       /proc/meminfo     MemTotal, MemAvailable
//       /proc/self/statm  resident            이 프로세스의 RSS(page)

#include <stdbool.h>
#include <stdint.h>

/* host_window: 창 하나의 측정 결과.
 *   has_* 가 false 면 그 창에서 그 값을 얻지 못한 것임. 0 을 넣지 않는 이유: 0 은 '한가했음' 과
 *     같은 모양이라 읽는 쪽이 측정 구멍을 볼 수 없음.
 *   첫 창의 has_node_cpu 와 has_process_cpu 는 false 임 - 차이를 낼 앞선 읽기가 없기 때문임 */
struct host_window {
	// 이 노드가 쓸 수 있는 CPU 수. 점유율을 내려면 분모가 필요해 같이 실음. 0 이면 읽지 못한 것임
	uint32_t cpu_count;

	// 창 동안 노드 전체가 바쁘게 돈 코어 수의 평균. cpu_count 로 나누면 점유율임
	bool has_node_cpu;
	double node_cpu_busy_cores;
	// 같은 창에서 이 프로세스가 쓴 코어 수의 평균
	bool has_process_cpu;
	double process_cpu_cores;

	// 창 끝의 한 점. used = MemTotal - MemAvailable
	bool has_node_memory;
	uint64_t memory_total_bytes;
	uint64_t memory_used_bytes;
	// 창 끝의 이 프로세스 RSS
	bool has_process_memory;
	uint64_t process_memory_rss_bytes;
};

struct host;

/* host_new: procfs 파일 넷을 열어 두고 첫 누적값을 읽음.
 *   반환: 실패(할당, /proc 을 못 엶)면 NULL. 네 파일 중 하나라도 못 열면 NULL - 일부만 재는 핸들을
 *     만들면 그 창의 값이 왜 없는지 부르는 쪽이 가릴 수 없음. */
struct host *host_new(void);

/* host_window_close: 지금 값을 읽어 창 하나의 결과를 채우고, 다음 창의 시작점을 지금으로 옮김.
 *   부작용: procfs 를 네 번 읽음(pread). 읽기가 실패하면 그 칸의 has_* 를 false 로 두고 실패 수를 올림.
 *   반환: 0 성공, -EINVAL host 나 window_out 이 NULL. 읽기 실패는 오류가 아님 - 결과의 has_* 가 말함. */
int host_window_close(struct host *host, struct host_window *window_out);

/* host_get_failure_count: 지금까지 procfs 읽기가 실패한 횟수. 종료 보고가 읽음 -
 *   한 창의 has_* 는 그 창만 말하므로, 실행 전체가 얼마나 못 봤는지는 이 값으로만 알 수 있음 */
uint64_t host_get_failure_count(const struct host *host);

void host_free(struct host *host);

#endif /* TELEMETRY_HOST_H */
