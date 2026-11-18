/**
 * host.c
 * : libhost 구현 - procfs 네 파일을 열어 두고 창 경계마다 읽어 CPU 와 메모리 사용량을 냄
 *
 * [1] 파일을 열어 두고 pread(fd, buf, n, 0) 으로 다시 읽음. procfs 는 읽을 때마다 내용을
 *     새로 만들어 주므로 오프셋 0 으로 다시 읽으면 그때의 값이 나옴.
 *
 * [2] /proc/stat 은 CPU 가 많은 장비에서 한 번에 다 담기지 않을 수 있음. 여기서 보는 것은
 *     첫 줄(전체 합계)뿐이라 버퍼가 잘려도 영향이 없음.
 *
 * [3] /proc/self/stat 의 두 번째 칸(comm)은 괄호 안에 공백과 괄호를 담을 수 있어, 칸을 앞에서
 *     세면 어긋남. 마지막 ')' 를 찾아 그 뒤부터 셈.
 *
 *     12345 (my app) S 1 12345 ...
 *                  ^
 *                  마지막 ')' - 이 뒤가 세 번째 칸(state)
 *
 * [4] 실패 처리. 한 파일을 못 읽으면 그 칸만 값 없음으로 두고 실패 수를 올림. 0 을 넣지 않음 -
 *     0 은 '한가했음' 과 같은 모양이라 읽는 쪽이 측정 구멍을 볼 수 없음.
 */
#include "libhost/host.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// 한 번에 읽는 양. /proc/stat 의 첫 줄과 /proc/meminfo 의 앞쪽 몇 줄이 들어오면 충분함
#define READ_BUF_BYTES 4096

/* MIN_WINDOW_TICKS: CPU 창 평균을 내는 데 필요한 최소 경과 시간을 tick 수로 둔 것.
 *   이유: 측정 단위가 1 tick(보통 10 ms)이라, 창이 그만큼 짧으면 tick 하나가 걸렸는지 아닌지로
 *     값이 통째로 바뀜. 경과 2 ms 에 1 tick 이 걸리면 '5 코어' 가 나가고 읽는 쪽은 그것을 사실로 받음.
 *   10 인 근거: 양자화 오차를 1 tick / 10 tick = 10 % 아래로 누르는 가장 작은 값임. 그보다 짧은 창은
 *     값을 내지 않고 값 없음으로 둠 - 창 길이가 3초인 운영 경로에서는 걸리지 않고, 기동 직후나
 *     창을 연달아 닫는 시험에서만 걸림 */
#define MIN_WINDOW_TICKS 10

/* 누적 CPU 시간 한 쌍. 창 평균은 양끝 두 값의 차이로 내므로 직전 창 끝 값을 들고 있어야 함 */
struct cpu_cumulative {
	bool is_valid;
	uint64_t node_busy_ticks;
	uint64_t process_ticks;
	int64_t monotonic_ns;
};

struct host {
	int stat_fd;         // /proc/stat
	int process_stat_fd; // /proc/self/stat
	int meminfo_fd;      // /proc/meminfo
	int process_statm_fd;// /proc/self/statm
	// sysconf 결과. 창마다 부르지 않게 한 번만 읽음
	long clock_ticks_per_sec;
	long page_size_bytes;
	uint32_t cpu_count;
	struct cpu_cumulative previous;
	uint64_t failure_count;
	char buf[READ_BUF_BYTES];
};

static int64_t monotonic_ns(void) {
	struct timespec monotonic_time;
	clock_gettime(CLOCK_MONOTONIC, &monotonic_time);
	return (int64_t)monotonic_time.tv_sec * 1000000000LL + monotonic_time.tv_nsec;
}

/* read_text: 열어 둔 procfs 파일을 오프셋 0 에서 다시 읽어 host->buf 에 NUL 로 끝내 담음.
 *   반환: 읽었으면 true. 0 바이트나 오류면 false(부르는 쪽이 그 칸을 값 없음으로 둠) */
static bool read_text(struct host *host, int fd) {
	ssize_t read_len = pread(fd, host->buf, sizeof(host->buf) - 1, 0);
	if (read_len <= 0)
		return false;
	host->buf[read_len] = '\0';
	return true;
}

/* read_node_busy_ticks: /proc/stat 첫 줄에서 노드가 바쁘게 돈 시간을 tick 으로 냄.
 *   bus 시간 = 전체 합 - idle - iowait. iowait 를 빼는 이유: 그 동안 CPU 는 다른 일을 할 수 있어
 *     '바쁨' 으로 세면 점유율이 부풀려짐.
 *
 *     cpu  user nice system idle iowait irq softirq steal guest guest_nice
 *                           ^^^^ ^^^^^^ 이 둘만 빼고 전부 더함
 *
 *   반환: 읽었으면 true 와 *busy_ticks_out. 첫 줄이 "cpu " 로 시작하지 않거나 칸이 모자라면 false */
static bool read_node_busy_ticks(struct host *host, uint64_t *busy_ticks_out) {
	if (!read_text(host, host->stat_fd))
		return false;
	if (strncmp(host->buf, "cpu ", 4))
		return false;
	char *cursor = host->buf + 4;
	uint64_t total_ticks = 0;
	uint64_t idle_ticks = 0;
	int field_index = 0;
	for (; field_index < 10; field_index++) {
		char *next_cursor = NULL;
		unsigned long long value = strtoull(cursor, &next_cursor, 10);
		if (next_cursor == cursor)
			break;
		cursor = next_cursor;
		total_ticks += value;
		// 네 번째와 다섯 번째 칸이 idle 과 iowait
		if (field_index == 3 || field_index == 4)
			idle_ticks += value;
	}
	// user, nice, system, idle 네 칸은 어느 커널에나 있음. 그보다 적으면 모양이 다른 것이라 믿지 않음
	if (field_index < 4)
		return false;
	*busy_ticks_out = total_ticks - idle_ticks;
	return true;
}

/* read_process_ticks: /proc/self/stat 의 utime + stime 을 tick 으로 냄.
 *   반환: 읽었으면 true 와 *process_ticks_out. ')' 가 없거나 칸이 모자라면 false */
static bool read_process_ticks(struct host *host, uint64_t *process_ticks_out) {
	if (!read_text(host, host->process_stat_fd))
		return false;
	char *cursor = strrchr(host->buf, ')');
	if (!cursor)
		return false;
	cursor++;
	// ')' 뒤 첫 칸이 state(세 번째 칸)이므로 utime(열네 번째)은 그로부터 열한 칸 뒤, stime 은 그다음
	uint64_t utime_ticks = 0;
	uint64_t stime_ticks = 0;
	for (int field_index = 0; field_index < 13; field_index++) {
		char *next_cursor = NULL;
		if (field_index == 0) {
			// state 는 숫자가 아니라 글자 하나임. 공백을 건너뛰고 한 글자를 지나감
			while (*cursor == ' ')
				cursor++;
			if (!*cursor)
				return false;
			cursor++;
			continue;
		}
		unsigned long long value = strtoull(cursor, &next_cursor, 10);
		if (next_cursor == cursor)
			return false;
		cursor = next_cursor;
		if (field_index == 11)
			utime_ticks = value;
		if (field_index == 12)
			stime_ticks = value;
	}
	*process_ticks_out = utime_ticks + stime_ticks;
	return true;
}

/* meminfo_value_kb: /proc/meminfo 에서 키 하나의 값을 kB 로 찾음. 줄 시작에서만 맞춰 봄 -
 *   "MemTotal" 로 "MemTotal:" 과 "MemAvailable" 을 가리지 못하면 엉뚱한 줄을 읽음 */
static bool meminfo_value_kb(const char *text, const char *key, uint64_t *value_out) {
	size_t key_len = strlen(key);
	for (const char *line = text; line && *line; ) {
		if (!strncmp(line, key, key_len) && line[key_len] == ':') {
			char *next_cursor = NULL;
			unsigned long long value = strtoull(line + key_len + 1, &next_cursor, 10);
			if (next_cursor == line + key_len + 1)
				return false;
			*value_out = value;
			return true;
		}
		line = strchr(line, '\n');
		if (line)
			line++;
	}
	return false;
}

/* read_node_memory: MemTotal 과 MemAvailable 로 전체와 쓰는 중인 양을 냄.
 *   MemFree 가 아니라 MemAvailable 을 쓰는 이유: 캐시 중 회수할 수 있는 몫을 커널이 계산해 둔 값이라,
 *     캐시를 '쓰는 중' 으로 세어 점유율이 늘 90 % 로 보이는 것을 피함.
 *   반환: 둘 다 읽고 total >= available 이면 true. 아니면 false */
static bool read_node_memory(struct host *host, uint64_t *total_bytes_out, uint64_t *used_bytes_out) {
	if (!read_text(host, host->meminfo_fd))
		return false;
	uint64_t total_kb = 0;
	uint64_t available_kb = 0;
	if (!meminfo_value_kb(host->buf, "MemTotal", &total_kb))
		return false;
	if (!meminfo_value_kb(host->buf, "MemAvailable", &available_kb))
		return false;
	if (available_kb > total_kb)
		return false;
	*total_bytes_out = total_kb * 1024;
	*used_bytes_out = (total_kb - available_kb) * 1024;
	return true;
}

/* read_process_rss: /proc/self/statm 의 두 번째 칸(resident)을 바이트로 냄 */
static bool read_process_rss(struct host *host, uint64_t *rss_bytes_out) {
	if (!read_text(host, host->process_statm_fd))
		return false;
	char *cursor = NULL;
	strtoull(host->buf, &cursor, 10);
	if (cursor == host->buf)
		return false;
	char *next_cursor = NULL;
	unsigned long long resident_pages = strtoull(cursor, &next_cursor, 10);
	if (next_cursor == cursor)
		return false;
	*rss_bytes_out = resident_pages * (uint64_t)host->page_size_bytes;
	return true;
}

struct host *host_new(void) {
	long clock_ticks_per_sec = sysconf(_SC_CLK_TCK);
	long page_size_bytes = sysconf(_SC_PAGESIZE);
	long online_cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
	if (clock_ticks_per_sec <= 0 || page_size_bytes <= 0)
		return NULL;

	struct host *host = calloc(1, sizeof(*host));
	if (!host)
		return NULL;
	host->clock_ticks_per_sec = clock_ticks_per_sec;
	host->page_size_bytes = page_size_bytes;
	host->cpu_count = online_cpu_count > 0 ? (uint32_t)online_cpu_count : 0;

	const struct { const char *path; int *fd; } procfs_files[] = {
		{ "/proc/stat", &host->stat_fd },
		{ "/proc/self/stat", &host->process_stat_fd },
		{ "/proc/meminfo", &host->meminfo_fd },
		{ "/proc/self/statm", &host->process_statm_fd },
	};
	for (size_t i = 0; i < sizeof(procfs_files) / sizeof(procfs_files[0]); i++) {
		*procfs_files[i].fd = open(procfs_files[i].path, O_RDONLY | O_CLOEXEC);
		if (*procfs_files[i].fd < 0) {
			// 하나라도 못 열면 핸들을 만들지 않음. 일부만 재는 핸들은 그 창의 값이 왜 없는지 가릴 수 없음
			for (size_t j = 0; j < i; j++)
				close(*procfs_files[j].fd);
			free(host);
			return NULL;
		}
	}

	// 첫 창의 시작점. 여기서 못 읽으면 is_valid 가 false 로 남아 첫 창의 CPU 가 값 없음으로 나감
	uint64_t node_busy_ticks = 0;
	uint64_t process_ticks = 0;
	if (read_node_busy_ticks(host, &node_busy_ticks) && read_process_ticks(host, &process_ticks)) {
		host->previous.is_valid = true;
		host->previous.node_busy_ticks = node_busy_ticks;
		host->previous.process_ticks = process_ticks;
	} else {
		host->failure_count++;
	}
	host->previous.monotonic_ns = monotonic_ns();
	return host;
}

/* cores_from_ticks: 누적 tick 차이와 경과 시간으로 '그 창 동안 쓴 코어 수' 를 냄.
 *   창이 MIN_WINDOW_TICKS 보다 짧으면 false - 양자화가 값을 지배해 믿을 수 없는 수가 나감 */
static bool cores_from_ticks(const struct host *host, uint64_t tick_delta, int64_t elapsed_ns, double *cores_out) {
	int64_t min_elapsed_ns = MIN_WINDOW_TICKS * 1000000000LL / host->clock_ticks_per_sec;
	if (elapsed_ns < min_elapsed_ns)
		return false;
	double elapsed_seconds = (double)elapsed_ns / 1000000000.0;
	*cores_out = (double)tick_delta / (double)host->clock_ticks_per_sec / elapsed_seconds;
	return true;
}

int host_window_close(struct host *host, struct host_window *window_out) {
	if (!host || !window_out)
		return -EINVAL;
	memset(window_out, 0, sizeof(*window_out));
	window_out->cpu_count = host->cpu_count;

	int64_t now_ns = monotonic_ns();
	uint64_t node_busy_ticks = 0;
	uint64_t process_ticks = 0;
	bool is_cpu_read = read_node_busy_ticks(host, &node_busy_ticks) && read_process_ticks(host, &process_ticks);
	if (!is_cpu_read)
		host->failure_count++;

	if (is_cpu_read && host->previous.is_valid) {
		int64_t elapsed_ns = now_ns - host->previous.monotonic_ns;
		// 누적값이 뒤로 갔으면 창을 포기함. 생기지 않아야 하지만, 음수 차이를 부호 없는 수로
		// 	바꾸면 코어 수가 터무니없이 큰 값으로 나가 읽는 쪽이 그것을 사실로 받음
		if (node_busy_ticks >= host->previous.node_busy_ticks && process_ticks >= host->previous.process_ticks) {
			window_out->has_node_cpu = cores_from_ticks(host, node_busy_ticks - host->previous.node_busy_ticks,
			                                            elapsed_ns, &window_out->node_cpu_busy_cores);
			window_out->has_process_cpu = cores_from_ticks(host, process_ticks - host->previous.process_ticks,
			                                               elapsed_ns, &window_out->process_cpu_cores);
		}
	}

	uint64_t memory_total_bytes = 0;
	uint64_t memory_used_bytes = 0;
	if (read_node_memory(host, &memory_total_bytes, &memory_used_bytes)) {
		window_out->has_node_memory = true;
		window_out->memory_total_bytes = memory_total_bytes;
		window_out->memory_used_bytes = memory_used_bytes;
	} else {
		host->failure_count++;
	}

	uint64_t process_memory_rss_bytes = 0;
	if (read_process_rss(host, &process_memory_rss_bytes)) {
		window_out->has_process_memory = true;
		window_out->process_memory_rss_bytes = process_memory_rss_bytes;
	} else {
		host->failure_count++;
	}

	// 다음 창의 시작점. CPU 를 못 읽었으면 is_valid 를 내려 다음 창도 값 없음으로 나감 -
	// 	두 창에 걸친 차이를 한 창의 값으로 내보내지 않기 위함
	host->previous.is_valid = is_cpu_read;
	host->previous.node_busy_ticks = node_busy_ticks;
	host->previous.process_ticks = process_ticks;
	host->previous.monotonic_ns = now_ns;
	return 0;
}

uint64_t host_get_failure_count(const struct host *host) {
	return host ? host->failure_count : 0;
}

void host_free(struct host *host) {
	if (!host)
		return;
	close(host->stat_fd);
	close(host->process_stat_fd);
	close(host->meminfo_fd);
	close(host->process_statm_fd);
	free(host);
}
