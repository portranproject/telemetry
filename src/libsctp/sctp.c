/* libsctp/sctp.c — 와이어의 SCTP 패킷 → 완성된 사용자 메시지(F1AP/NGAP PDU)  (RFC 9260)
 *
 * [신입 가이드]
 *   입력: 캡처 모듈이 준 패킷 하나(struct cap_record). sctp_input 으로 들어온다.
 *   출력: 완성된 메시지(struct sctp_message)와 연결 시작·끝(struct sctp_assoc_event). 콜백으로 나간다.
 *   패킷 1개 ≠ 메시지 1개다. 한 패킷에 메시지 여러 개(번들링), 한 메시지가 여러 패킷(단편화),
 *   재전송 중복, 캡처 잘림이 섞여 온다. 이것을 정리해 완성된 메시지만 넘기는 것이 이 파일의 일이다.
 *   수동 관측자라 재전송을 요청할 수 없으므로, 끝내 못 본 TSN 은 유실 추정(tsn_gap_count)으로만 센다.
 *
 * 핵심 자료구조(안쪽 → 바깥쪽):
 *   fragment          — 아직 메시지를 완성하지 못한 DATA 조각 하나(힙)
 *   reassembly_queue  — 한 방향의 미완성 조각 목록
 */
#include <stddef.h>
#include <stdint.h>

#include "sctp.h"

// fragment: 아직 메시지를 완성하지 못한 DATA 조각 하나(SCTP 메시지 단편).
//   패킷 버퍼는 sctp_input 이 끝나면 사라지므로 바이트 복사
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
