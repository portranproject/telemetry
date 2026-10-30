/* libsctp/sctp.h — libsctp: 와이어의 SCTP 패킷 → 완성된 사용자 메시지(F1AP/NGAP PDU)  (RFC 9260)
 *   번들링(한 패킷 여러 DATA 청크), 단편 조립(B/E, TSN 연속), 중복 제거(방향별 TSN 창),
 *   연결 시작·끝(INIT/ABORT/SHUTDOWN COMPLETE, vtag).
 * 스레드: 단일 스레드. 콜백으로 넘기는 구조체와 그 안의 포인터는 콜백 안에서만 유효.
 */
#ifndef TELEMETRY_SCTP_H
#define TELEMETRY_SCTP_H

// TODO: include libcap/cap.h
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SCTP_PPID_NGAP 60
#define SCTP_PPID_F1AP 62

    // sctp_message: 완성된 사용자 메시지 하나(F1AP/NGAP PDU 한 개).
    struct sctp_message
    {
        const struct cap_record *record;
        uint32_t assoc_id;
        uint32_t ppid; // 수신 쪽 F1AP·NGAP 디코더 분기
        uint16_t stream_id;
        uint32_t tsn;
        uint16_t fragment_count;
        const uint8_t *data; // 메시지 바이트
        size_t len;          // 메시지(PDU) 바이트 수
    };

    // sctp_assoc_kind: 연결 알림 종류. 0 은 비워 두어 초기화 안 된 값을 구분한다.
    enum sctp_assoc_kind
    {
        SCTP_ASSOC_START = 1, // INIT 또는 INIT 없이 vtag 가 바뀐 재시작
        SCTP_ASSOC_END = 2,   // ABORT 또는 SHUTDOWN COMPLETE
    };

    // sctp_assoc_event: 연결 시작·끝 알림 하나.
    struct sctp_assoc_event
    {
        const struct cap_record *record; // 알림을 일으킨 패킷
        uint32_t assoc_id;               // sctp_message.assoc_id 와 같은 번호
        enum sctp_assoc_kind kind;
    };

    // sctp_stats: 누적 통계. 버린 입력이 왜 버려졌는지 구분해 캡처 품질·이상 입력을 확인 용도
    struct sctp_stats
    {
        // 패킷
        uint64_t packet_count;
        uint64_t bad_header_count;
        uint64_t truncated_packet_count; // 캡처가 원래 길이보다 짧게 잘린 패킷

        // 청크
        uint64_t chunk_count;
        uint64_t data_chunk_count;
        uint64_t idata_chunk_count;

        // 버린 청
        uint64_t duplicate_chunk_count; // 이미 본 TSN(재전송)
        uint64_t too_old_chunk_count;
        uint64_t partial_chunk_count;

        // 단편
        uint64_t fragment_chunk_count;             // 메시지 일부만 담은 DATA 청크(B·E 중 하나 이상 꺼짐)
        uint64_t reassembled_count;                // 조각을 모아 완성한 메시지
        uint64_t fragment_evicted_count;           // 유효 시간·메모리 상한 때문에 버린 조각
        uint64_t idata_fragment_unsupported_count; // 단편화된 I-DATA(조립 미지원이라 버림)

        // 전달
        uint64_t message_count; // 콜백으로 넘긴 메시지

        // 연결·vtag
        uint64_t init_count;               // INIT·INIT-ACK
        uint64_t abort_shutdown_count;     // ABORT·SHUTDOWN COMPLETE(vtag 검사 전 카운트)
        uint64_t vtag_reset_count;         // INIT 없이 vtag 가 바뀌어 재시작으로 본 횟수
        uint64_t vtag_mismatch_drop_count; // vtag 가 기대값과 달라 버린 패킷

        // 유실
        uint64_t tsn_gap_count; // 끝내 보지 못한 TSN 수(유실 추정)

        // 표 상한
        uint64_t direction_evicted_count; // 방향 표가 꽉 차 밀어낸 방향 레코드
        uint64_t assoc_evicted_count;     // 연결 표가 꽉 차 밀어낸 연결 레코드
    };

#ifdef __cplusplus
}
#endif
#endif /* TELEMETRY_SCTP_H */
