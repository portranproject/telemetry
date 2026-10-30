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

#ifdef __cplusplus
}
#endif
#endif /* TELEMETRY_SCTP_H */
