/**
 * nas.c
 * : 5GS NAS 메시지 해석 - 와이어 바이트에서 지표에 필요한 값만 꺼냄 (TS 24.501 v17.18.1)
 *   asn1c 를 쓰지 않는 손 디코더. 전역 상태 없음
 *
 * [1] NAS-PDU 바이트 배치. 옥텟 1 의 EPD 가 어느 표를 쓸지 고름
 *
 *     5GMM 평문  EPD 0x7e, SHT 0
 *       +------+------+------+--------------------------------+
 *       | 0x7e | SHT  | type | IE ...                         |
 *       +------+------+------+--------------------------------+
 *          1      2      3     4..n
 *
 *     5GMM 보호  EPD 0x7e, SHT 1~4                               TS 24.501 8.2.28
 *       +------+------+-----------+------+------------------------------------+
 *       | 0x7e | SHT  | MAC (4)   | SN   | 안쪽 = 평문 5GMM 메시지            |
 *       +------+------+-----------+------+------------------------------------+
 *          1      2      3..6       7      8..n
 *
 *     5GSM  EPD 0x2e. 보안 머리 없음 - 옥텟 2 는 PDU 세션 ID       TS 24.501 9.3 ↔ 9.4
 *       +------+------+------+------+-------------------------+
 *       | 0x2e | PSI  | PTI  | type | IE ...                  |
 *       +------+------+------+------+-------------------------+
 *          1      2      3      4     5..n
 *
 * [2] nas_parse 의 분기
 *
 *     len < 2                                    -> truncated
 *     EPD 0x2e                                   -> parse_plain(buf,     inner=false)
 *     EPD 0x7e --+-- SHT 0                       -> parse_plain(buf,     inner=false)
 *                +-- SHT 1, 3  무결성만          -> parse_plain(buf + 7, inner=true)
 *                +-- SHT 2, 4  암호 --+-- NEA0   -> parse_plain(buf + 7, inner=true)
 *                |                    +-- 그 밖  -> 안 읽음. msg_type = -1
 *                +-- SHT 5~15                    -> reserved_sht
 *     그 밖                                      -> epd_mismatch
 *
 * [3] 가시성과 방향은 호출자가 정함 (nas.h [1]). SHT 4 -> SECURITY MODE COMPLETE 추론도
 *     전제가 (SHT 4) 와 (상행) 둘이라 방향을 아는 계층에서 함
 *
 * [4] 담지 않았으면 이유를 센다. 목록과 근거 조항은 nas.h
 *
 * [5] 안 꺼내는 것: 영구 식별자 SUCI / IMEI / IMEISV. 임시 식별자 5G-S-TMSI 만 꺼냄
 */
#include <errno.h>
#include <string.h>

#include "nas.h"

// 선택 IE 번호와 TV 형식의 옥텟 수. 메시지 타입과 값이 겹칠 수 있어 리터럴로 쓰지 않음
#define NAS_IEI_5GS_MOBILE_IDENTITY		0x77	// 표 8.2.7.1.1, 8.2.19.1.1 - TLV-E
#define NAS_IEI_LOCAL_TIME_ZONE			0x46	// 표 8.2.19.1.1 - TV 2.  9.11.3.52
#define NAS_IEI_UNIVERSAL_TIME_AND_TIME_ZONE	0x47	// 표 8.2.19.1.1 - TV 8.  9.11.3.53
#define NAS_IE_BYTES_LOCAL_TIME_ZONE		2
#define NAS_IE_BYTES_UNIVERSAL_TIME_AND_TIME_ZONE 8

struct nas_msg_info {
	const char *name;
	enum nas_msg_direction msg_type_direction;
};

// TS 24.501 표 9.7.1 - 5GMM 37개. 이 표가 '아는 타입' 의 정의임
// 	둘째 열은 8.2.x 각 메시지의 "Direction:" 줄. 방향을 따로 표로 두면 두 목록이 어긋나므로 한 표에 둠
static struct nas_msg_info mm_info(int msg_type) {
	switch (msg_type) {
	case 0x41:
		return (struct nas_msg_info){ "Registration request", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x42:
		return (struct nas_msg_info){ "Registration accept", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x43:
		return (struct nas_msg_info){ "Registration complete", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x44:
		return (struct nas_msg_info){ "Registration reject", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x45:
		return (struct nas_msg_info){ "Deregistration request (UE originating)", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x46:
		return (struct nas_msg_info){ "Deregistration accept (UE originating)", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x47:
		return (struct nas_msg_info){ "Deregistration request (UE terminated)", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x48:
		return (struct nas_msg_info){ "Deregistration accept (UE terminated)", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x4c:
		return (struct nas_msg_info){ "Service request", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x4d:
		return (struct nas_msg_info){ "Service reject", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x4e:
		return (struct nas_msg_info){ "Service accept", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x4f:
		return (struct nas_msg_info){ "Control plane service request", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x50:
		return (struct nas_msg_info){ "Network slice-specific authentication command", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x51:
		return (struct nas_msg_info){ "Network slice-specific authentication complete", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x52:
		return (struct nas_msg_info){ "Network slice-specific authentication result", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x54:
		return (struct nas_msg_info){ "Configuration update command", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x55:
		return (struct nas_msg_info){ "Configuration update complete", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x56:
		return (struct nas_msg_info){ "Authentication request", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x57:
		return (struct nas_msg_info){ "Authentication response", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x58:
		return (struct nas_msg_info){ "Authentication reject", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x59:
		return (struct nas_msg_info){ "Authentication failure", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x5a:
		return (struct nas_msg_info){ "Authentication result", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x5b:
		return (struct nas_msg_info){ "Identity request", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x5c:
		return (struct nas_msg_info){ "Identity response", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x5d:
		return (struct nas_msg_info){ "Security mode command", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x5e:
		return (struct nas_msg_info){ "Security mode complete", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x5f:
		return (struct nas_msg_info){ "Security mode reject", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x64:
		return (struct nas_msg_info){ "5GMM status", NAS_MSG_DIR_BOTH };
	case 0x65:
		return (struct nas_msg_info){ "Notification", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x66:
		return (struct nas_msg_info){ "Notification response", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x67:
		return (struct nas_msg_info){ "UL NAS transport", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x68:
		return (struct nas_msg_info){ "DL NAS transport", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x69:
		return (struct nas_msg_info){ "Relay key request", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0x6a:
		return (struct nas_msg_info){ "Relay key accept", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x6b:
		return (struct nas_msg_info){ "Relay key reject", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x6c:
		return (struct nas_msg_info){ "Relay authentication request", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0x6d:
		return (struct nas_msg_info){ "Relay authentication response", NAS_MSG_DIR_UE_TO_NETWORK };
	default:
		return (struct nas_msg_info){ NULL, NAS_MSG_DIR_UNKNOWN };
	}
}

// TS 24.501 표 9.7.2 - 5GSM 20개. 둘째 열은 8.3.x 의 "Direction:" 줄
static struct nas_msg_info sm_info(int msg_type) {
	switch (msg_type) {
	case 0xc1:
		return (struct nas_msg_info){ "PDU session establishment request", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0xc2:
		return (struct nas_msg_info){ "PDU session establishment accept", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0xc3:
		return (struct nas_msg_info){ "PDU session establishment reject", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0xc5:
		return (struct nas_msg_info){ "PDU session authentication command", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0xc6:
		return (struct nas_msg_info){ "PDU session authentication complete", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0xc7:
		return (struct nas_msg_info){ "PDU session authentication result", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0xc9:
		return (struct nas_msg_info){ "PDU session modification request", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0xca:
		return (struct nas_msg_info){ "PDU session modification reject", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0xcb:
		return (struct nas_msg_info){ "PDU session modification command", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0xcc:
		return (struct nas_msg_info){ "PDU session modification complete", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0xcd:
		return (struct nas_msg_info){ "PDU session modification command reject", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0xd1:
		return (struct nas_msg_info){ "PDU session release request", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0xd2:
		return (struct nas_msg_info){ "PDU session release reject", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0xd3:
		return (struct nas_msg_info){ "PDU session release command", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0xd4:
		return (struct nas_msg_info){ "PDU session release complete", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0xd6:
		return (struct nas_msg_info){ "5GSM status", NAS_MSG_DIR_BOTH };
	case 0xd8:
		return (struct nas_msg_info){ "Service-level authentication command", NAS_MSG_DIR_NETWORK_TO_UE };
	case 0xd9:
		return (struct nas_msg_info){ "Service-level authentication complete", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0xda:
		return (struct nas_msg_info){ "Remote UE report", NAS_MSG_DIR_UE_TO_NETWORK };
	case 0xdb:
		return (struct nas_msg_info){ "Remote UE report response", NAS_MSG_DIR_NETWORK_TO_UE };
	default:
		return (struct nas_msg_info){ NULL, NAS_MSG_DIR_UNKNOWN };
	}
}

const char *nas_msg_name(int epd, int msg_type) {
	if (epd == NAS_EPD_5GMM)
		return mm_info(msg_type).name;
	if (epd == NAS_EPD_5GSM)
		return sm_info(msg_type).name;
	return NULL;
}
