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
 *     5GSM  EPD 0x2e. 보안 헤더 없음 - 옥텟 2 는 PDU 세션 ID       TS 24.501 9.3 ↔ 9.4
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

// 메시지별 TLV-E IEI 집합. 9.11.1 이 IEI 를 "an IEI known in the message" 로 정의하므로 같은
// 	번호가 메시지마다 다른 IE 를 가리킴. 전역으로 0x7X = TLV-E 라고 보면 그 메시지 표에 없는
// 	번호에서 길이를 2옥텟으로 읽어 걸음이 어긋남
//
// 	            70 71 72 73 74 75 76 77 78 79 7A 7B 7C    표            개수
// 	RA          O  O  O  O  O  O  O  O  O  O  O  O  O     8.2.7.1.1     13
// 	CUC         O  O  O  O  -  O  O  O  -  O  -  -  -     8.2.19.1.1    8
//
// 	0x73 은 RA 에서 SOR transparent container, CUC 에서 NSAG information 임. 두 표에서 뜻이
// 	같은 것은 0x77 (5GS mobile identity) 하나이고 그것이 이 주사의 대상임
// 	비트 n = IEI (0x70 + n) 이 그 메시지 표에 TLV-E 로 있음
#define NAS_IEI_TLVE_FIRST			0x70
#define NAS_IEI_TLVE_SET_REGISTRATION_ACCEPT	0x1fff
#define NAS_IEI_TLVE_SET_CONFIG_UPDATE_COMMAND	0x02ef

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

static uint16_t read_be16(const uint8_t *bytes) {
	return (uint16_t)(bytes[0] << 8 | bytes[1]);
}

// MALFORMED 만 7.7.1 의 '없는 것으로 취급' 대상임
enum mobile_id_result { MOBILE_ID_TAKEN, MOBILE_ID_NOT_EXTRACTED, MOBILE_ID_MALFORMED };

// take_mobile_id: 5GS mobile identity 값에서 5G-S-TMSI 48비트를 꺼냄. TS 24.501 표 9.11.3.4.1
//
// 	타입 2  5G-GUTI    | 타입 | MCC MNC (3) | Region (1) | Set+Ptr (2) | TMSI (4) |   값 11 옥텟
// 	타입 4  5G-S-TMSI  | 타입 |                          | Set+Ptr (2) | TMSI (4) |   값  7 옥텟
// 	                                                      \___________  ___________/
// 	                                                                  48비트
//
//      길이가 표와 다르면 거부함. 앞부분만 읽으면 공격자가 덧붙인 바이트에서 신원을 꺼낸 셈이 됨
//
//      반환: TAKEN(48비트까지 담음) / NOT_EXTRACTED(종류만 담음 - 타입 1, 3, 5 는 영구 식별자라
//      48비트가 없음) / MALFORMED(길이가 표와 다름)
//      부작용: 종류는 셋 다 아닌 기형일 때만 빼고 id_type 에 담음. 48비트는 stmsi48 과 has_stmsi48 에
//      담음. 기형이면 rejected_ie_count 를 올림
static enum mobile_id_result take_mobile_id(const uint8_t *id_bytes, size_t id_bytes_len, struct nas_msg *nas_msg) {
	if (id_bytes_len < 1) {			// 타입 옥텟이 없음. 표가 최소 3 옥텟 (LV-E 3-n) 을 정했으므로 규격 밖
                nas_msg->rejected_ie_count++;
		return MOBILE_ID_MALFORMED;
        }
	int identity_type = id_bytes[0] & 0x07;
	size_t required_len = 0;		// 0 = 48비트를 싣지 않는 종류라 길이가 표에 고정되지 않음
	size_t cursor_offset_bytes = 0;
	if (identity_type == 2) {
		required_len = 11;
		cursor_offset_bytes = 5;
	} else if (identity_type == 4) {
		required_len = 7;
		cursor_offset_bytes = 1;
        }
	bool carries_stmsi48 = required_len != 0;
	if (carries_stmsi48 && id_bytes_len != required_len) {
                nas_msg->rejected_ie_count++;
		return MOBILE_ID_MALFORMED;
        }
	// 종류는 표 9.11.3.4.1 이 3비트 값 여덟 개 전부에 뜻을 줘 범위 검사가 없음. 48비트를 안 꺼내는
	// 	종류도 담는 이유: 하류가 '5G-GUTI 로 왔나' 를 보므로 SUCI 를 안 올리면 '안 읽음' 과 같아짐
	nas_msg->id_type = identity_type;
	if (!carries_stmsi48)
		return MOBILE_ID_NOT_EXTRACTED;
	const uint8_t *cursor = id_bytes + cursor_offset_bytes;
	uint64_t amf_set_id_and_pointer = read_be16(cursor);
	uint64_t tmsi = (uint64_t)cursor[2] << 24 | (uint64_t)cursor[3] << 16 | (uint64_t)cursor[4] << 8 | cursor[5];
	nas_msg->has_stmsi48 = true;
	nas_msg->stmsi48 = amf_set_id_and_pointer << 32 | tmsi;
	return MOBILE_ID_TAKEN;
}

// take_mobile_id_lve: LV-E 로 실린 5GS mobile identity 하나. 길이 2 옥텟 뒤에 값이 옴
//      반환 없음. 값 부분은 take_mobile_id 에 넘기므로 그쪽 부작용이 그대로 적용됨
//      부작용: 길이 2 옥텟이 없거나 선언된 길이가 메시지 끝을 넘으면 missing_mandatory_ie_count 를 올림
static void take_mobile_id_lve(const uint8_t *bytes, size_t bytes_len, struct nas_msg *nas_msg) {
	if (bytes_len < 2) {
		nas_msg->missing_mandatory_ie_count++;
		return;
	}
	size_t ie_len = read_be16(bytes);
	if (2 + ie_len > bytes_len) {
		nas_msg->missing_mandatory_ie_count++;
		return;
	}
	take_mobile_id(bytes + 2, ie_len, nas_msg);
}

// scan_guti: 선택 IE 를 건너뛰며 5G-GUTI (IEI 0x77) 를 찾음. 같은 IE 가 또 오면 첫 것만 씀 (7.6.3)
//
// 	IEI 비트 8 = 1            -> 1 옥텟            IE 타입 1, 2
// 	그 메시지의 TLV-E 집합    -> 1 + 2 + 길이      TLV-E. 위 NAS_IEI_TLVE_SET_*
// 	0x46, 0x47 (CUC 에서만)   -> 2, 8 옥텟         TV. 표 8.2.19.1.1
// 	그 밖                     -> 1 + 1 + 길이      TLV
//
// 	기형 IE 는 첫 것으로 보지 않고 주사를 이어감. 7.7.1 : "The UE shall treat all optional IEs that
// 	are syntactically incorrect in a message as not present in the message. The network shall take
// 	the same approach."
//
// 	모르는 IEI 를 TLV 로 보는 근거. 9.11.1 : "If this octet does not correspond to an IEI known in
// 	the message, the receiver shall determine whether this IE is of type 1 or 2 ... or an IE of
// 	type 4 (i.e. that the next octet is the length indicator ...)".
// 	열거가 닫혀 있어 TLV-E 는 선택지에 없음. 그래서 그 메시지 표에 TLV-E 로 없는 번호는 TLV 로 봄.
// 	2 옥텟 길이로 읽으면 걸음이 어긋나 공격자가 고른 48비트가 5G-S-TMSI 로 올라감
//
// 	0x46 · 0x47 을 메시지로 가르는 이유: REGISTRATION ACCEPT 표에는 그 IEI 가 없음. 거기서 TV 로
// 	추측하면 걸음이 어긋나 공격자가 고른 바이트를 5G-S-TMSI 로 읽음
//
// 	비트 8 로 가르는 근거는 두 대상 메시지의 IEI 전수 분류임 (표 8.2.7.1.1 및 8.2.19.1.1) -
// 	IE 타입 1 TV 는 전부 비트 8 = 1 이고, 비트 8 이 0 인 TV 는 CUC 의 둘뿐
//
// 	부작용: 선언된 길이나 TV 의 표가 정한 크기가 메시지 끝을 넘으면 ie_scan_aborted_count 를 올림.
// 	5G-GUTI 를 못 본 것이 "GUTI 가 없었다" 와 같아짐. 표에 없는 0x70~0x7F 번호를 TLV 로
// 	건너뛰면 unknown_tlve_iei_count 를 올림
static void scan_guti(const uint8_t *bytes, size_t bytes_len, size_t offset_bytes, int msg_type, struct nas_msg *nas_msg) {
	uint16_t tlve_iei_set = NAS_IEI_TLVE_SET_REGISTRATION_ACCEPT;
	if (msg_type == NAS_MM_CONFIG_UPDATE_COMMAND)
		tlve_iei_set = NAS_IEI_TLVE_SET_CONFIG_UPDATE_COMMAND;
	while (offset_bytes < bytes_len) {
		uint8_t iei = bytes[offset_bytes];
		if (iei & 0x80) {
			offset_bytes++;
			continue;
		}
		// 비트 8 이 0 이라 0x70 이상이면 0x70~0x7F 번호대임
		bool in_tlve_block = iei >= NAS_IEI_TLVE_FIRST;
		bool is_tlve_iei = in_tlve_block && ((tlve_iei_set >> (iei - NAS_IEI_TLVE_FIRST)) & 1);
		if (is_tlve_iei) {
			if (offset_bytes + 3 > bytes_len) {
				nas_msg->ie_scan_aborted_count++;
				return;
			}
			size_t ie_len = read_be16(bytes + offset_bytes + 1);
			if (offset_bytes + 3 + ie_len > bytes_len) {
				nas_msg->ie_scan_aborted_count++;
				return;
			}
			if (iei == NAS_IEI_5GS_MOBILE_IDENTITY
			    && take_mobile_id(bytes + offset_bytes + 3, ie_len, nas_msg) != MOBILE_ID_MALFORMED)
				return;
			offset_bytes += 3 + ie_len;
		} else if (msg_type == NAS_MM_CONFIG_UPDATE_COMMAND && iei == NAS_IEI_LOCAL_TIME_ZONE) {
			if (offset_bytes + NAS_IE_BYTES_LOCAL_TIME_ZONE > bytes_len) {
				nas_msg->ie_scan_aborted_count++;
				return;
			}
			offset_bytes += NAS_IE_BYTES_LOCAL_TIME_ZONE;
		} else if (msg_type == NAS_MM_CONFIG_UPDATE_COMMAND && iei == NAS_IEI_UNIVERSAL_TIME_AND_TIME_ZONE) {
			if (offset_bytes + NAS_IE_BYTES_UNIVERSAL_TIME_AND_TIME_ZONE > bytes_len) {
				nas_msg->ie_scan_aborted_count++;
				return;
			}
			offset_bytes += NAS_IE_BYTES_UNIVERSAL_TIME_AND_TIME_ZONE;
		} else {
			if (in_tlve_block)
				nas_msg->unknown_tlve_iei_count++;
			if (offset_bytes + 2 > bytes_len) {
				nas_msg->ie_scan_aborted_count++;
				return;
			}
			size_t ie_len = bytes[offset_bytes + 1];
			if (offset_bytes + 2 + ie_len > bytes_len) {
				nas_msg->ie_scan_aborted_count++;
				return;
			}
			offset_bytes += 2 + ie_len;
		}
	}
}

// parse_plain: 평문 5GMM / 5GSM 메시지 하나. 배치는 파일 헤더 [1]
// 	inner=true 는 보호된 메시지의 안쪽. 그때만 옥텟 2 의 보안 헤더 타입을 봄 - 0 이 아니면
// 	inner_not_plain_count 를 올리되 해석은 이어감. 바깥 호출에선 옥텟 2 를 읽지 않음
// 	반환: 0 = 해석함, -EBADMSG = 형식 오류 (이유 계수기 하나를 올린 뒤)
static int parse_plain(const uint8_t *buf, size_t len, struct nas_msg *nas_msg, bool inner) {
	if (len < 3) {
		nas_msg->truncated_count++;
		return -EBADMSG;
	}
	// 보호된 안쪽은 규격상 늘 5GMM 임. 5GSM 은 5GMM 전송 메시지의 Payload container 로만 운반되고
	// 	보안 보호는 5GMM 계층 기능임. 그래서 inner 면 아래 5GMM 검사로 떨어져 epd_mismatch 가 됨
	if (!inner && buf[0] == NAS_EPD_5GSM) {
		if (len < 4) {
			nas_msg->truncated_count++;
			return -EBADMSG;
		}
		struct nas_msg_info info = sm_info(buf[3]);
		if (!info.name) {
			nas_msg->unknown_msg_type_count++;
			return 0;
		}
		nas_msg->msg_type = buf[3];
		nas_msg->msg_type_direction = info.msg_type_direction;
		return 0;
	}
	if (buf[0] != NAS_EPD_5GMM) {
		nas_msg->epd_mismatch_count++;
		return -EBADMSG;
	}
	// 8.2.28.1 은 안쪽을 "a plain 5GS NAS message" 로 정하고 표 9.3.1 에서 평문의 보안 헤더 타입은
	// 	0000 뿐임. 버리지는 않음 - 실측 캡처에서 OAI 가 DEREGISTRATION REQUEST (UE originating)
	// 	의 그 자리에 0x04 를 싣는데 옥텟 3 부터는 멀쩡히 풀려, 버리면 실제 메시지를 잃음
	// 	남기는 이유: 안쪽이 또 보호된 것이면 옥텟 3 은 타입이 아니라 MAC 첫 옥텟임 (실측: 안쪽
	// 	SHT 1~4 x MAC 첫 옥텟 전수 1,024건 중 148건에 이름이 붙음). 바이트로는 둘을 가릴 수 없음
	if (inner && (buf[1] & 0x0f) != 0)
		nas_msg->inner_not_plain_count++;
	// 이름표가 관문임. 두 표의 값 구간이 겹치지 않아 (5GMM 0x41~0x6d, 5GSM 0xc1~0xdb) 표 밖의 값을
	// 	담으면 소비자가 반대쪽 표로 조회해 다른 이름이 붙음
	struct nas_msg_info info = mm_info(buf[2]);
	if (info.name) {
		nas_msg->msg_type = buf[2];
		nas_msg->msg_type_direction = info.msg_type_direction;
	} else {
		nas_msg->unknown_msg_type_count++;
	}
	const uint8_t *bytes = buf + 3;
	size_t bytes_len = len - 3;
	// 지역 변수가 아니라 nas_msg->msg_type 으로 분기함. 표에 없는 타입은 -1 이라 default 로 떨어져
	// 	어떤 IE 도 꺼내지 않음 - 표와 아래 case 집합이 어긋나도 신원이 새지 않음
	switch (nas_msg->msg_type) {
	case NAS_MM_REGISTRATION_REQUEST:	// 8.2.6 : ngKSI|등록 유형 (V 1), 5GS mobile identity (LV-E)
		// 관문을 IE 마다 나눔. 하나로 묶으면 2 옥텟 메시지에서 등록 유형이 있는데도 안 담김
		if (bytes_len < 1) {
			nas_msg->missing_mandatory_ie_count++;
			break;
		}
		nas_msg->reg_type = bytes[0] & 0x07;
		if (bytes_len < 3) {
			nas_msg->missing_mandatory_ie_count++;
			break;
		}
		take_mobile_id_lve(bytes + 1, bytes_len - 1, nas_msg);
		break;
	case NAS_MM_DEREG_REQ_UE_ORIG:		// 8.2.12 : ngKSI|해제 유형 (V 1), 5GS mobile identity (LV-E)
		// 관문을 IE 마다 나눔(위 8.2.6 과 같은 이유). 표 8.2.12.1.1 이 해제 유형을 `M V 1/2`,
		// 	5GS mobile identity 를 `M LV-E 6-n` 으로 둔 별개 IE 라, 신원이 없어도 해제 유형은 읽힘
		if (bytes_len < 1) {
                        nas_msg->missing_mandatory_ie_count++;
                        break;
                }
		// Switch off 는 표 9.11.3.20.1 의 "Switch off (octet 1, bit 4)". 반옥텟 두 개가 한 옥텟을
		// 	나눌 때 표에 먼저 적힌 쪽이 낮은 비트임 - 바로 위 8.2.6 의 등록 유형이 같은 관례이고
		// 	실 캡처에서 initial(1) 로 읽히는 것으로 확인됨
		nas_msg->switch_off = (bytes[0] >> 3) & 0x01;
		if (bytes_len < 3) {
                        nas_msg->missing_mandatory_ie_count++;
                        break;
                }
		take_mobile_id_lve(bytes + 1, bytes_len - 1, nas_msg);
                break;
	case NAS_MM_SERVICE_REQUEST:		// 8.2.16 : 서비스 유형|ngKSI (V 1), 5G-S-TMSI (LV-E)
		if (bytes_len < 3) {
                        nas_msg->missing_mandatory_ie_count++;
                        break;
                }
		take_mobile_id_lve(bytes + 1, bytes_len - 1, nas_msg);
                break;
	case NAS_MM_IDENTITY_RESPONSE:		// 8.2.22 : 5GS mobile identity (LV-E) 가 타입 바로 뒤
		take_mobile_id_lve(bytes, bytes_len, nas_msg);
		break;
	case NAS_MM_SECURITY_MODE_COMMAND:	// 8.2.25 : 선택 NAS 보안 알고리즘 (V 1)
		// 표 9.11.3.34.1 은 두 니블 모두 0000~0111 만 정의하고 "All other values are reserved." 임
		// 	한 니블이라도 예약값이면 IE 전체를 버림. 알고리즘이 모름으로 남아 안쪽을 읽지 않게 됨
		if (bytes_len < 1) {
			nas_msg->missing_mandatory_ie_count++;
			break;
		}
		{
			int ciph_alg = (bytes[0] >> 4) & 0x0f;
			int integ_alg = bytes[0] & 0x0f;
			if (ciph_alg > 7 || integ_alg > 7) {
				nas_msg->rejected_ie_count++;
				break;
			}
			nas_msg->has_sec_alg = true;
			nas_msg->nas_ciph_alg = ciph_alg;
			nas_msg->nas_integ_alg = integ_alg;
		}
		break;
	case NAS_MM_REGISTRATION_REJECT:	// 8.2.9
	case NAS_MM_SERVICE_REJECT:		// 8.2.18
	case NAS_MM_AUTH_FAILURE:		// 8.2.4
	case NAS_MM_SECURITY_MODE_REJECT:	// 8.2.27
	case NAS_MM_5GMM_STATUS:		// 8.2.29 - 다섯 다 타입 바로 뒤 5GMM 원인 (V 1)
		if (bytes_len < 1) {
			nas_msg->missing_mandatory_ie_count++;
			break;
		}
		// 범위 검사 없음. 표 9.11.3.2.1 : "Any other value received by the network shall be
		// 	treated as 0110 1111, "protocol error, unspecified"." - 256개 값 전부에 해석이 있음
		nas_msg->mm_cause = bytes[0];
		break;
	case NAS_MM_DEREG_REQ_UE_TERM:		// 8.2.14 : 해제 유형|spare (V 1), 5GMM 원인은 선택 (TV 2
		// 표 8.2.14.1.1 이 해제 유형과 spare 반옥텟을 `M V 1/2` 둘로 둬 필수 1 옥텟임. 그 방향에선
		// 	비트 4 가 spare 라 값은 안 읽지만(표 9.11.3.20.1 "In the network to UE direction bit 4
		// 	is spare"), 없다는 사실은 세야 기형과 정상이 같은 모양이 되지 않음
		if (bytes_len < 1) {
                        nas_msg->missing_mandatory_ie_count++;
                        break;
                }
		// 첫 선택 IE 만 봄. 7.6.2 : "The UE shall ignore all out of sequence IEs in a message
		// 	which are not encoded as "comprehension required" ... The network should take the
		// 	same approach."
		// 표 8.2.14.1.1 은 5GMM 원인을 `O TV 2` 로 둠. 길이 옥텟이 없어 표가 정한 2 옥텟을 씀
		// 	IEI 는 왔는데 값 옥텟이 없으면 scan_guti 의 TV 분기와 같이 주사 중단을 남김
		// 	안 남기면 "상대가 원인을 안 보냈다" 와 같은 모양이 되어 지표에서 가릴 수 없음
		if (bytes_len == 2 && bytes[1] == NAS_IEI_5GMM_CAUSE)
			nas_msg->ie_scan_aborted_count++;
		else if (bytes_len >= 3 && bytes[1] == NAS_IEI_5GMM_CAUSE)
			nas_msg->mm_cause = bytes[2];
		break;
	case NAS_MM_REGISTRATION_ACCEPT:	// 8.2.7 : 5GS 등록 결과 (LV 2) 뒤 선택 IE 중 5G-GUTI
		if (bytes_len < 2) {		// 길이 옥텟이 없으면 선택 IE 시작점을 알 수 없음
			nas_msg->missing_mandatory_ie_count++;
			break;
		}
		// 표 8.2.7.1.1 이 `M LV 2` 로 못박아 길이 옥텟 값은 1 뿐임. 검사 없이 주사 시작점으로 쓰면
		// 	그 시작점이 상대가 고른 값이 됨 - 꼬리가 같은 두 입력이 서로 다른 5G-S-TMSI 를
		// 	rc=0 으로 내놓았음 (확신 있는 오값)
		if (bytes[0] != 1) {
			nas_msg->rejected_ie_count++;
			break;
		}
		scan_guti(bytes, bytes_len, 2, nas_msg->msg_type, nas_msg);
		break;
	case NAS_MM_CONFIG_UPDATE_COMMAND:	// 8.2.19 : 선택 IE 만
		scan_guti(bytes, bytes_len, 0, nas_msg->msg_type, nas_msg);
		break;
	default:
		break;
	}
	return 0;
}

// nas_parse: NAS-PDU 하나를 해석해 nas_msg 를 채움. 분기는 파일 헤더 [2]
// 	known_nas_ciph_alg 가 0 (NEA0) 이 아니면 암호된 안쪽을 읽지 않음 - 가시성은 호출자가 정함
// 	반환: 0 = 해석함, -EBADMSG = 형식 오류, -EINVAL = 호출자 버그 (계수기를 올리지 않음)
// 	buf 는 빌려 읽기만 하고 nas_msg 밖으로 포인터를 남기지 않음. 힙·전역 상태 없음
int nas_parse(const uint8_t *buf, size_t len, int known_nas_ciph_alg, struct nas_msg *nas_msg) {
	if (!nas_msg)
		return -EINVAL;
	memset(nas_msg, 0, sizeof(*nas_msg));
	nas_msg->msg_type = -1;
	nas_msg->nas_sequence_number = -1;
	nas_msg->mm_cause = -1;
	nas_msg->reg_type = -1;
	nas_msg->id_type = -1;
	nas_msg->switch_off = -1;
	nas_msg->nas_ciph_alg = -1;
	nas_msg->nas_integ_alg = -1;
	// 0 을 그대로 두면 '평문 (SHT 0)' 과 '해당 없음' 이 같아짐. epd 도 같다 - 0 은 EPD 값이 아니지만
	// 	호출자는 음수만 센티널로 보므로 0 이 남으면 '읽었다' 로 읽힘
	nas_msg->epd = -1;
	nas_msg->sht = -1;

	// buf 가 NULL 인데 len 이 0 이 아니면 호출자 버그임. 와이어 사실이 아니므로 세지 않음
	if (!buf && len > 0)
		return -EINVAL;
	// 길이 0 NAS-PDU 는 와이어에서 올 수 있음 (ap.h 가 len 0 을 NULL 로 넘김). 잘린 PDU 는 libsctp 가
	// 	부분 청크에서 멈춰 디코더에 닿지 않으므로, 여기 온 길이는 상대가 정한 값임
	if (len < 2) {
		nas_msg->truncated_count++;
		return -EBADMSG;
	}
	// 아는 두 값만 담음. EPD 가 타입을 어느 표 (9.7.1 / 9.7.2) 로 읽을지 고르므로, 표 밖의 값을 담으면
	// 	소비자가 그 값으로 분기함. "상대가 모르는 EPD 를 보냈다" 는 사실은 계수기가 나름
	if (buf[0] != NAS_EPD_5GMM && buf[0] != NAS_EPD_5GSM) {
		nas_msg->epd_mismatch_count++;
		return -EBADMSG;
	}
	nas_msg->epd = buf[0];
	if (buf[0] == NAS_EPD_5GSM) {
		int parse_result = parse_plain(buf, len, nas_msg, false);
		nas_msg->inner_readable = parse_result == 0;
		return parse_result;
	}
	nas_msg->sht = buf[1] & 0x0f;
	if (nas_msg->sht == 0) {
		int parse_result = parse_plain(buf, len, nas_msg, false);
		nas_msg->inner_readable = parse_result == 0;
		return parse_result;
	}
	if (nas_msg->sht > 4) {
		nas_msg->reserved_sht_count++;
		// 예약 코드값을 내보내면 호출자가 그 니블에 판정 등급을 달아 출력함. 정의역은 0~4 와 -1 뿐
		nas_msg->sht = -1;
		return -EBADMSG;
	}
	if (len < NAS_PROTECTED_HEADER_BYTES + 3) {
		nas_msg->truncated_count++;
		return -EBADMSG;
	}
	nas_msg->nas_sequence_number = buf[6];
	bool ciphered = nas_msg->sht == 2 || nas_msg->sht == 4;
	if (ciphered && known_nas_ciph_alg != 0)
		return 0;	// 암호인데 NEA0 가 아니거나 모름 - 안 읽음. msg_type 은 -1 로 남음
	int parse_result = parse_plain(buf + NAS_PROTECTED_HEADER_BYTES, len - NAS_PROTECTED_HEADER_BYTES, nas_msg, true);
	if (parse_result < 0)
		return parse_result;
	nas_msg->inner_readable = true;
	return 0;
}
