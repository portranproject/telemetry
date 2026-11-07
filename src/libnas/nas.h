/**
 * nas.h
 * : libnas 공개 계약 - 5GS NAS 메시지로부터 값 추출과 계수
 *
 * [1] 이 라이브러리가 정하지 않는 것 두 가지. 아래 전제를 이 계층이 모르므로 호출자가 판정함.
 *       가시성  보호된 안쪽을 읽을지     <- known_nas_ciph_alg 를 호출자가 넘김
 *       방향    타입이 올 수 있는 방향   -> msg_type_direction 을 호출자가 와이어 방향과 대조
 * [2] nas_parse 반환값과 그때 읽어도 되는 필드
 *       0      전부
 *       음수   이유별 계수기, 그리고 보안 머리에서 읽은 만큼 - epd / sht / nas_sequence_number.
 *              못 읽은 것은 -1 임. 이 셋을 남기는 이유: 호출자가 바이트를 다시 뜯으면 예약 SHT
 *              판정이 두 계층에서 갈림
 * [3] 다루지 않는 것 : 영구 식별자 SUCI / IMEI / IMEISV. 임시 식별자 5G-S-TMSI 만 꺼냄.
 */

#ifndef TELEMETRY_NAS_H
#define TELEMETRY_NAS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum nas_epd {
	NAS_EPD_5GMM = 0x7e,
	NAS_EPD_5GSM = 0x2e
};
#define NAS_CIPH_UNKNOWN (-1)

// 보호된 5GS NAS 메시지의 머리 길이. EPD 1 + SHT 1 + MAC 4 + Sequence number 1 (TS 24.501 8.2.28)
// 	공개인 이유: 와이어 포맷 사실이고 읽는 쪽이 둘이다 (디코더, 퍼저의 안쪽 메시지 배치)
#define NAS_PROTECTED_HEADER_BYTES 7

// 타입이 규격상 올 수 있는 방향. TS 24.501 8.2.x / 8.3.x 각 메시지의 "Direction:" 줄
// 	7.4 NOTE : "A message type not defined for the EPD in the given direction is regarded
// 	by the receiver as a message type not defined for the EPD"
// 	즉 '아는 타입' 판정에 방향이 들어감. 와이어 방향은 libnas 가 모르므로 표가 말하는 허용 방향만 담음.
enum nas_msg_direction {
	NAS_MSG_DIR_UNKNOWN = 0,        // 표에 없는 타입
	NAS_MSG_DIR_UE_TO_NETWORK,      // 상행 전용
	NAS_MSG_DIR_NETWORK_TO_UE,      // 하행 전용
	NAS_MSG_DIR_BOTH,               // 5GMM STATUS (0x64), 5GSM STATUS (0xd6) 뿐
};

// TS 24.501 8.2 5GMM 메시지 타입. 코드가 분기하는 것만 둠. 표 전체는 nas.c 의 mm_info
enum nas_mm_type {
	NAS_MM_REGISTRATION_REQUEST   = 0x41, NAS_MM_REGISTRATION_ACCEPT    = 0x42,
	NAS_MM_REGISTRATION_COMPLETE  = 0x43, NAS_MM_REGISTRATION_REJECT    = 0x44,
	NAS_MM_DEREG_REQ_UE_ORIG      = 0x45, NAS_MM_DEREG_ACC_UE_ORIG      = 0x46,
	NAS_MM_DEREG_REQ_UE_TERM      = 0x47, NAS_MM_DEREG_ACC_UE_TERM      = 0x48,
	NAS_MM_SERVICE_REQUEST        = 0x4c, NAS_MM_SERVICE_REJECT         = 0x4d,
	NAS_MM_SERVICE_ACCEPT         = 0x4e, NAS_MM_CP_SERVICE_REQUEST     = 0x4f,
	NAS_MM_CONFIG_UPDATE_COMMAND  = 0x54,
	NAS_MM_AUTH_REQUEST           = 0x56, NAS_MM_AUTH_RESPONSE          = 0x57,
	NAS_MM_AUTH_REJECT            = 0x58, NAS_MM_AUTH_FAILURE           = 0x59,
	NAS_MM_IDENTITY_REQUEST       = 0x5b, NAS_MM_IDENTITY_RESPONSE      = 0x5c,
	NAS_MM_SECURITY_MODE_COMMAND  = 0x5d, NAS_MM_SECURITY_MODE_COMPLETE = 0x5e,
	NAS_MM_SECURITY_MODE_REJECT   = 0x5f, NAS_MM_5GMM_STATUS            = 0x64,
};

// TS 24.501 표 8.2.14.1.1 의 선택 IE 번호. 값이 NAS_MM_AUTH_REJECT 와 같지만 다른 이름공간임
#define NAS_IEI_5GMM_CAUSE 0x58

// TS 24.501 표 9.11.3.2.1 의 5GMM 원인값. 거절이 영구인지(단말·가입 자체가 거부) 가리는 셋만 둠 -
// 	그 셋만 5GMM 주상태를 DEREGISTERED 로 확정하는 근거이기 때문임
enum nas_mm_cause {
	NAS_CAUSE_ILLEGAL_UE = 3,
	NAS_CAUSE_ILLEGAL_ME = 6,
	NAS_CAUSE_5GS_NOT_ALLOWED = 7
};

// REGISTRATION REQUEST 의 5GS 등록 유형. TS 24.501 표 9.11.3.7.1, 하위 3비트
// 	3비트 중 이름이 없는 값은 0 하나뿐임. 표가 "All other values are unused and shall be
// 	interpreted as "initial registration", if received by the network" 라고 정했으므로 raw 값을
// 	그대로 담고, 이름을 붙이는 쪽이 0 을 initial 로 읽음
enum nas_reg_type {
	NAS_REG_INITIAL = 1,
	NAS_REG_MOBILITY = 2,
	NAS_REG_PERIODIC = 3,
	NAS_REG_EMERGENCY = 4,
	NAS_REG_SNPN_ONBOARDING = 5,
	NAS_REG_DISASTER_MOBILITY = 6,
	NAS_REG_DISASTER_INITIAL = 7
};
#endif /* TELEMETRY_NAS_H */
