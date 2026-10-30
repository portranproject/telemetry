# asn1 : 3GPP 제어평면 메시지 문법과 디코더 생성

libcap 은 SCTP 바이트만 넘기고, 그 안의 F1AP/NGAP/RRC 는 ASN.1(APER/UPER)로 인코딩돼 있음.
해당 문법과 생성 설정/패치를 포함하고 있으며, `make asn1` 로 디코더 라이브러리 4개 생성.
(`build/lib{f1ap,nrrrc,ngap,asn1skel}.a`)

## 파일 목록

| 파일 | 내용 | 용도 |
|---|---|---|
| `f1ap-18.8.0.asn`    | F1AP 문법 (TS 38.473 V18.8.0) | `libf1ap.a` (APER) 생성 |
| `nr-rrc-17.3.0.asn1` | NR RRC 문법 (TS 38.331)        | `libnrrrc.a` (UPER) 생성 — F1AP 안의 RRC 컨테이너 |
| `ngap-15.8.0.asn1`   | NGAP 문법 (TS 38.413)          | `libngap.a` (APER) 생성 — N2 |
| `asn1.mk`            | 생성된 C -> .a 4개로 묶는 빌드 규칙 | 상위 Makefile 이 재귀 호출 |
| `asn1_glue.c`        | 패치가 사용하는 전역 카운터 2개   | skeleton 라이브러리에 포함 |
| `patches/`           | 패치 파일 | 생성 전/후에 적용 |

