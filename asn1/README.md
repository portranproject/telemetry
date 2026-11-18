# asn1 — 3GPP 규격의 ASN.1 문법에서 F1AP·NGAP·RRC 디코더 생성

5G 기지국은 무선을 맡는 DU(Distributed Unit)와 그 위의 CU(Central Unit)로 나뉘고, CU 는 코어망의
AMF(단말의 접속과 이동을 관리하는 기능)에 연결된다. 이 폴더는 그 사이를 오가는 제어 메시지 세 가지의 디코더를 만든다.

| 프로토콜 | 오가는 구간 | 규격·판 | 부호화 규칙 | 문법 파일 |
|---|---|---|---|---|
| F1AP | DU ↔ CU (F1 구간) | 3GPP TS 38.473 V18.8.0 (2025-12) | APER | `f1ap-18.8.0.asn` |
| NGAP | CU ↔ AMF (N2 구간) | 3GPP TS 38.413 V15.8.0 (2020-07) | APER | `ngap-15.8.0.asn1` |
| NR RRC | 단말 ↔ CU. F1 구간에서는 F1AP 메시지 안에 실려 지나간다 | 3GPP TS 38.331 V17.3.0 (2022-12) | UPER | `nr-rrc-17.3.0.asn1` |

세 규격은 메시지의 구조를 ASN.1 이라는 표기법으로 적는다. 이 README 는 그 ASN.1 텍스트를 "문법" 이라고 부른다.
선로에는 문법의 구조를 부호화 규칙(ITU-T X.691 의 PER)에 따라 비트로 바꾼 것이 실린다. APER 는 값을 바이트 경계에
맞추는 변종이고 UPER 는 맞추지 않는 변종이다(TS 38.473 9.5 절, TS 38.413 9.5 절, TS 38.331 8.1 절).

이 README 에서 쓰는 말:

- **PDU**: 프로토콜 메시지 하나.
- **IE**(Information Element): 메시지 안의 항목 하나. F1AP·NGAP 메시지는 IE 의 목록이다.
- **판**: 규격의 버전. V18.8.0 은 Release 18 의 8.0 판이다.
- **asn1c**: ASN.1 문법을 C 코드로 바꾸는 공개 도구(§5).
- **skeleton**: asn1c 가 함께 설치하는 런타임 C 코드. 문법에서 생성되는 `F1AP_*.c` 는 타입마다의 표이고,
  그 표를 읽어 비트를 실제로 푸는 코드가 skeleton 이다.

```
f1ap-18.8.0.asn     (F1AP)  ──┐        asn1c (고정 커밋 + patches/)
ngap-15.8.0.asn1    (NGAP)  ──┼── asn1c ──▶ C 소스 ──▶ build/libf1ap.a  libngap.a  libnrrrc.a  libasn1skel.a
nr-rrc-17.3.0.asn1  (RRC)   ──┘
```

이 폴더의 규칙은 두 가지다.

1. **문법은 규격 원문 그대로 쓴다.** 문법 파일을 손으로 고치지 않고, 고친 사본으로 디코더를 만들지도 않는다.
   문법을 고치면 그 디코더는 표준이 정한 메시지가 아니라 우리가 정한 메시지를 읽게 된다.
2. **고칠 것이 있으면 도구(asn1c)를 고친다.** 고친 내용은 전부 `patches/` 에 패치 파일로 두고,
   각 패치에 무엇을 왜 고쳤는지와 어디서 가져왔는지를 적는다.

## 1. 폴더 구성

| 경로 | 내용 |
|---|---|
| `f1ap-18.8.0.asn` | F1AP 문법. TS 38.473 V18.8.0 |
| `ngap-15.8.0.asn1` | NGAP 문법. TS 38.413 V15.8.0. OAI 저장소가 보관한 파일과 바이트까지 같다 |
| `nr-rrc-17.3.0.asn1` | NR RRC 문법. TS 38.331 V17.3.0. OAI 저장소가 보관한 파일과 바이트까지 같다 |
| `SOURCES` | 문법마다 규격·판·3GPP 배포 파일·sha256 을 적은 표 |
| `patches/01`~`11` | asn1c 에 적용하는 패치 11개(§4.3) |
| `asn1.mk` | 빌드 규칙. asn1c 받기부터 라이브러리까지 |
| `asn1_glue.c` | 패치 04·07·11 이 올리는 계수기 2개의 정의 |

## 2. 빌드

`Makefile` 이 있는 디렉터리(이 폴더의 한 단계 위)에서 실행한다.

```sh
sudo apt-get install -y git build-essential autoconf automake libtool bison flex patch   # Ubuntu 24.04, 한 번만
make -j"$(nproc)" asn1
```

| 단계 | 하는 일 | 결과 |
|---|---|---|
| 1 | asn1c 를 GitHub 에서 고정 커밋으로 받고, 받은 커밋의 해시를 대조한다 | `build/asn1c/src/` |
| 2 | `patches/` 의 패치를 이름 순으로 적용한다. 문맥이 한 줄이라도 어긋나거나 이미 적용된 패치이면 멈춘다 | |
| 3 | asn1c 를 빌드해 `build/asn1c/` 안에 설치한다 | `build/asn1c/bin/asn1c`, `build/asn1c/.installed` |
| 4 | 문법 3개를 C 소스로 바꾼다 | `build/gen/{f1ap,ngap,rrc}/` |
| 5 | 세 디렉터리에 복사된 skeleton 을 한곳에 모은다 | `build/gen/skel/` |
| 6 | 컴파일해 정적 라이브러리 4개로 묶는다 | `build/lib{f1ap,ngap,nrrrc,asn1skel}.a` |

- **필요한 도구의 판**: GNU make 4.0 이상(3.x 면 오류를 내고 멈춘다). asn1c 의 파서는 빌드할 때 bison 과 flex 로 생성된다.
  확인한 판은 Ubuntu 24.04 의 GNU make 4.3, bison 3.8.2, flex 2.6.4 다.

## 3. 문법 파일 — 어디서 왔고, 규격과 같은가

### 3.1 출처

| 문법 파일 | 규격·판 | 3GPP 배포 파일 | 파일이 온 곳 |
|---|---|---|---|
| `f1ap-18.8.0.asn` | TS 38.473 V18.8.0 (2025-12) | `38.473/38473-i80.zip` | 이 저장소에 전부터 있던 파일. OCUDU release_26_10 이 쓰는 판과 같다 |
| `ngap-15.8.0.asn1` | TS 38.413 V15.8.0 (2020-07) | `38.413/38413-f80.zip` | OAI 저장소 `openair3/NGAP/MESSAGES/ASN1/ngap-15.8.0.asn1` (바이트까지 같다) |
| `nr-rrc-17.3.0.asn1` | TS 38.331 V17.3.0 (2022-12) | `38.331/38331-h30.zip` | OAI 저장소 `openair2/RRC/NR/MESSAGES/ASN.1/nr-rrc-17.3.0.asn1` (바이트까지 같다) |

### 3.2 3GPP 는 ASN.1 을 어떻게 배포하는가

3GPP 는 이 세 규격의 ASN.1 을 별도 파일로 배포하지 않는다. 위 zip 3개를 풀면 규격 문서 1개만 나온다
(`38473-i80.zip`·`38331-h30.zip` 은 `.docx`, `38413-f80.zip` 은 `.doc`). ASN.1 은 그 문서 본문에 들어 있다.

본문에서 ASN.1 을 뽑는 규칙은 TS 38.331 의 Annex A.3.1.1 "ASN.1 clauses" 가 적고 있다(Annex A 는 규격 작성 지침을 담은
참고용 부록이다). 요지: ASN.1 을 규격에서 뽑기 쉽도록, 각 ASN.1 절은 `-- ASN1START` 만으로 된 문단으로 시작하고
`-- ASN1STOP` 만으로 된 문단으로 끝난다. TS 38.473 과 TS 38.413 에는 이런 설명이 없지만 9.4.3~9.4.8 절의 모듈 6개가
같은 표식으로 싸여 있다. Wireshark 의 추출 스크립트(`tools/extract_asn1_from_spec.pl`)도 이 표식을 쓴다.

OAI 가 보관한 NGAP·RRC 파일도 이 규칙으로 뽑은 것이다. NGAP 파일에는 표식 줄(`-- ASN1START`, `-- ASN1STOP`)이
주석으로 남아 있고, 줄 끝이 CRLF 이며, 본문의 따옴표 두 곳이 UTF-8 이 아닌 글자로 들어 있다. 전부 주석 안이라 문법에
영향이 없다.

## 4. asn1c — 어디서 가져와 어떻게 쓰나

asn1c 는 ASN.1 문법을 C 코드로 바꾸는 공개 도구다. 3GPP 가 만든 것이 아니고, 3GPP 는 변환기를 지정하지 않는다.

### 4.1 어느 저장소의 어느 커밋인가

| 항목 | 값 |
|---|---|
| 저장소 | `https://github.com/mouse07410/asn1c` |
| 브랜치 | `vlm_master` (이 저장소의 기본 브랜치) |
| 커밋 | `940dd5fa9f3917913fd487b13dfddfacd0ded06e` (2024-04-05) |
| 받는 방법 | `git fetch --depth 1 <저장소> <커밋>` 뒤 `git rev-parse HEAD` 가 위 값과 같은지 대조 |
| 설치 위치 | `build/asn1c/` (`build/` 밖에는 아무것도 설치하지 않는다) |

이름이 비슷한 것이 둘 있다. asn1c 의 원본은 `github.com/vlm/asn1c` 다. `mouse07410/asn1c` 는 그것을 복제해
기능을 더한 포크이고, 포크의 기본 브랜치 이름이 `vlm_master` 다. `vlm` 저장소와 `vlm_master` 브랜치는 다른 것이다.

### 4.2 왜 이 커밋이고, 왜 가장 새 릴리스가 아닌가

- **같은 커밋을 OAI 와 FlexRIC 이 쓴다.** OAI 의 `cmake_targets/tools/build_helper` 와 FlexRIC 의 Dockerfile 4개가
  이 해시를 `git checkout` 한다. OAI 스크립트에는 이유가 주석으로 있다: 바로 다음 커밋 `5fa129cf`(2024-05-22)가
  F1 과 NG 를 깬다.
- **새 릴리스로는 우리 디코더가 빌드되지 않는다.** 포크의 가장 새 릴리스는 v1.5.3(2026-10-07)이다.
  v1.5.2(2026-10-04)로 같은 문법·같은 옵션을 생성해 보면 구조체의 모양이 달라진다(값으로 들어 있던 멤버가 포인터가 된다).
  `rrc.c` 가 26곳에서 컴파일 오류를 내고, 오류 없이 컴파일되는 `ngap.c` 는 GUAMI(AMF 식별자)를 읽는 곳에서
  SIGSEGV 로 끝난다. v1.5.3 도 같은 모양의 구조체를 만든다. 새 릴리스로 가려면 디코더 세 개를 다시 써야 한다.

### 4.3 패치 11개

| 패치 | 고치는 곳 | 고치기 전 증상 | 출처 |
|---|---|---|---|
| `01-asn1c-root-range` | 컴파일러 | `INTEGER (0..3, ..., 4 \| 5)` 의 비트 수를 0..5 로 계산한다. F1AP 의 SRB(RRC 메시지를 나르는 무선 통로) 번호 1·2·3 이 2·4·6 으로 읽힌다 | 포크 커밋 `03364659`(2026-07-14)의 해당 부분을 옮김 |
| `02-asn1c-enum-t-name-clash` | 컴파일러 | ENUMERATED 값 이름이 `t` 면 생성 C 가 컴파일되지 않는다(RRC 의 `CA-BandwidthClassNR-r17`. V18.8.0 부터 해당. 지금 문법 17.3.0 에는 없다) | 포크 커밋 `0695fe88`(2025-09-15) 그대로 |
| `03-skeleton-sequence-extension-leak` | 런타임 | 확장이 있는 SEQUENCE 를 풀다 입력이 모자라면 메모리를 해제하지 않고 실패로 돌아간다 | 포크 커밋 `350c48f1`(2026-06-12)에 같은 수정이 있다 |
| `04-skeleton-enum-unknown-tolerant` | 런타임 | APER 에서 문법이 모르는 ENUMERATED 확장값을 첫 번째 값으로 바꿔서 돌려준다 | 우리가 씀 |
| `05-skeleton-opentype-discard-checks` | 런타임 | 모르는 IE 를 버릴 때 길이가 음수이거나 남은 바이트보다 길어도 성공으로 처리한다 | 포크 커밋 `0ecf9c92`(2025-09-22) 그대로 |
| `06-skeleton-integer-shift` | 런타임 | 8옥텟 INTEGER 를 모을 때 부호 있는 정수를 왼쪽으로 민다. C 표준이 동작을 정하지 않은 연산이다 | 우리가 씀 |
| `07-skeleton-opentype-count-discarded` | 런타임 | APER 에서 모르는 IE 를 버려도 그 사실이 어디에도 남지 않는다 | 우리가 씀 |
| `08-skeleton-integer-range-align` | 런타임 | APER 에서 범위(상한 − 하한 + 1)가 129~255 인 INTEGER 를 틀리게 읽는다. 성공으로 끝나면서 값만 틀리거나, 뒤 필드가 밀려 PDU 전체가 실패한다 | 우리가 씀. 포크 HEAD 에도 같은 결함이 있다 |
| `09-asn1c-choice-version-brackets` | 컴파일러·파서 | CHOICE 의 `...` 뒤 `[[ ]]` 안에 있는 선택지를 묶음 하나로 취급한다. 그 선택지가 오면 디코드가 실패하거나 다른 선택지로 읽힌다 | 포크 커밋 `8baade52`(2024-09-26)의 소스 수정 그대로 |
| `10-asn1c-enum-alias-per-constraints` | 컴파일러 | ENUMERATED 에 다른 이름을 붙인 정의(`A ::= B`)의 PER 제약 표가 비어 생성된다. 그 타입이 오면 디코드가 실패한다 | 포크 커밋 `5f8f225b`(2025-09-12) 그대로 |
| `11-skeleton-choice-unknown-extension-alternative` | 런타임 | 확장 가능한 CHOICE 에 문법이 모르는 확장 선택지가 오면 순번을 읽지 않고 두 번째 루트 선택지로 푼다. NGAP-PDU 가 그 모양이라 조작된 PDU 가 성공 응답으로 읽힌다 | 우리가 씀. 포크 HEAD 에도 같은 결함이 있다 |
