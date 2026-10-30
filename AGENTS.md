# AGENTS.md  — 프로젝트 개발 규칙

## 개발·실행 환경

### 역할 분담
- 로컬(macOS): 코드 작성만 한다. 로컬에서 빌드·실행하지 말 것.
- macOS에서 빌드되게 하려고 코드를 고치지 말 것(`#ifdef __APPLE__` 같은 우회 코드 금지). 이 코드는 Linux에서만 실행된다.
- CU EC2(Ubuntu): 빌드·실행·동작 확인은 여기서 한다. CU에서 통과해야 통과로 본다.

### 경로
- 프로젝트: 로컬 `telemetry/` → CU `~/telemetry/`
- EC2 제어판 폴더: 프로젝트 기준 `../p2/` (팀원은 자기 세트 폴더 `../pN/`)
- 아래 명령은 모두 프로젝트 루트(`telemetry/`)에서 실행한다.

### 주소
- CU 공인 IP(SSH 주소)는 create·start 할 때마다 바뀐다. 코드·스크립트·커밋에 적지 말고, 매번 `../p2/ctl.sh status`의 cu 행 `SSH_IP`로 확인할 것.
- 사설 IP(F1 주소)는 세트별로 고정: pN → CU `172.31.N.10`, DU `172.31.N.11` (p2: CU `172.31.2.10`, DU `172.31.2.11`). F1-C는 SCTP 포트 38472.

### 코드를 CU로 보내기 (rsync)
```bash
rsync -az --delete --exclude '.git' --exclude 'build' \
  -e "ssh -i ../p2/portran-key.pem -o UserKnownHostsFile=../p2/known_hosts -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10" \
  ./ ubuntu@<CU 공인 IP>:~/telemetry/
```
- git은 기록·공유용으로만 쓴다. CU로 코드를 옮길 때 git push/pull을 쓰지 말 것.

### CU에서 명령 실행 (SSH)
- `ctl.sh ssh cu`는 대화형 접속이라 쓰지 말고, 실행할 명령을 붙여서 쓸 것.
```bash
ssh -i ../p2/portran-key.pem -o UserKnownHostsFile=../p2/known_hosts -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
  ubuntu@<CU 공인 IP> 'cd ~/telemetry && <명령>'
```
- SSH가 연결되지 않으면 `../p2/ctl.sh allow-me`를 실행한 뒤 다시 시도할 것(내 공인 IP가 바뀐 경우).

### CU에서 sudo 사용
- sudo는 빌드·캡처·실행에 자유롭게 사용해도 된다.
- 단, sudo가 있어도 다음은 하지 말 것.
  - 스택 설정 파일 수정: `/root/OCUDU/configs/`, `/root/workspace/` 아래 파일 전부.
    예외: 사용자가 승인한 `ctl.sh fix-ip`.
  - 스택 프로세스(ocu, 5G 코어, RIC) 종료·재시작. 스택에 문제가 있으면 사용자에게 알리고 `ctl.sh up`을 제안할 것.
  - 패킷을 바꾸거나 막는 동작. eBPF 프로그램은 패킷을 수정하지 않는 읽기 전용 헬퍼만 쓸 것
    (패킷을 수정하는 헬퍼는 커널 패닉을 일으킬 수 있다). iptables·tc로 패킷을 차단·변경하지 말 것.
    캡처용으로 붙인 eBPF·tc는 작업이 끝나면 떼어 낼 것.
  - 패키지 설치(`apt install` 등)는 먼저 물어볼 것. 골든 AMI와 환경이 달라져 팀원 박스에서 재현되지 않는다.

### DU 박스 (읽기 전용)
- DU는 로그 확인(읽기)만 허용한다. 파일 수정, 프로그램 실행·종료, 코드 전송·빌드는 하지 말 것. sudo는 로그 읽기에만 쓸 것.
- 접속 방법은 CU와 같고, 주소만 `status`의 du 행 `SSH_IP`를 쓴다. CU와 DU의 IP를 헷갈리지 말 것.
- 예: F1 Setup 실패 원인은 DU의 `/tmp/odu.boot.log`로 확인한다.

### EC2 제어 (로컬 `../p2/ctl.sh`)
| 단계 | 명령 |
|---|---|
| 바로 실행해도 됨 | `status`, `allow-me` |
| 사용자에게 먼저 물어보고 실행 | `up`, `fix-ip` |
| 실행 금지 (필요하면 사용자에게 명령을 제안) | `create`, `start`, `stop`, `destroy` |

- 실행 금지 이유: 과금 시작·중지와 박스 영구 삭제는 사람이 결정한다. destroy의 확인 입력을 파이프 등으로 대신 넣는 것도 금지.
- CU·DU가 꺼져 있으면(status에서 running이 아니면) 사용자에게 start를 요청할 것.
- 스택은 `ctl.sh up`으로만 기동한다(CU → DU → UE 순서 자동). DU가 CU보다 먼저 뜨면 F1 Setup이 실패한다.

### 박스 안 ctl.sh (`/root/workspace/ctl.sh`)
- 로컬 제어판(`../p2/ctl.sh`)과 이름은 같지만 다른 스크립트다. 이 문서에서 경로 없이 `ctl.sh`라고 쓰면 로컬 제어판을 뜻한다.
  - CU의 것: CU 스택(코어 → RIC → ocu) 기동, DU EC2 켜기
  - DU의 것: odu와 UE 기동
- 허용: 로그 보기(`logs`)만. CU·DU 모두 가능하다. SSH 옵션은 "CU에서 명령 실행"과 같다.
  ```bash
  'timeout 20 sudo /root/workspace/ctl.sh logs ocu'
  ```
  로그를 계속 출력하는 방식이면 명령이 끝나지 않으므로 `timeout`을 붙인다.
- 그 외 명령은 실행하지 말 것. 스택 기동은 로컬 `ctl.sh up`으로만 한다.
  이유: 기동 순서가 꼬이면 F1 Setup이 실패하고 RIC가 죽으며, CU의 것은 DU EC2를 켜서 과금을 시작할 수 있다.

### 비밀 정보
- 제어판 폴더의 `credentials`, `portran-key.pem`은 열어 보거나 출력·복사하지 말 것. 키는 ssh·rsync의 `-i` 경로로만 사용한다.
- 제어판 폴더의 파일을 프로젝트 안으로 복사하거나 커밋하지 말 것.
- 키 내용, AWS 계정 정보, 공인 IP를 코드나 커밋에 넣지 말 것.

### 동작 확인
- CU에서 빌드하는 명령: (정해지면 추가)
- 동작했다고 판단하는 기준: (정해지면 추가)

## 코드 작성 규칙

> 적용 범위: 모든 새 코드에 적용할 것. 규칙이 바뀌어도 이미 작성된 코드를 일괄 수정하지 말 것(요청받은 경우 제외).
> 규칙이 충돌하면: 정확성 > 가독성 > 간결함.
> 코드 예시: 이 문서의 코드 예시는 작성 스타일을 보여 주기 위한 것이다. 예시가 있다는 이유로 함수·구조체·상수를 만들지 말고, 필요한지는 요구사항과 표준 문서(RFC·3GPP TS)를 근거로 판단할 것. 판단 결과가 예시와 같다면 그대로 써도 된다.

### 1. 직관적으로 작성 (과도한 추상화 금지)
- 한 곳에서만 쓰이는 래퍼·헬퍼 함수를 만들지 말 것. 같은 로직이 3번 이상 반복될 때만 함수로 분리.
- 매크로 트릭, 함수 포인터 테이블, 범용 프레임워크를 새로 만들지 말 것.

### 2. 이름 짓기
- 이름만 보고 의미를 알 수 있게 쓸 것. 과도한 줄임말 금지.
- 허용하는 줄임말
  - C 관용어: i, j, len, buf, ctx, ptr, idx, src, dst
  - 도메인 용어: TSN, SSN, PPID, vtag, UE, RRC, NAS, IE, assoc
- 예: ❌ `sa, da, sp, dp` → ✅ `src_addr, dst_addr, src_port, dst_port`
- 단위가 있는 값은 이름 끝에 단위를 붙일 것(_ns, _ms, _bytes, _count).
  - 예: ❌ `timeout` → ✅ `timeout_ns` / ❌ `size` → ✅ `size_bytes`

### 3. 함수 주석
다음 형식으로 쓸 것: `/* 함수명: 역할 ... */`
- 역할: 무엇을 하는가
- 이유: 왜 필요한가, 왜 이 방식인가
- 실패 시 반환값, 포인터 소유권(빌려 쓰는 포인터인지), 부작용(콜백 호출·통계 갱신)
- 3줄 이하의 단순 함수는 한 줄 설명으로 충분.

```c
/* tsn_check_duplicate: 받은 DATA 청크의 TSN을 처음 본 것인지 판정한다.
 *   이유: 수동 관측자는 재전송된 DATA도 그대로 보므로, 중복을 걸러야 같은 메시지를 상위로 두 번 올리지 않는다.
 *   반환: TSN_NEW / TSN_DUPLICATE / TSN_TOO_OLD(판정 창보다 오래되어 판정 불가).
 */
static enum tsn_result tsn_check_duplicate(struct sctp_direction *direction, uint32_t tsn)
```

### 4. 변수 주석
- 이유 필수: 전역·static 변수, 구조체 필드, `#define` 상수(특히 숫자), 상태 플래그.
- 지역 변수: 이름만으로 의도가 드러나지 않을 때만 주석.
- "무엇"보다 "왜"를 쓸 것.
  - ❌ `#define FRAGMENT_TIMEOUT_NS (5ull * 1000000000ull) // 5초`
  - ✅ `#define FRAGMENT_TIMEOUT_NS (5ull * 1000000000ull) // 5초. 유실된 조각을 무한정 기다리며 메모리를 잡지 않도록`

### 5. 정확성 우선 (clever 금지)
- 비트 트릭 남용, 여러 동작을 한 줄에 압축, 중첩 삼항 연산자 금지.
- 패킷 바이트는 공격자가 보낸 입력으로 간주. 읽기 전에 항상 길이를 검사할 것.
- malloc, parse 등 실패할 수 있는 호출의 반환값은 모두 검사.
- 정수 오버플로와 부호 변환에 주의. 타입 변환은 명시적 캐스트로.
- 판단할 수 없으면 추측하지 말고 "알 수 없음(UNKNOWN)" 상태로 처리(fail-closed).
- 성능 최적화는 측정 근거(벤치마크 결과)가 있을 때만.

### 6. 조건문 읽기 쉽게
- 오류·예외 조건은 함수 앞쪽에서 먼저 return (early return).
- 조건문(if·switch) 중첩은 최대 2단계. 반복문(for·while)은 세지 않고, else if 연결은 중첩으로 보지 않는다. 넘으면 early return(반복문 안에서는 continue·break)이나 bool 변수로 풀 것.
- 여러 조건이 섞인 복잡한 조건은 이름 있는 bool 변수로 뺄 것.
  ```c
  // ❌
  if (chunk_type == CHUNK_TYPE_DATA && (chunk_flags & DATA_FLAG_BEGIN) && !(chunk_flags & DATA_FLAG_END))
  // ✅
  bool is_first_fragment = chunk_type == CHUNK_TYPE_DATA
                        && (chunk_flags & DATA_FLAG_BEGIN)
                        && !(chunk_flags & DATA_FLAG_END);
  if (is_first_fragment)
  ```
- 부정의 부정을 피할 것. ❌ `if (!is_not_found)` → ✅ `if (is_found)`

### 7. 숫자 대신 이름 쓰기
- 프로토콜 숫자(PPID, 청크 타입, IE id, 메시지 타입)는 이름 있는 상수로 쓰고, 정의에 스펙 근거(RFC·3GPP TS 번호와 조항)를 주석으로 남길 것.
  ```c
  #define PPID_F1AP           62    // F1AP (3GPP TS 38.472)
  #define DATA_FLAG_UNORDERED 0x04  // SCTP DATA 청크 U 비트 (RFC 9260 §3.3.1)
  ```
  - 예: ❌ `if (ppid == 62)` → ✅ `if (ppid == PPID_F1AP)`
- 이미 정의된 상수가 있으면 새로 만들지 말고 그것을 쓸 것.
- 여러 상태를 돌려주는 함수는 1/0/-1 같은 숫자 대신 enum을 쓸 것. 호출하는 쪽의 `if (r == -1)`만 보고는 의미를 알 수 없기 때문.
  ```c
  enum tsn_result { TSN_NEW, TSN_DUPLICATE, TSN_TOO_OLD };
  ```

### 8. 변경 범위
- 요청받은 작업과 관련 없는 수정(포맷 정리, 이름 변경, 리팩터링)을 섞지 말 것.
- 근처 코드에서 고칠 점을 발견하면 직접 고치지 말고, 작업이 끝난 뒤 따로 알릴 것.

### 9. 함수 매개변수
- 매개변수는 5개 이하로 할 것. 넘으면 하나의 개념으로 묶을 수 있는지 검토.
- 묶을 때는 의미 있는 개념(해석한 청크, 완성된 메시지 등)으로 묶을 것.
  매개변수 수를 줄이려는 목적만으로 `xxx_args` 같은 구조체를 만들지 말 것.
- 구조체는 필드 이름을 지정해서 초기화(`.tsn = tsn`)할 것. 호출하는 쪽에서 각 값의 의미가 보이게 하기 위해서다.
- 같은 타입의 매개변수가 여러 개 이어지면 순서를 바꿔 넣어도 컴파일러가 잡지 못한다. 묶을 때 이 점도 고려할 것.

```c
// ❌ 0, 0, 1이 무엇인지 알 수 없고, 같은 타입 값의 순서가 바뀌어도 컴파일된다
deliver_message(ctx, record, 0, ppid, 0, 0, 1, payload, payload_len);

// ✅ 각 값의 의미가 보이고, 순서 실수가 생길 수 없다
struct sctp_message message = {
    .record         = record,
    .ppid           = ppid,
    .fragment_count = 1,
    .data           = payload,
    .len            = payload_len,
};
deliver_message(ctx, &message);
```
