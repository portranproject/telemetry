#!/usr/bin/env bash
# check_readonly.sh [--xlated] <bpf.o> - 탭 BPF 가 패킷을 바꾸지 않는지 빌드 때 강제로 확인함.
#   배경: tcx egress 에서 bpf_skb_pull_data 가 SCTP GSO skb 를 깨뜨려 커널 패닉이 났음.
#
#   1단계(기본, 빌드 때, 권한 불필요): llvm-objdump 로 오브젝트를 풀어
#     (a) 부르는 헬퍼가 모두 허용 목록 안인지 (kfunc 와 서브프로그램 호출 call -N 도 거부)
#     (b) 모든 exit 바로 앞에서 r0 = -1 (TCX_NEXT) 인지. 판정에 끼어들지 않는 수동 탭인지
#     (c) 출력 형식이 바뀌어 아무것도 못 찾고 통과하는 일이 없게, bpf_skb_load_bytes 호출이 보여야 통과
#   2단계(--xlated, root, QEMU 게스트에서만): verifier 를 통과시킨 뒤 커널이 실제로 실행할 코드(xlated)의 호출을 검사.
#     소스에 없어도 verifier 가 끼워 넣는 헬퍼를 잡음 (예: tc 에서 패킷을 직접 쓰면 bpf_skb_pull_data 가 끼워짐)
#   3단계(SRC=<bpf.c> 지정 시): 소스에서 ctx(skb) 필드 쓰기를 찾음. 호출 검사로는 안 잡힘
#   허용 목록 밖이 하나라도 있으면 실패함. 새 헬퍼는 패킷과 skb 를 바꾸지 않는지 검토한 뒤 여기 추가
set -euo pipefail
MODE=objdump
[ "${1:-}" = "--xlated" ] && { MODE=xlated; shift; }
OBJECT_FILE="${1:?usage: $0 [--xlated] <bpf.o>}"

declare -A ALLOW=(              # 헬퍼 번호에서 이름으로 (모두 패킷을 읽기만 하거나 패킷과 무관)
  [1]=map_lookup_elem
  [8]=get_smp_processor_id
  [26]=skb_load_bytes
  [130]=ringbuf_output
  [208]=ktime_get_tai_ns
)
ALLOW_NAMES=" ${ALLOW[*]} "

name_of() { grep -oE "FN\([a-z0-9_]+, $1," /usr/include/linux/bpf.h 2>/dev/null | sed -E 's/FN\(([a-z0-9_]+),.*/\1/' || true; }
has_violation=0

if [ "$MODE" = objdump ]; then
  OBJDUMP="${LLVM_OBJDUMP:-$(command -v llvm-objdump || ls /usr/bin/llvm-objdump* 2>/dev/null | head -1)}"
  [ -x "$OBJDUMP" ] || { echo "check_readonly: llvm-objdump 없음 (apt install llvm)"; exit 1; }
  DISASSEMBLY=$("$OBJDUMP" -d --mcpu=v3 "$OBJECT_FILE")

  # (a) 헬퍼 허용 목록
  calls=$(grep -oE 'call (-?0x[0-9a-f]+|-?[0-9]+)$' <<< "$DISASSEMBLY" | awk '{print $2}' | sort -u || true)
  for call_operand in $calls; do
    case "$call_operand" in
      -*) echo "check_readonly: kfunc/서브프로그램 호출(call $call_operand) - 검토 필요 ($OBJECT_FILE)" >&2; has_violation=1; continue ;;
    esac
    helper_id=$(printf '%d' "$call_operand")
    [ -n "${ALLOW[$helper_id]:-}" ] && continue
    echo "check_readonly: 금지/미검토 헬퍼 호출 helper_id=$helper_id ($(name_of "$helper_id")) in $OBJECT_FILE" >&2
    has_violation=1
  done
  # (c) 형식이 바뀌어 아무 호출도 못 찾았다면 "검사한 척" 통과하지 않게
  grep -qx '0x1a' <<< "$calls" || { echo "check_readonly: bpf_skb_load_bytes(0x1a) 호출을 못 찾음 - objdump 출력 형식 확인 필요" >&2; has_violation=1; }

  # (b) 모든 exit 바로 앞 명령이 r0/w0 = -1 (TCX_NEXT) 인지
  exit_count=$(grep -cE '\bexit$' <<< "$DISASSEMBLY" || true)
  tcx_next_count=$(grep -B1 -E '\bexit$' <<< "$DISASSEMBLY" | grep -cE '\b[rw]0 = -0x1$' || true)
  if [ "$exit_count" -eq 0 ] || [ "$exit_count" -ne "$tcx_next_count" ]; then
    echo "check_readonly: exit $exit_count 개 중 $tcx_next_count 개만 r0 = -1(TCX_NEXT) - 탭이 패킷 판정에 끼어들 수 있음" >&2
    has_violation=1
  fi
else
  [ "$(id -u)" -eq 0 ] || { echo "check_readonly --xlated: root 필요"; exit 1; }
  grep -qw 'MYKERNEL_LAB=1' /proc/cmdline || { echo "check_readonly --xlated: QEMU 랩 게스트에서만 (BPF 를 커널에 올림)"; exit 1; }
  PIN_PATH=/sys/fs/bpf/cap_xlated_check_$$
  trap 'rm -rf "$PIN_PATH"' EXIT
  mkdir -p "$PIN_PATH"
  bpftool prog loadall "$OBJECT_FILE" "$PIN_PATH" >/dev/null   # verifier 통과 = 로드만 (어디에도 부착하지 않음)
  for pinned_prog in "$PIN_PATH"/*; do
    while read -r helper_function; do
      helper_name="${helper_function#bpf_}"
      case "$ALLOW_NAMES" in *" $helper_name "*) continue ;; esac
      case "$helper_name" in *map_lookup_elem) continue ;; esac   # 맵 종류별로 펼쳐진 조회 (예: percpu_array_map_lookup_elem)
      echo "check_readonly: xlated 에 허용목록 밖 호출 '$helper_function' (pinned_prog $(basename "$pinned_prog"))" >&2
      has_violation=1
    done < <(bpftool prog dump xlated pinned "$pinned_prog" | grep -oE 'call [a-zA-Z_][a-zA-Z0-9_]*' | awk '{print $2}' | sort -u)
  done
fi

# 3단계: ctx 필드 쓰기. skb->mark = x, skb->cb[0] |= x, ++skb->priority, ctx->x-- 같은 형태
if [ -n "${SRC:-}" ]; then
  WRITE_PATTERN='\b(skb|ctx)->[a-z_]+(\[[^]]*\])?'
  if grep -nE "$WRITE_PATTERN[[:space:]]*([-+*/%|&^]|<<|>>)?=[^=]|$WRITE_PATTERN[[:space:]]*(\+\+|--)|(\+\+|--)[[:space:]]*$WRITE_PATTERN" "$SRC" >&2; then
    echo "check_readonly: ctx 필드 쓰기 발견 ($SRC) - 수동 탭은 skb 와 ctx 를 바꾸지 않는다" >&2
    has_violation=1
  fi
fi

[ "$has_violation" -eq 0 ] && echo "check_readonly($MODE): OK - 읽기 전용 헬퍼만, 모든 exit 이 TCX_NEXT ($OBJECT_FILE)"
exit "$has_violation"
