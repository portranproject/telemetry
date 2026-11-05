# asn1.mk — 3GPP 문법(asn1/ 의 .asn·.asn1 3개)에서 디코더 라이브러리 4개를 만들고 저장소 루트에서 실행.
#
#   make -f asn1/asn1.mk
#
#   1) asn1c 준비   고정 커밋을 받아 asn1/patches/ 를 적용하고 빌드
#   2) 문법 → C     문법 3개를 asn1c 에 전달
#   3) skeleton     세 디렉터리에 복사된 asn1c 런타임을 한곳으로 모음
#   4) C → .a       libf1ap.a(APER) libngap.a(APER) libnrrrc.a(UPER) libasn1skel.a(런타임)
#
# 요구 사항 : GNU make 4.0 이상, git, autoconf, automake, libtool, bison, flex, cc, patch, sha256sum.

ifneq ($(filter 3.%,$(MAKE_VERSION)),)
  $(error GNU make 4.0 이상이 필요하다(지금 $(MAKE_VERSION)))
endif
.DELETE_ON_ERROR:

BLD ?= build
CC  ?= cc
ASN_CFLAGS ?= -O2 -g0 -w -fPIC -DASN_DISABLE_BER_SUPPORT -DASN_DISABLE_OER_SUPPORT

GEN := $(BLD)/gen
OBJ := $(BLD)/asn1
LIB := $(BLD)

MAKEOVERRIDES :=

# ---- 1) asn1c ---------------------------------------------------------------------------------
# mouse07410/asn1c 는 원본 vlm/asn1c 에 APER(F1AP·NGAP 의 부호화 규칙)를 더한 fork. 원본에는 APER 지원 X
#
# 이 커밋은 OAI(cmake_targets/tools/build_helper)와 FlexRIC(Dockerfile)이 고정해 쓰는 것과 같음
# 바로 다음 커밋 5fa129cf 는 OCTET_STRING_aper.c 를 바꿔 F1·NG 디코드를 깸(OAI 설치 스크립트의 주석).
ASN1C_REPO    ?= https://github.com/mouse07410/asn1c
ASN1C_COMMIT  := 940dd5fa9f3917913fd487b13dfddfacd0ded06e
ASN1C_DIR     := $(BLD)/asn1c
ASN1C         := $(ASN1C_DIR)/bin/asn1c
ASN1C_STAMP   := $(ASN1C_DIR)/.installed
ASN1C_PATCHES := $(sort $(wildcard asn1/patches/*.patch))
ASN1C_TOOLS   := git autoreconf automake libtoolize bison flex patch sha256sum $(firstword $(CC))

# ---- 2) 문법 ----------------------------------------------------------------------------------
# F1AP 는 TS 38.473 V18.8.0, NGAP 은 TS 38.413 V15.8.0, RRC 는 TS 38.331 V17.3.0 . 
# asn1/SOURCES 참고
F1AP_GRAMMAR := asn1/f1ap-18.8.0.asn
NGAP_GRAMMAR := asn1/ngap-15.8.0.asn1
RRC_GRAMMAR  := asn1/nr-rrc-17.3.0.asn1
ASN1C_OPTS   := -gen-APER -gen-UPER -no-gen-BER -no-gen-JER -no-gen-OER -fcompound-names -no-gen-example -findirect-choice
ASN1C_SKEL   := -S $(ASN1C_DIR)/share/asn1c

.DEFAULT_GOAL := asn1
.PHONY: asn1 asn1c libs FORCE
FORCE:

define write_if_changed
@mkdir -p $(dir $(1)) && { $(2); } > $(1).new && { cmp -s $(1).new $(1) && rm -f $(1).new || mv $(1).new $(1); }
endef

asn1: $(GEN)/.skel.stamp
	@$(MAKE) --no-print-directory -f asn1/asn1.mk BLD=$(BLD) CC='$(CC)' ASN_CFLAGS='$(ASN_CFLAGS)' libs

asn1c: $(ASN1C_STAMP)

# asn1c 를 다시 만들 조건: 고정 커밋이 바뀜, 패치가 추가·삭제됨, 패치의 수정 내용이 바뀜.
$(ASN1C_DIR).sig: FORCE
	$(call write_if_changed,$@,echo '$(ASN1C_COMMIT)'; for patch_file in $(ASN1C_PATCHES); do printf '%s ' $$patch_file; grep -v '^#' $$patch_file | sha256sum; done)

$(ASN1C_STAMP): $(ASN1C_DIR).sig
	@for tool in $(ASN1C_TOOLS); do command -v $$tool >/dev/null 2>&1 || \
	    { echo "asn1c 빌드에 필요한 '$$tool' 이 없다. Ubuntu: apt-get install -y git build-essential autoconf automake libtool bison flex patch"; exit 1; }; done
	@test -n "$(ASN1C_PATCHES)" || { echo "asn1/patches/ 에 패치가 0개다"; exit 1; }
	rm -rf $(ASN1C_DIR) && mkdir -p $(ASN1C_DIR)/src
	git -C $(ASN1C_DIR)/src init -q
	git -C $(ASN1C_DIR)/src fetch -q --depth 1 $(ASN1C_REPO) $(ASN1C_COMMIT)
	git -C $(ASN1C_DIR)/src checkout -q FETCH_HEAD
	test "$$(git -C $(ASN1C_DIR)/src rev-parse HEAD)" = "$(ASN1C_COMMIT)"
	for patch_file in $(ASN1C_PATCHES); do \
	    patch -N -F0 --batch -s -d $(ASN1C_DIR)/src -p1 < $$patch_file || { echo "패치 실패: $$patch_file"; exit 1; }; done
	cd $(ASN1C_DIR)/src && { autoreconf -i && ./configure --prefix=$(abspath $(ASN1C_DIR)) && $(MAKE) && $(MAKE) install; } \
	    > ../build.log 2>&1 || { tail -20 ../build.log; exit 1; }
	test -x $(ASN1C) && test -f $(ASN1C_DIR)/share/asn1c/constr_SEQUENCE_aper.c
	touch $@

# 문법을 다시 변환할 조건: 문법 파일의 내용이나 생성 옵션이 바뀜, 또는 asn1c 가 다시 만들어짐.
$(GEN)/f1ap.sig: FORCE
	$(call write_if_changed,$@,sha256sum $(F1AP_GRAMMAR); echo 'F1AP_ $(ASN1C_OPTS)')
$(GEN)/ngap.sig: FORCE
	$(call write_if_changed,$@,sha256sum $(NGAP_GRAMMAR); echo 'NGAP_ $(ASN1C_OPTS)')
$(GEN)/rrc.sig: FORCE
	$(call write_if_changed,$@,sha256sum $(RRC_GRAMMAR); echo 'NR_ -pdu=all $(ASN1C_OPTS)')

# 생성이 중간에 끊겨도 "생성했다" 는 표시가 남지 않게 하기 위함.
$(GEN)/.f1ap.stamp: $(F1AP_GRAMMAR) $(GEN)/f1ap.sig $(ASN1C_STAMP)
	rm -f $@ && rm -rf $(GEN)/f1ap && mkdir -p $(GEN)/f1ap
	ASN1C_PREFIX=F1AP_ $(ASN1C) $(ASN1C_SKEL) $(ASN1C_OPTS) -fno-include-deps -D $(GEN)/f1ap $< > $(GEN)/f1ap.log 2>&1 || (tail -20 $(GEN)/f1ap.log; false)
	touch $@
$(GEN)/.ngap.stamp: $(NGAP_GRAMMAR) $(GEN)/ngap.sig $(ASN1C_STAMP)
	rm -f $@ && rm -rf $(GEN)/ngap && mkdir -p $(GEN)/ngap
	ASN1C_PREFIX=NGAP_ $(ASN1C) $(ASN1C_SKEL) $(ASN1C_OPTS) -fno-include-deps -D $(GEN)/ngap $< > $(GEN)/ngap.log 2>&1 || (tail -20 $(GEN)/ngap.log; false)
	touch $@
$(GEN)/.rrc.stamp: $(RRC_GRAMMAR) $(GEN)/rrc.sig $(ASN1C_STAMP)
	rm -f $@ && rm -rf $(GEN)/rrc && mkdir -p $(GEN)/rrc
	ASN1C_PREFIX=NR_ $(ASN1C) $(ASN1C_SKEL) -pdu=all $(ASN1C_OPTS) -D $(GEN)/rrc $< > $(GEN)/rrc.log 2>&1 || (tail -20 $(GEN)/rrc.log; false)
	touch $@

# ---- 3) skeleton ------------------------------------------------------------------------------
$(GEN)/.skel.stamp: $(GEN)/.f1ap.stamp $(GEN)/.ngap.stamp $(GEN)/.rrc.stamp
	rm -f $@ && rm -rf $(GEN)/skel && mkdir -p $(GEN)/skel
	for f in $(GEN)/f1ap/* $(GEN)/ngap/* $(GEN)/rrc/*; do b=$${f##*/}; case $$b in F1AP_*|NGAP_*|NR_*|Makefile*) ;; *) cp -f $$f $(GEN)/skel/ ;; esac; done
	touch $@

# ---- 4) 라이브러리 ----------------------------------------------------------------------------
F1AP_SRCS := $(wildcard $(GEN)/f1ap/F1AP_*.c)
NGAP_SRCS := $(wildcard $(GEN)/ngap/NGAP_*.c)
RRC_SRCS  := $(wildcard $(GEN)/rrc/NR_*.c)
SKEL_SRCS := $(wildcard $(GEN)/skel/*.c)

ifneq ($(filter libs,$(MAKECMDGOALS)),)
  ifeq ($(and $(F1AP_SRCS),$(NGAP_SRCS),$(RRC_SRCS),$(SKEL_SRCS)),)
    $(error $(GEN) 의 생성 소스가 비어 있다(f1ap $(words $(F1AP_SRCS)), ngap $(words $(NGAP_SRCS)), rrc $(words $(RRC_SRCS)), skel $(words $(SKEL_SRCS))) — `rm -f $(GEN)/.*.stamp` 뒤 다시 make asn1)
  endif
endif

F1AP_OBJS := $(patsubst $(GEN)/f1ap/%.c,$(OBJ)/f1ap/%.o,$(F1AP_SRCS))
NGAP_OBJS := $(patsubst $(GEN)/ngap/%.c,$(OBJ)/ngap/%.o,$(NGAP_SRCS))
RRC_OBJS  := $(patsubst $(GEN)/rrc/%.c,$(OBJ)/rrc/%.o,$(RRC_SRCS))
SKEL_OBJS := $(patsubst $(GEN)/skel/%.c,$(OBJ)/skel/%.o,$(SKEL_SRCS)) $(OBJ)/skel/asn1_glue.o

libs: $(LIB)/libasn1skel.a $(LIB)/libf1ap.a $(LIB)/libngap.a $(LIB)/libnrrrc.a

$(OBJ)/cflags.sig: FORCE
	$(call write_if_changed,$@,echo '$(CC) $(ASN_CFLAGS)')

$(OBJ)/f1ap/%.o: $(GEN)/f1ap/%.c $(OBJ)/cflags.sig | $(OBJ)/f1ap
	@$(CC) $(ASN_CFLAGS) -I$(GEN)/f1ap -c $< -o $@
$(OBJ)/ngap/%.o: $(GEN)/ngap/%.c $(OBJ)/cflags.sig | $(OBJ)/ngap
	@$(CC) $(ASN_CFLAGS) -I$(GEN)/ngap -c $< -o $@
$(OBJ)/rrc/%.o: $(GEN)/rrc/%.c $(OBJ)/cflags.sig | $(OBJ)/rrc
	@$(CC) $(ASN_CFLAGS) -I$(GEN)/rrc -c $< -o $@
$(OBJ)/skel/%.o: $(GEN)/skel/%.c $(OBJ)/cflags.sig | $(OBJ)/skel
	@$(CC) $(ASN_CFLAGS) -I$(GEN)/skel -c $< -o $@
# asn1_glue.c: 패치 04·07 이 올리는 계수기 2개의 정의
$(OBJ)/skel/asn1_glue.o: asn1/asn1_glue.c $(OBJ)/cflags.sig | $(OBJ)/skel
	@$(CC) $(ASN_CFLAGS) -c $< -o $@

$(OBJ)/f1ap $(OBJ)/ngap $(OBJ)/rrc $(OBJ)/skel:
	@mkdir -p $@

$(LIB)/libasn1skel.a: $(SKEL_OBJS)
	$(file >$@.objs,$^)
	@rm -f $@ && ar rcs $@ @$@.objs && rm -f $@.objs && echo "  AR  $@ ($(words $^) obj)"
$(LIB)/libf1ap.a: $(F1AP_OBJS)
	$(file >$@.objs,$^)
	@rm -f $@ && ar rcs $@ @$@.objs && rm -f $@.objs && echo "  AR  $@ ($(words $^) obj)"
$(LIB)/libngap.a: $(NGAP_OBJS)
	$(file >$@.objs,$^)
	@rm -f $@ && ar rcs $@ @$@.objs && rm -f $@.objs && echo "  AR  $@ ($(words $^) obj)"
$(LIB)/libnrrrc.a: $(RRC_OBJS)
	$(file >$@.objs,$^)
	@rm -f $@ && ar rcs $@ @$@.objs && rm -f $@.objs && echo "  AR  $@ ($(words $^) obj)"
