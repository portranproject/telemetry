# asn1.mk — asn1c 빌드 결과물(build/gen/)을 정적 라이브러리 3개로 컴파일 
#   libasn1skel.a : asn1c 런타임 skeleton 
#   libf1ap.a     : F1AP_* 타입 (APER)
#   libnrrrc.a    : NR_* 타입 (UPER)
#   libngap.a     : NGAP_* 타입 (APER)
GEN ?= build/gen
OBJ ?= build/asn1
LIB ?= build
CC  ?= cc
# codec 매크로는 세 라이브러리 모두 동일해야 함.
#  skeleton 디스크립터 테이블 공유 -> 불일치 시 ODR 위반
ASN_CFLAGS ?= -O2 -g0 -w -DASN_DISABLE_BER_SUPPORT -DASN_DISABLE_OER_SUPPORT

F1AP_SRCS := $(wildcard $(GEN)/f1ap/F1AP_*.c)
RRC_SRCS  := $(wildcard $(GEN)/rrc/NR_*.c)
NGAP_SRCS := $(wildcard $(GEN)/ngap/NGAP_*.c)
SKEL_SRCS := $(wildcard $(GEN)/skel/*.c)

F1AP_OBJS := $(patsubst $(GEN)/f1ap/%.c,$(OBJ)/f1ap/%.o,$(F1AP_SRCS))
RRC_OBJS  := $(patsubst $(GEN)/rrc/%.c,$(OBJ)/rrc/%.o,$(RRC_SRCS))
NGAP_OBJS := $(patsubst $(GEN)/ngap/%.c,$(OBJ)/ngap/%.o,$(NGAP_SRCS))
SKEL_OBJS := $(patsubst $(GEN)/skel/%.c,$(OBJ)/skel/%.o,$(SKEL_SRCS)) $(OBJ)/skel/asn1_glue.o

all: $(LIB)/libasn1skel.a $(LIB)/libf1ap.a $(LIB)/libnrrrc.a $(LIB)/libngap.a

$(OBJ)/f1ap/%.o: $(GEN)/f1ap/%.c | $(OBJ)/f1ap
	@$(CC) $(ASN_CFLAGS) -I$(GEN)/f1ap -c $< -o $@
$(OBJ)/rrc/%.o: $(GEN)/rrc/%.c | $(OBJ)/rrc
	@$(CC) $(ASN_CFLAGS) -I$(GEN)/rrc -c $< -o $@
$(OBJ)/ngap/%.o: $(GEN)/ngap/%.c | $(OBJ)/ngap
	@$(CC) $(ASN_CFLAGS) -I$(GEN)/ngap -c $< -o $@
$(OBJ)/skel/%.o: $(GEN)/skel/%.c | $(OBJ)/skel
	@$(CC) $(ASN_CFLAGS) -I$(GEN)/skel -c $< -o $@
$(OBJ)/skel/asn1_glue.o: asn1/asn1_glue.c | $(OBJ)/skel
	@$(CC) $(ASN_CFLAGS) -c $< -o $@

$(OBJ)/f1ap $(OBJ)/rrc $(OBJ)/ngap $(OBJ)/skel:
	@mkdir -p $@

$(LIB)/libasn1skel.a: $(SKEL_OBJS)
	@rm -f $@ && ar rcs $@ $^ && echo "  AR  $@ ($(words $^) obj)"
$(LIB)/libf1ap.a: $(F1AP_OBJS)
	@rm -f $@ && ar rcs $@ $^ && echo "  AR  $@ ($(words $^) obj)"
$(LIB)/libnrrrc.a: $(RRC_OBJS)
	@rm -f $@ && ar rcs $@ $^ && echo "  AR  $@ ($(words $^) obj)"
$(LIB)/libngap.a: $(NGAP_OBJS)
	@rm -f $@ && ar rcs $@ $^ && echo "  AR  $@ ($(words $^) obj)"

.PHONY: all
