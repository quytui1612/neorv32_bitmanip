# 64KB IMEM - ALL ciphers (B + crypto bitmanip, KHÔNG Zkne/Zknd)
MARCH = rv32imc_zba_zbb_zbs_zbkb_zbkc_zbkx_zicsr_zifencei
EFFORT = -O2
USER_FLAGS += -ggdb -gdwarf-3
USER_FLAGS += -Wl,--defsym,__neorv32_rom_size=64k
USER_FLAGS += -Wl,--defsym,__neorv32_ram_size=8k

APP_SRC += ./main.c
APP_INC += -I .

APP_SRC += ../../../tiny-AES-c/aes.c
APP_INC += -I ../../../tiny-AES-c
APP_SRC += ./aes_wp.c
APP_SRC += ./aes_bm.c
APP_SRC += ./aes_ttable.c
APP_SRC += ./mkv_wp.c
APP_SRC += ./mkv_ttable.c
APP_SRC += ./magma.c
APP_SRC += ./speck.c
APP_SRC += ./speck_fast.c
APP_SRC += ./speck128.c
APP_SRC += ./lea.c
APP_SRC += ./chacha.c
APP_SRC += ./present.c
APP_SRC += ./xcipher.c
APP_SRC += ./simon.c
APP_SRC += ./prince.c

NEORV32_HOME ?= ../../..
include $(NEORV32_HOME)/sw/common/common.mk
