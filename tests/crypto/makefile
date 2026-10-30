MARCH ?= rv32imc_zba_zbb_zbs_zbkb_zbkc_zbkx_zicsr_zifencei
EFFORT = -O2
USER_FLAGS += -DNEORV32_BOARD_KAT
USER_FLAGS += -Wl,--defsym,__neorv32_rom_size=64k
USER_FLAGS += -Wl,--defsym,__neorv32_ram_size=8k

APP_SRC += ./board_kat.c
APP_INC += -I ../../sw/example/hello_world -I ../../tiny-AES-c
APP_SRC += ../../tiny-AES-c/aes.c
APP_SRC += ../../sw/example/hello_world/aes_wp.c
APP_SRC += ../../sw/example/hello_world/aes_bm.c
APP_SRC += ../../sw/example/hello_world/aes_ttable.c
APP_SRC += ../../sw/example/hello_world/mkv_wp.c
APP_SRC += ../../sw/example/hello_world/mkv_ttable.c
APP_SRC += ../../sw/example/hello_world/chacha.c
APP_SRC += ../../sw/example/hello_world/magma.c
APP_SRC += ../../sw/example/hello_world/speck_fast.c
APP_SRC += ../../sw/example/hello_world/speck.c
APP_SRC += ../../sw/example/hello_world/speck128.c
APP_SRC += ../../sw/example/hello_world/lea.c
APP_SRC += ../../sw/example/hello_world/present.c
APP_SRC += ../../sw/example/hello_world/prince.c
APP_SRC += ../../sw/example/hello_world/simon.c

NEORV32_HOME ?= ../..
include $(NEORV32_HOME)/sw/common/common.mk
