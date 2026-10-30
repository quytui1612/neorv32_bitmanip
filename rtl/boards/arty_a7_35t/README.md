# NEORV32 on Digilent Arty A7-35T (Bitmanip)

Board top and constraints for **Arty A7-35T** (XC7A35TCSG324-1) with **bootloader** and **bitmanip** (Zba, Zbb, Zbs) enabled.

## Files

| File | Description |
|------|-------------|
| `neorv32_arty_a7_35t_top.vhd` | Top entity – port names match Digilent XDC (CLK100MHZ, btn, led, uart_*) |
| `arty_a7_35t_neorv32.xdc` | Constraints – clock, reset (btn0), 4 LEDs, USB-UART |

## FPGA Target

- **Part:** XC7A35TCSG324-1
- **Package:** CSG324
- **Speed grade:** -1

## Pin Mapping

| Signal | Package Pin | Description |
|--------|-------------|-------------|
| CLK100MHZ | E3 | 100 MHz system clock |
| btn[0] | D9 | CPU RESET (active-high) |
| led[0] | H5 | GPIO output bit 0 |
| led[1] | J5 | GPIO output bit 1 |
| led[2] | T9 | GPIO output bit 2 |
| led[3] | T10 | GPIO output bit 3 |
| uart_rxd_out | D10 | FPGA TX → Host RX |
| uart_txd_in | A9 | FPGA RX ← Host TX |

## CPU Configuration

The setup uses `neorv32_test_setup_bootloader_bitmanip` with:

- **ISA:** rv32imc + Zba + Zbb + Zbs (RISC-V B extension)
- **Crypto:** Zbkb + Zbkc + Zbkx + Zkne + Zknd (AES hardware acceleration)
- **IMEM:** 16 KB
- **DMEM:** 8 KB
- **Boot mode:** UART Bootloader
- **Clock:** 100 MHz

## Quick Start

1. Open Vivado → Create Project → Select **XC7A35TCSG324-1**
2. Add all `.vhd` files from `rtl/core/` to library `neorv32`
3. Add `rtl/test_setups/neorv32_test_setup_bootloader_bitmanip.vhd` to library `neorv32`
4. Add `rtl/boards/arty_a7_35t/neorv32_arty_a7_35t_top.vhd` to library `work`
5. Add `rtl/boards/arty_a7_35t/arty_a7_35t_neorv32.xdc` as constraints
6. Set `neorv32_arty_a7_35t_top` as top entity
7. Run Synthesis → Implementation → Generate Bitstream

## Deployment

See [docs/HUONG_DAN_ARTY_A7_35T_BITMANIP.md](../../docs/HUONG_DAN_ARTY_A7_35T_BITMANIP.md) for full build and deployment instructions (Vietnamese).

## Differences from Arty A7-100T

| Feature | Arty A7-35T | Arty A7-100T |
|---------|-------------|--------------|
| FPGA Part | XC7A35TCSG324-1 | XC7A100TCSG324-1 |
| Logic Cells | 33,280 | 101,440 |
| DSP Slices | 90 | 240 |
| Block RAM | 180 KB | 4,860 KB |
| Pinout | Identical | Identical |
| Clock | 100 MHz | 100 MHz |

The RTL and constraints are **identical** between both boards. The only difference is the FPGA part selection in Vivado.
