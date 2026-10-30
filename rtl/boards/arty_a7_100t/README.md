# NEORV32 on Digilent Arty A7-100T (Bitmanip)

Board top and constraints for **Arty A7-100T** (XC7A100TCSG324-1) with **bootloader** and **bitmanip** (Zba, Zbb, Zbs) enabled.

- **Top:** `neorv32_arty_a7_100t_top.vhd` – port names match Digilent XDC (CLK100MHZ, btn, led, uart_*).
- **Constraints:** `arty_a7_100t_neorv32.xdc` – clock, reset (btn0), 4 LEDs, USB-UART.

See [docs/HUONG_DAN_ARTY_A7_100T_BITMANIP.md](../../docs/HUONG_DAN_ARTY_A7_100T_BITMANIP.md) for full build and deployment instructions (Vietnamese).
