library ieee;
use ieee.std_logic_1164.all;
library neorv32;
use neorv32.neorv32_package.all;

entity neorv32_arty_a7_100t_top is
  port (
    CLK100MHZ   : in  std_ulogic;
    btn         : in  std_ulogic_vector(3 downto 0);
    led         : out std_ulogic_vector(3 downto 0);
    uart_txd_in : in  std_ulogic;
    uart_rxd_out: out std_ulogic
  );
end entity;

architecture rtl of neorv32_arty_a7_100t_top is
  signal rstn      : std_ulogic;
  signal gpio_out  : std_ulogic_vector(7 downto 0);
begin
  rstn <= not btn(0);
  u_neorv32 : entity neorv32.neorv32_test_setup_bootloader_bitmanip
  generic map (
    CLOCK_FREQUENCY => 100000000,
    IMEM_SIZE       => 65536,
    DMEM_SIZE       => 8192
  )
  port map (
    clk_i       => CLK100MHZ,
    rstn_i      => rstn,
    gpio_o      => gpio_out,
    uart0_txd_o => uart_rxd_out,
    uart0_rxd_i => uart_txd_in
  );
  led <= gpio_out(3 downto 0);
end architecture;
