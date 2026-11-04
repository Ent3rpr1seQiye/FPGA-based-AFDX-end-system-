`timescale 1ns/1ps
`default_nettype none
// Competition-facing application interface.
// One message is one continuous tx_valid interval. The first two accepted
// bytes are the big-endian 16-bit VLID; all following bytes are application
// data. Framing, A/B duplication, IC/RM, MAC and FCS are internal.
module AFDX_top #(
    parameter TICK_NS=8,
    parameter APP_MAX_BYTES=4096,
    parameter OUTPUT_DEPTH=8192,
    parameter REASSEMBLY_TIMEOUT_US=1000000
) (
    input  wire       clk,
    input  wire       reset,
    input  wire [7:0] tx_data,
    input  wire       tx_valid,
    output wire       tx_ready,
    output wire [7:0] rx_data,
    output wire       rx_valid,
    input  wire       rx_ready
);
initial begin
    if(APP_MAX_BYTES>4096)$error("APP_MAX_BYTES exceeds 4096");
    if(OUTPUT_DEPTH>8192)$error("OUTPUT_DEPTH exceeds 8192");
end
afdx_app_system #(
    .TICK_NS(TICK_NS),
    .APP_MAX_BYTES(APP_MAX_BYTES),
    .APP_RAM_DEPTH(8192),
    .OUTPUT_DEPTH(OUTPUT_DEPTH),
    .REASSEMBLY_TIMEOUT_US(REASSEMBLY_TIMEOUT_US)
) u_app_system (
    .clk(clk),.reset(reset),
    .s_data(tx_data),.s_valid(tx_valid),.s_ready(tx_ready),
    .m_data(rx_data),.m_valid(rx_valid),.m_ready(rx_ready)
);
endmodule
`default_nettype wire
