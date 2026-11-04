`timescale 1ns/1ps
`default_nettype none
module afdx_app_system #(
    parameter integer TICK_NS=8,
    parameter integer APP_MAX_BYTES=4096,
    parameter integer APP_RAM_DEPTH=8192,
    parameter integer OUTPUT_DEPTH=8192,
    parameter integer REASSEMBLY_TIMEOUT_US=1000000
) (
    input wire clk,input wire reset,
    input wire [7:0] s_data,input wire s_valid,output wire s_ready,
    output wire [7:0] m_data,output wire m_valid,input wire m_ready
);
wire [7:0] c_a_tx,c_b_tx,s_a_tx,s_b_tx;
wire c_a_en,c_b_en,c_a_er,c_b_er,s_a_en,s_b_en,s_a_er,s_b_er;
// Named link controls remain tied high/low in hardware.  Testbenches may
// force them to model a broken or corrupted external A/B path without
// disturbing the sender MAC's line-start feedback.
wire forward_a_enable=1'b1,forward_b_enable=1'b1;
wire forward_a_corrupt=1'b0,forward_b_corrupt=1'b0;
wire client_boot,server_boot,client_ready;
wire [7:0] client_rx_data,server_rx_data;
wire client_rx_valid,server_rx_valid,unused_server_ready;
wire client_rx_ready,server_rx_ready;
reg output_active,output_select_server;
wire idle_select_server=server_rx_valid;
wire selected_server=output_active?output_select_server:idle_select_server;
assign m_data=selected_server?server_rx_data:client_rx_data;
assign m_valid=selected_server?server_rx_valid:client_rx_valid;
assign server_rx_ready=m_ready&&selected_server;
assign client_rx_ready=m_ready&&!selected_server;
always @(posedge clk)begin
    if(reset)begin output_active<=0;output_select_server<=0;end
    else if(!output_active)begin
        if(server_rx_valid)begin output_active<=1;output_select_server<=1;end
        else if(client_rx_valid)begin output_active<=1;output_select_server<=0;end
    end else if((output_select_server&&!server_rx_valid)||(!output_select_server&&!client_rx_valid))
        output_active<=0;
end

assign s_ready=client_boot&&server_boot&&client_ready;
afdx_app_endpoint #(.TICK_NS(TICK_NS),.APP_MAX_BYTES(APP_MAX_BYTES),
    .APP_RAM_DEPTH(APP_RAM_DEPTH),.REASSEMBLY_TIMEOUT_US(REASSEMBLY_TIMEOUT_US),
    .LOCAL_IP(32'h0a000001),.PEER_IP(32'h0a000002),
    .ENABLE_SERVICES(0),.ENABLE_TIME_SYNC(1),.TIME_MASTER(0),
    .RTC_INITIAL_NS(32'd500000)) u_client (
    .clk(clk),.rst(reset),.app_tx_data(s_data),.app_tx_valid(s_valid&&server_boot),
    .app_tx_ready(client_ready),.app_rx_data(client_rx_data),.app_rx_valid(client_rx_valid),
    .app_rx_ready(client_rx_ready),
    .gmii_a_rxd(s_a_tx),.gmii_a_rx_dv(s_a_en),.gmii_a_rx_er(s_a_er),
    .gmii_a_txd(c_a_tx),.gmii_a_tx_en(c_a_en),.gmii_a_tx_er(c_a_er),
    .gmii_b_rxd(s_b_tx),.gmii_b_rx_dv(s_b_en),.gmii_b_rx_er(s_b_er),
    .gmii_b_txd(c_b_tx),.gmii_b_tx_en(c_b_en),.gmii_b_tx_er(c_b_er),.boot_done(client_boot));

afdx_app_endpoint #(.TICK_NS(TICK_NS),.APP_MAX_BYTES(APP_MAX_BYTES),
    .APP_RAM_DEPTH(APP_RAM_DEPTH),.REASSEMBLY_TIMEOUT_US(REASSEMBLY_TIMEOUT_US),
    .LOCAL_IP(32'h0a000002),.PEER_IP(32'h0a000001),
    .ENABLE_SERVICES(1),.ENABLE_TIME_SYNC(1),.TIME_MASTER(1),
    .RTC_INITIAL_NS(0)) u_server (
    .clk(clk),.rst(reset),.app_tx_data(8'd0),.app_tx_valid(1'b0),.app_tx_ready(unused_server_ready),
    .app_rx_data(server_rx_data),.app_rx_valid(server_rx_valid),.app_rx_ready(server_rx_ready),
    .gmii_a_rxd(c_a_tx),.gmii_a_rx_dv(c_a_en&&forward_a_enable),
    .gmii_a_rx_er(c_a_er||forward_a_corrupt),
    .gmii_a_txd(s_a_tx),.gmii_a_tx_en(s_a_en),.gmii_a_tx_er(s_a_er),
    .gmii_b_rxd(c_b_tx),.gmii_b_rx_dv(c_b_en&&forward_b_enable),
    .gmii_b_rx_er(c_b_er||forward_b_corrupt),
    .gmii_b_txd(s_b_tx),.gmii_b_tx_en(s_b_en),.gmii_b_tx_er(s_b_er),.boot_done(server_boot));
endmodule
`default_nettype wire
