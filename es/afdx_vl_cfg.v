`timescale 1ns / 1ps
`default_nettype none
//-----------------------------------------------------------------------------
// afdx_vl_cfg.v - AFDX Virtual Link configuration tables + global registers
//
// N_TX_VL (up to 128) / N_RX_VL (up to 4096) entries kept in registers,
// RX lookup is a parallel VLID match (associative, returns entry index).
//
// TX VL entry (i = 0..N_TX_VL-1), cfg addr 0x1000 + i*4 + word:
//    word0 = {valid[31], bag[18:16], vlid[15:0]}
//    word1 = {src_port[31:16], dst_port[15:0]}
//    word2 = dst_ip[31:0]
// RX VL entry (i = 0..N_RX_VL-1), cfg addr 0x2000 + i*2 + word:
//    word0 = {valid[31], port_type[30], ic_dis[29], no_rm[28],
//             rsvd[27:22], rx_port[21:16], vlid[15:0]}
//    word1 = {police_enable[31], bag[30:28], max_payload[27:16], dst_port[15:0]}
// max_payload=0 retains the legacy 1471-byte payload ceiling.
//-----------------------------------------------------------------------------
module afdx_vl_cfg #(
    parameter N_TX_VL   = 16,
    parameter N_RX_VL   = 16,
    parameter N_RX_PORT = 8,
    parameter RX_IDX_WIDTH = (N_RX_VL > 1) ? $clog2(N_RX_VL) : 1
) (
    input  wire        clk,
    input  wire        rst,

    // config bus (word addressed)
    input  wire        cfg_wen,
    input  wire [19:0] cfg_addr,
    input  wire [31:0] cfg_wdata,

    // TX VL lookup by index (registered read)
    input  wire [6:0]  txvl_idx,
    output reg         txvl_valid,
    output reg  [15:0] txvl_vlid,
    output reg  [2:0]  txvl_bag,
    output reg  [15:0] txvl_src_port,
    output reg  [15:0] txvl_dst_port,
    output reg  [31:0] txvl_dst_ip,
    // Independent host-commit lookup; zero means the standard 1471-byte cap.
    input wire [6:0] tx_commit_idx,
    output wire [11:0] tx_commit_max_payload,

    // RX VL associative lookup by VLID (combinational)
    input  wire [15:0] rxvl_vlid,
    output reg         rxvl_valid,
    output reg         rxvl_type,
    output reg         rxvl_ic_dis,
    output reg         rxvl_no_rm,
    output reg  [5:0]  rxvl_port,
    output reg  [15:0] rxvl_dst_port,
    output reg         rxvl_police_enable,
    output reg  [2:0]  rxvl_bag,
    output reg  [11:0] rxvl_max_payload,
    output reg  [RX_IDX_WIDTH-1:0] rxvl_idx, // matched entry index

    // globals
    output reg  [47:0] src_mac,
    output reg  [31:0] src_ip,
    output reg  [7:0]  ip_ttl,
    output reg  [15:0] rm_skew_us,
    output reg         es_enable,
    output reg         tx_enable
);

// TX VL table storage
reg        tx_vl_valid_r [0:N_TX_VL-1];
reg [15:0] tx_vl_vlid_r  [0:N_TX_VL-1];
reg [2:0]  tx_vl_bag_r   [0:N_TX_VL-1];
reg [15:0] tx_vl_sport_r [0:N_TX_VL-1];
reg [15:0] tx_vl_dport_r [0:N_TX_VL-1];
reg [31:0] tx_vl_dip_r   [0:N_TX_VL-1];
reg [11:0] tx_vl_max_payload_r [0:N_TX_VL-1];
assign tx_commit_max_payload=(tx_commit_idx<N_TX_VL) ? tx_vl_max_payload_r[tx_commit_idx]:12'd0;

// RX VL table storage (N_RX_VL associative entries)
reg        rx_vl_valid_r [0:N_RX_VL-1];
reg        rx_vl_type_r  [0:N_RX_VL-1];
reg        rx_vl_icd_r   [0:N_RX_VL-1];
reg        rx_vl_norm_r  [0:N_RX_VL-1];
reg [5:0]  rx_vl_port_r  [0:N_RX_VL-1];
reg [15:0] rx_vl_vlid_r  [0:N_RX_VL-1];
reg [15:0] rx_vl_dport_r [0:N_RX_VL-1];
reg        rx_vl_police_r [0:N_RX_VL-1];
reg [2:0]  rx_vl_bag_r [0:N_RX_VL-1];
reg [11:0] rx_vl_max_payload_r [0:N_RX_VL-1];

integer i;

// config bus write decode
//   0x00000-0x00FFF : globals
//   0x01000-0x011FF : TX VL table (128 entries, idx*4 + word)
//   0x02000-0x03FFF : RX VL table (4096 entries, idx*2 + word)
// Decode the complete address before truncating its table index. Addresses
// beyond an implemented table are ignored rather than aliasing low entries.
wire [6:0]  txvl_widx  = cfg_addr[8:2];
wire [1:0]  txvl_wword = cfg_addr[1:0];
wire [11:0] rxvl_widx  = cfg_addr[12:1];
wire        rxvl_wword = cfg_addr[0];
wire cfg_is_txvl = (cfg_addr >= 20'h01000) &&
                    (cfg_addr < 20'h01200) && (txvl_widx < N_TX_VL);
wire cfg_is_rxvl = (cfg_addr >= 20'h02000) &&
                    (cfg_addr < 20'h04000) && (rxvl_widx < N_RX_VL);

always @(posedge clk) begin
    if (rst) begin
        for (i = 0; i < N_TX_VL; i = i + 1) begin
            tx_vl_valid_r[i] <= 1'b0;
            tx_vl_vlid_r[i]  <= 16'd0;
            tx_vl_bag_r[i]   <= 3'd0;
            tx_vl_sport_r[i] <= 16'd0;
            tx_vl_dport_r[i] <= 16'd0;
            tx_vl_dip_r[i]   <= 32'd0;
            tx_vl_max_payload_r[i] <= 12'd0;
        end
        for (i = 0; i < N_RX_VL; i = i + 1) begin
            rx_vl_valid_r[i] <= 1'b0;
            rx_vl_type_r[i]  <= 1'b0;
            rx_vl_icd_r[i]   <= 1'b0;
            rx_vl_norm_r[i]  <= 1'b0;
            rx_vl_port_r[i]  <= 6'd0;
            rx_vl_vlid_r[i]  <= 16'd0;
            rx_vl_dport_r[i] <= 16'd0;
            rx_vl_police_r[i] <= 1'b0;
            rx_vl_bag_r[i] <= 3'd0;
            rx_vl_max_payload_r[i] <= 12'd0;
        end
        src_mac    <= 48'h02_00_00_00_00_00;  // netID bits patched per-net
        src_ip     <= 32'h0A00_0001;
        ip_ttl     <= 8'd1;
        rm_skew_us <= 16'd1000;
        es_enable  <= 1'b1;
        tx_enable  <= 1'b1;
    end else if (cfg_wen) begin
        if (cfg_is_txvl) begin
            case (txvl_wword)
                2'd0: begin
                    tx_vl_valid_r[txvl_widx] <= cfg_wdata[31];
                    tx_vl_bag_r[txvl_widx]   <= cfg_wdata[18:16];
                    tx_vl_vlid_r[txvl_widx]  <= cfg_wdata[15:0];
                end
                2'd1: begin
                    tx_vl_sport_r[txvl_widx] <= cfg_wdata[31:16];
                    tx_vl_dport_r[txvl_widx] <= cfg_wdata[15:0];
                end
                2'd2: tx_vl_dip_r[txvl_widx] <= cfg_wdata;
                2'd3: tx_vl_max_payload_r[txvl_widx] <= cfg_wdata[11:0];
                default: ;
            endcase
        end else if (cfg_is_rxvl) begin
            if (rxvl_wword == 1'b0) begin
                rx_vl_valid_r[rxvl_widx] <= cfg_wdata[31];
                rx_vl_type_r[rxvl_widx]  <= cfg_wdata[30];
                rx_vl_icd_r[rxvl_widx]   <= cfg_wdata[29];
                rx_vl_norm_r[rxvl_widx]  <= cfg_wdata[28];
                rx_vl_port_r[rxvl_widx]  <= cfg_wdata[21:16];
                rx_vl_vlid_r[rxvl_widx]  <= cfg_wdata[15:0];
            end else begin
                rx_vl_dport_r[rxvl_widx] <= cfg_wdata[15:0];
                rx_vl_police_r[rxvl_widx] <= cfg_wdata[31];
                rx_vl_bag_r[rxvl_widx] <= cfg_wdata[30:28];
                rx_vl_max_payload_r[rxvl_widx] <= cfg_wdata[27:16];
            end
        end else begin
            case (cfg_addr)
                20'h00001: src_mac[31:0]  <= cfg_wdata;
                20'h00002: src_mac[47:32] <= cfg_wdata[15:0];
                20'h00003: src_ip         <= cfg_wdata;
                20'h00004: ip_ttl         <= cfg_wdata[7:0];
                20'h00005: rm_skew_us     <= cfg_wdata[15:0];
                20'h00006: begin
                    es_enable <= cfg_wdata[0];
                    tx_enable <= cfg_wdata[1];
                end
                default: ;
            endcase
        end
    end
end

// registered TX table read
always @(posedge clk) begin
    if (rst || txvl_idx >= N_TX_VL) begin
        txvl_valid    <= 1'b0;
        txvl_vlid     <= 16'd0;
        txvl_bag      <= 3'd0;
        txvl_src_port <= 16'd0;
        txvl_dst_port <= 16'd0;
        txvl_dst_ip   <= 32'd0;
    end else begin
        txvl_valid    <= tx_vl_valid_r[txvl_idx];
        txvl_vlid     <= tx_vl_vlid_r[txvl_idx];
        txvl_bag      <= tx_vl_bag_r[txvl_idx];
        txvl_src_port <= tx_vl_sport_r[txvl_idx];
        txvl_dst_port <= tx_vl_dport_r[txvl_idx];
        txvl_dst_ip   <= tx_vl_dip_r[txvl_idx];
    end
end

// RX VL associative lookup (parallel match over N_RX_VL entries)
integer m;
always @(*) begin
    rxvl_valid    = 1'b0;
    rxvl_type     = 1'b0;
    rxvl_ic_dis   = 1'b0;
    rxvl_no_rm    = 1'b0;
    rxvl_port     = 6'd0;
    rxvl_dst_port = 16'd0;
    rxvl_police_enable = 1'b0;
    rxvl_bag = 3'd0;
    rxvl_max_payload = 12'd0;
    rxvl_idx      = {RX_IDX_WIDTH{1'b0}};
    for (m = 0; m < N_RX_VL; m = m + 1) begin
        if (rx_vl_valid_r[m] && rx_vl_vlid_r[m] == rxvl_vlid && !rxvl_valid) begin
            rxvl_valid    = 1'b1;
            rxvl_type     = rx_vl_type_r[m];
            rxvl_ic_dis   = rx_vl_icd_r[m];
            rxvl_no_rm    = rx_vl_norm_r[m];
            rxvl_port     = rx_vl_port_r[m];
            rxvl_dst_port = rx_vl_dport_r[m];
            rxvl_police_enable = rx_vl_police_r[m];
            rxvl_bag = rx_vl_bag_r[m];
            rxvl_max_payload = rx_vl_max_payload_r[m];
            rxvl_idx      = m[RX_IDX_WIDTH-1:0];
        end
    end
end

endmodule
`default_nettype wire
