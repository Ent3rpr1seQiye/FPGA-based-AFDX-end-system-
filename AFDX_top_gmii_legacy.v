`timescale 1ns / 1ps
`default_nettype none
//-----------------------------------------------------------------------------
// AFDX_top.v - competition-facing top level (亿海微2026选题接口)
//
// MODE=1 (default): configured end-system with real MAC/FCS RX and TX.
// MODE=2: same wire interface with SNMPv2c on VLID 1 / UDP 161.
// MODE=3: adds packet-based RTC synchronization on VLID 2 / UDP 55000.
// MODE=4: adds ARINC615A loading/unloading on VLID3 (TFTP UDP69 + TIDs).
// Management responses use configured manager IP/port (static AFDX route).
// Use 125MHz/8ns for gigabit byte operation; RX requires contiguous GMII
// frames (7x55,D5,dst..SN,FCS) and the output carries complete wire frames.
// MODE=0 compatibility: receives an AFDX frame on rx_* (dst MAC first byte,
// optional 0x55..D5 preamble tolerated), parses + integrity-checks it
// (dst MAC 03-00-00-00-VLID, IPv4/UDP, min-length pad, trailing SN), and
// forwards well-formed frames byte-for-byte on tx_*.
//
//   rx channel : byte accepted when rx_valid && tx_ready
//   tx channel : byte accepted when tx_valid && rx_ready
// The peer must hold rx_valid/rx_data while tx_ready is low. This is a
// MAC-side frame stream: optional preamble, but NO FCS. Not physical GMII.
//
// Frame boundaries are recovered from the IPv4 total-length field:
//   frame_len = 14 + ip_tot + pad + 1(SN),  pad = max(0, 45 - ip_tot)
//-----------------------------------------------------------------------------
module AFDX_top_gmii_legacy #(
    parameter MODE = 1,          // 0: raw; 1: echo; 2: SNMP; 3: SNMP + RTC sync
    parameter TICK_NS = 8,
    parameter N_TX_VL = 128,
    parameter N_RX_VL = 4096,
    parameter OUTPUT_DEPTH = 8192, // output FIFO byte entries; use 4096 or 8192
    parameter [31:0] SNMP_MANAGER_IP = 32'h0a000002,
    parameter [15:0] SNMP_MANAGER_PORT = 16'd40000,
    parameter TIME_MASTER=0, TIME_POLL_US=8000, TIME_TIMEOUT_US=4000,
    parameter TIME_HOLDOVER_US=32000, TIME_LOCK_THRESHOLD_NS=25000, TIME_LOCK_SAMPLES=3,
    parameter [31:0] TIME_LOCAL_IP=TIME_MASTER ? 32'h0a000002 : 32'h0a000001,
    parameter [31:0] TIME_PEER_IP=TIME_MASTER ? 32'h0a000001 : 32'h0a000002,
    parameter [31:0] TIME_NODE_ID=TIME_MASTER ? 32'd2 : 32'd1,
    parameter [31:0] TIME_INITIAL_SEC=0, TIME_INITIAL_NS=0,
    parameter RTC_RATE_PPB=0,
    parameter LOADER_IMAGE_BYTES=4096,LOADER_TIMEOUT_US=20000,LOADER_MAX_RETRIES=3,
    parameter TRAFFIC_GUARD=0,TRAFFIC_GAP_US=64,TRAFFIC_BURST=2,MAX_OUTPUT_STALL_US=8
) (
    input  wire       clk,        // 时钟信号
    input  wire       reset,      // 复位信号
    output wire [7:0] tx_data,    // 发送数据
    input  wire [7:0] rx_data,    // 接收数据
    output wire       tx_valid,   // 发送数据有效指示
    input  wire       rx_valid,   // 接收数据有效指示
    output wire       tx_ready,   // 发送数据准备好指示
    input  wire       rx_ready    // 接收数据准备好指示
);

// ------------------------------------------------------------------
// rx byte-stream -> AXIS frame adapter
// ------------------------------------------------------------------
localparam A_SYNC = 2'd0,   // skipping preamble / waiting frame start
           A_DATA = 2'd1,   // inside frame
           A_GAP  = 2'd2;   // frame ended, wait for next start

reg [1:0]  astate;
reg [11:0] bcnt;            // bytes consumed in current frame
reg [15:0] ip_tot_r;
reg [11:0] exp_len;
reg        len_ok;

// expected frame length once IP total length known
wire [15:0] incoming_ip_len = {ip_tot_r[15:8], rx_data};
wire [16:0] incoming_frame_len = (incoming_ip_len < 16'd45) ?
                                 17'd60 : 17'd15 + incoming_ip_len;

reg         s_tvalid;
reg  [7:0]  s_tdata;
reg         s_tlast;
wire        s_tready;
wire        p_wr_en, p_wr_commit, p_wr_abort, p_wr_blocked;
wire        pe_valid;

wire        buffer_can_start;
// At a frame boundary, let the final byte and commit/abort drain before
// reserving another slot. Once admitted, a frame owns its buffer slot.
wire        start_ready = buffer_can_start && !s_tvalid && !p_wr_en &&
                          !pe_valid && !p_wr_commit && !p_wr_abort;
wire        input_ready = !reset && ((astate == A_DATA) ?
                          (!s_tvalid || s_tready) : start_ready);
wire        rx_fire = (MODE == 0) && rx_valid && input_ready;

always @(posedge clk) begin
    if (reset) begin
        astate   <= A_SYNC;
        bcnt     <= 12'd0;
        ip_tot_r <= 16'd0;
        exp_len  <= 12'd0;
        len_ok   <= 1'b0;
        s_tvalid <= 1'b0;
        s_tdata  <= 8'd0;
        s_tlast  <= 1'b0;
    end else begin
        if (s_tvalid && s_tready)
            s_tvalid <= 1'b0;          // default: consumed
        if (rx_fire) begin
            case (astate)
                A_SYNC: begin
                    if (rx_data == 8'hD5)
                        astate <= A_SYNC;    // SFD: next byte is dst MAC
                    else if (rx_data == 8'h55)
                        astate <= A_SYNC;    // preamble byte
                    else begin
                        // first frame byte (dst MAC)
                        s_tvalid <= 1'b1;
                        s_tdata  <= rx_data;
                        s_tlast  <= 1'b0;
                        bcnt     <= 12'd1;
                        len_ok   <= 1'b0;
                        astate   <= A_DATA;
                    end
                end
                A_DATA: begin
                    s_tvalid <= 1'b1;
                    s_tdata  <= rx_data;
                    if (bcnt == 12'd16)
                        ip_tot_r[15:8] <= rx_data;
                    if (bcnt == 12'd17) begin
                        ip_tot_r[7:0] <= rx_data;
                        // Reject oversized input at the parser; cap consumption
                        // so invalid 16-bit lengths cannot wrap the 12-bit count.
                        exp_len <= (incoming_frame_len > 17'd1514) ?
                                   12'd1514 : incoming_frame_len[11:0];
                        len_ok <= 1'b1;
                    end
                    // exp_len valid from bcnt>=18; defensive hard cap
                    // keeps a garbage frame from wedging the adapter
                    if ((len_ok && bcnt == exp_len - 12'd1) ||
                        bcnt == 12'd1526) begin
                        s_tlast <= 1'b1;
                        astate  <= A_GAP;
                    end
                    bcnt <= bcnt + 12'd1;
                end
                A_GAP: begin
                    if (rx_data == 8'h55 || rx_data == 8'hD5)
                        astate <= A_GAP;
                    else begin
                        s_tvalid <= 1'b1;
                        s_tdata  <= rx_data;
                        s_tlast  <= 1'b0;
                        bcnt     <= 12'd1;
                        len_ok   <= 1'b0;
                        astate   <= A_DATA;
                    end
                end
                default: astate <= A_SYNC;
            endcase
        end
    end
end

// ------------------------------------------------------------------
// parse + stage + auto-accept
// ------------------------------------------------------------------
wire [7:0]  p_wr_data;
wire [11:0] p_wr_len;
wire        fb_tvalid, fb_tlast;
wire [7:0]  fb_tdata;
wire        fb_tready;

afdx_rx_parse #(.FULL_FRAME(1)) u_parse (
    .clk(clk), .rst(reset), .es_enable(1'b1),
    .s_axis_tdata(s_tdata), .s_axis_tvalid(s_tvalid),
    .s_axis_tready(s_tready), .s_axis_tlast(s_tlast),
    .s_axis_tuser(1'b0),
    .wr_en(p_wr_en), .wr_data(p_wr_data),
    .wr_commit(p_wr_commit), .wr_abort(p_wr_abort),
    .wr_len(p_wr_len), .wr_blocked(p_wr_blocked),
    .eval_valid(pe_valid), .eval_resp(pe_valid),   // respond immediately
    .eval_accept(1'b1),                             // forward accepted frames
    .eval_vlid(), .eval_dport(), .eval_sport(), .eval_src_ip(), .eval_sn(), .eval_plen(),
    .eval_ip_id(), .eval_frag_offset(), .eval_mf(), .eval_first(),
    .eval_udp_total_len(), .eval_udp_checksum(),
    .st_rx_frame(), .st_rx_drop_parse()
);

afdx_frame_buf #(.DEPTH(2048)) u_fbuf (
    .clk(clk), .rst(reset),
    .wr_en(p_wr_en), .wr_data(p_wr_data),
    .wr_full(), .wr_blocked(p_wr_blocked),
    .wr_commit(p_wr_commit), .wr_abort(p_wr_abort), .wr_len(p_wr_len),
    .frame_avail(), .frame_len(),
    .m_axis_tdata(fb_tdata), .m_axis_tvalid(fb_tvalid),
    .m_axis_tready(fb_tready), .m_axis_tlast(fb_tlast),
    .can_start(buffer_can_start)
);

// ------------------------------------------------------------------
// tx byte-stream output (store-and-forward)
//   bytes advance on tx_valid && rx_ready (partner ready to receive)
//   tx_ready = DUT can accept an rx byte this cycle
// ------------------------------------------------------------------
wire [7:0] endpoint_data;
wire endpoint_valid, endpoint_ready;
generate
if(MODE >= 1 && MODE <= 4) begin : g_endpoint
    afdx_es_stream #(.N_TX_VL(N_TX_VL), .N_RX_VL(N_RX_VL), .TICK_NS(TICK_NS),
        .ENABLE_SNMP(MODE>=2), .SNMP_MANAGER_IP(SNMP_MANAGER_IP),
        .SNMP_MANAGER_PORT(SNMP_MANAGER_PORT), .OUTPUT_DEPTH(OUTPUT_DEPTH),
        .ENABLE_TIME_SYNC(MODE>=3), .TIME_MASTER(TIME_MASTER), .TIME_POLL_US(TIME_POLL_US),
        .TIME_TIMEOUT_US(TIME_TIMEOUT_US), .TIME_HOLDOVER_US(TIME_HOLDOVER_US),
        .TIME_LOCK_THRESHOLD_NS(TIME_LOCK_THRESHOLD_NS), .TIME_LOCK_SAMPLES(TIME_LOCK_SAMPLES),
        .TIME_LOCAL_IP(TIME_LOCAL_IP), .TIME_PEER_IP(TIME_PEER_IP), .TIME_NODE_ID(TIME_NODE_ID),
        .TIME_INITIAL_SEC(TIME_INITIAL_SEC), .TIME_INITIAL_NS(TIME_INITIAL_NS),
        .RTC_RATE_PPB(RTC_RATE_PPB),.ENABLE_LOADER(MODE>=4),
        .LOADER_IMAGE_BYTES(LOADER_IMAGE_BYTES),.LOADER_TIMEOUT_US(LOADER_TIMEOUT_US),
        .LOADER_MAX_RETRIES(LOADER_MAX_RETRIES),
        .TRAFFIC_GUARD(TRAFFIC_GUARD),.TRAFFIC_GAP_US(TRAFFIC_GAP_US),
        .TRAFFIC_BURST(TRAFFIC_BURST),.MAX_OUTPUT_STALL_US(MAX_OUTPUT_STALL_US)) u_endpoint (
        .clk(clk), .reset(reset), .rx_data(rx_data), .rx_valid(rx_valid),
        .tx_data(endpoint_data), .tx_valid(endpoint_valid),
        .tx_ready(endpoint_ready), .rx_ready(rx_ready)
    );
end else begin : g_raw
    assign endpoint_data=8'd0;
    assign endpoint_valid=1'b0;
    assign endpoint_ready=1'b0;
end
endgenerate
assign tx_data   = (MODE != 0) ? endpoint_data : fb_tdata;
assign tx_valid  = (MODE != 0) ? endpoint_valid : fb_tvalid;
assign fb_tready = (MODE == 0) && rx_ready;
assign tx_ready  = (MODE != 0) ? endpoint_ready : input_ready;

endmodule
`default_nettype wire
