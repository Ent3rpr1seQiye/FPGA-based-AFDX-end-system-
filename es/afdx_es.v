`timescale 1ns / 1ps
`default_nettype none
//-----------------------------------------------------------------------------
// afdx_es.v - AFDX End System (ARINC 664 Part 7), GMII interfaces
//
//   +------------------- AFDX End System -------------------+
//   | host TX ports -> tx_buf -> BAG scheduler -> tx_gen ----|--> MAC A (net A)
//   |                                                    |--> MAC B (net B)
//   | MAC A/B -> rx_parse -> frame_buf -> IC+RM -> rx_port ->|-> host RX ports
//   +-------------------------------------------------------+
//
// Single clock domain; at 12.5 MHz byte clock the link runs at 100 Mbps.
//-----------------------------------------------------------------------------
module afdx_es #(
    parameter N_TX_VL   = 16,
    parameter N_RX_VL   = 16,
    parameter N_RX_PORT = 8,
    parameter N_SLOTS   = 4,                 // TX frame pool slots
    parameter SLOT_BYTES = 2048,
    parameter N_RX_SLOT = 8,                 // RX shared pool slots
    parameter TICK_NS   = 80,                // clk period ns (12.5 MHz)
    parameter RTC_RATE_PPB = 0,
    parameter RX_ELASTIC_DEPTH = 4096
) (
    input  wire        clk,
    input  wire        rst,

    // GMII - network A
    input  wire [7:0]  gmii_a_rxd,
    input  wire        gmii_a_rx_dv,
    input  wire        gmii_a_rx_er,
    output wire [7:0]  gmii_a_txd,
    output wire        gmii_a_tx_en,
    output wire        gmii_a_tx_er,

    // GMII - network B
    input  wire [7:0]  gmii_b_rxd,
    input  wire        gmii_b_rx_dv,
    input  wire        gmii_b_rx_er,
    output wire [7:0]  gmii_b_txd,
    output wire        gmii_b_tx_en,
    output wire        gmii_b_tx_er,

    // host TX interface (AFDX queuing/sampling port writes)
    input  wire        host_tx_alloc_req,
    output wire [3:0]  host_tx_alloc_slot,
    output wire        host_tx_alloc_ack,
    output wire        host_tx_alloc_fail,
    input  wire        host_tx_wr_en,
    input  wire [14:0] host_tx_wr_addr,
    input  wire [7:0]  host_tx_wr_data,
    input  wire        host_tx_commit,
    input  wire [6:0]  host_tx_vl,
    input  wire [3:0]  host_tx_slot,
    input  wire [11:0] host_tx_len,
    input  wire [15:0] host_tx_ip_id,
    input  wire [12:0] host_tx_frag_offset,
    input  wire        host_tx_mf,
    input  wire        host_tx_first,
    input  wire [15:0] host_tx_udp_total_len,
    output wire        host_tx_commit_ready,

    // host RX interface
    input  wire [5:0]  host_rx_port,
    input  wire        host_rx_ready,
    output wire [7:0]  host_rx_tdata,
    output wire        host_rx_tvalid,
    output wire        host_rx_tlast,
    output wire        host_rx_avail,
    output wire [11:0] host_rx_flen,
    output wire [5:0]  host_rx_frame_port,
    output wire [15:0] host_rx_vlid,
    output wire [15:0] host_rx_ip_id,
    output wire [12:0] host_rx_frag_offset,
    output wire        host_rx_mf,
    output wire        host_rx_first,
    output wire [15:0] host_rx_udp_total_len,
    output wire [15:0] host_rx_udp_checksum,
    output wire [31:0] host_rx_src_ip,
    output wire [15:0] host_rx_src_port, host_rx_dst_port,

    // config bus (word addressed, write only for config; stats read mux)
    input  wire        cfg_wen,
    input  wire [19:0] cfg_addr,
    input  wire [31:0] cfg_wdata,
    input  wire [1:0]  cfg_rtc_op,
    input  wire        cfg_rtc_wen,
    output reg  [31:0] cfg_rdata,

    // RTC
    input  wire        rtc_adj_valid,
    input  wire        rtc_adj_sign,
    input  wire [31:0] rtc_adj_ns,
    input  wire        rtc_set_valid,
    input  wire [31:0] rtc_set_sec,
    input  wire [31:0] rtc_set_ns,
    output wire [31:0] rtc_sec,
    output wire [31:0] rtc_ns,
    output wire [31:0] tick_us,
    output wire        rtc_pps
);

// ------------------------------------------------------------------
// VL configuration + globals
// ------------------------------------------------------------------
wire [6:0]  txvl_idx;
wire        txvl_valid;
wire [15:0] txvl_vlid;
wire [2:0]  txvl_bag;
wire [15:0] txvl_src_port;
wire [15:0] txvl_dst_port;
wire [31:0] txvl_dst_ip;
wire [11:0] tx_commit_max_payload;
wire [15:0] rxvl_vlid;
wire        rxvl_valid;
wire        rxvl_type;
wire        rxvl_ic_dis;
wire        rxvl_no_rm;
wire [5:0]  rxvl_port;
wire [15:0] rxvl_dst_port;
wire rxvl_police_enable;
wire [2:0] rxvl_bag;
wire [11:0] rxvl_max_payload;
localparam RX_IDX_WIDTH = (N_RX_VL > 1) ? $clog2(N_RX_VL) : 1;
wire [RX_IDX_WIDTH-1:0] rxvl_idx;
wire [47:0] src_mac;
wire [31:0] src_ip;
wire [7:0]  ip_ttl;
wire [15:0] rm_skew_us;
wire        es_enable;
wire        tx_enable;

afdx_vl_cfg #(.N_TX_VL(N_TX_VL), .N_RX_VL(N_RX_VL),
              .N_RX_PORT(N_RX_PORT)) vl_cfg (
    .clk(clk), .rst(rst),
    .cfg_wen(cfg_wen), .cfg_addr(cfg_addr), .cfg_wdata(cfg_wdata),
    .txvl_idx(txvl_idx), .txvl_valid(txvl_valid), .txvl_vlid(txvl_vlid),
    .txvl_bag(txvl_bag), .txvl_src_port(txvl_src_port),
    .txvl_dst_port(txvl_dst_port), .txvl_dst_ip(txvl_dst_ip),
    .tx_commit_idx(host_tx_vl),.tx_commit_max_payload(tx_commit_max_payload),
    .rxvl_vlid(rxvl_vlid), .rxvl_valid(rxvl_valid), .rxvl_type(rxvl_type),
    .rxvl_ic_dis(rxvl_ic_dis), .rxvl_no_rm(rxvl_no_rm),
    .rxvl_port(rxvl_port), .rxvl_dst_port(rxvl_dst_port),
    .rxvl_police_enable(rxvl_police_enable), .rxvl_bag(rxvl_bag),
    .rxvl_max_payload(rxvl_max_payload),
    .rxvl_idx(rxvl_idx),
    .src_mac(src_mac), .src_ip(src_ip), .ip_ttl(ip_ttl),
    .rm_skew_us(rm_skew_us), .es_enable(es_enable), .tx_enable(tx_enable)
);

// ------------------------------------------------------------------
// TX path: buffer -> scheduler -> generator -> 2x MAC FIFO -> MACs
// ------------------------------------------------------------------
wire [N_TX_VL-1:0] vl_pending;
wire [6:0]  rd_vl;
wire        rd_pop;
wire [3:0]  rd_slot;
wire [11:0] rd_len;
wire [15:0] rd_ip_id,rd_udp_total_len;
wire [12:0] rd_frag_offset;
wire rd_mf,rd_first;
wire        rd_valid;
wire        free_valid;
wire [3:0]  free_slot;
wire [14:0] buf_rd_addr;
wire [7:0]  buf_rd_data;
wire        err_vl_overflow;

afdx_tx_buf #(.N_TX_VL(N_TX_VL), .N_SLOTS(N_SLOTS), .SLOT_BYTES(SLOT_BYTES))
tx_buf (
    .clk(clk), .rst(rst),
    .alloc_req(host_tx_alloc_req), .alloc_slot(host_tx_alloc_slot),
    .alloc_ack(host_tx_alloc_ack), .alloc_fail(host_tx_alloc_fail),
    .wr_en(host_tx_wr_en), .wr_addr(host_tx_wr_addr), .wr_data(host_tx_wr_data),
    .commit_valid(host_tx_commit), .commit_vl(host_tx_vl),
    .commit_slot(host_tx_slot), .commit_len(host_tx_len),
    .commit_max_payload(tx_commit_max_payload),
    .commit_ip_id(host_tx_ip_id),.commit_frag_offset(host_tx_frag_offset),
    .commit_mf(host_tx_mf),.commit_first(host_tx_first),
    .commit_udp_total_len(host_tx_udp_total_len),
    .commit_ready(host_tx_commit_ready),
    .vl_pending(vl_pending),
    .rd_vl(rd_vl), .rd_pop(rd_pop), .rd_slot(rd_slot), .rd_len(rd_len),
    .rd_ip_id(rd_ip_id),.rd_frag_offset(rd_frag_offset),
    .rd_mf(rd_mf),.rd_first(rd_first),.rd_udp_total_len(rd_udp_total_len),
    .rd_valid(rd_valid),
    .free_valid(free_valid), .free_slot(free_slot),
    .buf_rd_addr(buf_rd_addr), .buf_rd_data(buf_rd_data),
    .err_vl_overflow(err_vl_overflow)
);

wire        gen_req;
wire        gen_ack;
wire [6:0]  gen_vl_idx;
wire [3:0]  gen_slot;
wire [11:0] gen_len;
wire [15:0] gen_ip_id,gen_udp_total_len;
wire [12:0] gen_frag_offset;
wire gen_mf,gen_first;
wire [15:0] gen_vlid;
wire [15:0] gen_src_port;
wire [15:0] gen_dst_port;
wire [31:0] gen_dst_ip;
wire [31:0] now_tick;
// Frame tags follow the TX byte FIFOs to the actual MAC A line start.
// A/B are fed in lockstep and use identical clock/IFG settings.
reg [6:0] line_tags [0:63];
reg [5:0] line_tag_w, line_tag_r;
reg [6:0] line_tag_count;
reg mac_a_active_d;
wire mac_line_start = gmii_a_tx_en && !mac_a_active_d;
wire tag_push = gen_req && gen_ack;
wire tag_pop = mac_line_start && line_tag_count!=0;
always @(posedge clk) begin
    if(rst) begin line_tag_w<=0;line_tag_r<=0;line_tag_count<=0;mac_a_active_d<=0;end
    else begin
        mac_a_active_d<=gmii_a_tx_en;
        if(tag_push)begin line_tags[line_tag_w]<=gen_vl_idx;line_tag_w<=line_tag_w+1'b1;end
        if(tag_pop)line_tag_r<=line_tag_r+1'b1;
        case({tag_push,tag_pop})
            2'b10:line_tag_count<=line_tag_count+1'b1;
            2'b01:line_tag_count<=line_tag_count-1'b1;
            default:;
        endcase
    end
end

afdx_tx_sched #(.N_TX_VL(N_TX_VL), .TICK_NS(TICK_NS), .LINE_START_FEEDBACK(1)) tx_sched (
    .clk(clk), .rst(rst), .tx_enable(tx_enable),
    .vl_pending(vl_pending),
    .rd_vl(rd_vl), .rd_pop(rd_pop), .rd_slot(rd_slot), .rd_len(rd_len),
    .rd_ip_id(rd_ip_id),.rd_frag_offset(rd_frag_offset),
    .rd_mf(rd_mf),.rd_first(rd_first),.rd_udp_total_len(rd_udp_total_len),
    .rd_valid(rd_valid),
    .txvl_idx(txvl_idx), .txvl_valid(txvl_valid), .txvl_vlid(txvl_vlid),
    .txvl_bag(txvl_bag), .txvl_src_port(txvl_src_port),
    .txvl_dst_port(txvl_dst_port), .txvl_dst_ip(txvl_dst_ip),
    .gen_req(gen_req), .gen_ack(gen_ack),
    .gen_vl_idx(gen_vl_idx), .gen_slot(gen_slot), .gen_len(gen_len),
    .gen_ip_id(gen_ip_id),.gen_frag_offset(gen_frag_offset),
    .gen_mf(gen_mf),.gen_first(gen_first),.gen_udp_total_len(gen_udp_total_len),
    .gen_vlid(gen_vlid), .gen_src_port(gen_src_port),
    .gen_dst_port(gen_dst_port), .gen_dst_ip(gen_dst_ip),
    .now_tick(now_tick), .line_start_valid(tag_pop), .line_start_vl(line_tags[line_tag_r])
);

wire [7:0] gen_tdata;
wire       gen_tvalid;
wire       gen_tready;
wire       gen_tlast;
wire       tx_frame_stb;

afdx_tx_gen #(.N_TX_VL(N_TX_VL)) tx_gen (
    .clk(clk), .rst(rst),
    .gen_req(gen_req), .gen_ack(gen_ack),
    .gen_vl_idx(gen_vl_idx), .gen_slot(gen_slot), .gen_len(gen_len),
    .gen_ip_id(gen_ip_id),.gen_frag_offset(gen_frag_offset),
    .gen_mf(gen_mf),.gen_first(gen_first),.gen_udp_total_len(gen_udp_total_len),
    .gen_vlid(gen_vlid), .gen_src_port(gen_src_port),
    .gen_dst_port(gen_dst_port), .gen_dst_ip(gen_dst_ip),
    .src_mac(src_mac), .src_ip(src_ip), .ip_ttl(ip_ttl),
    .buf_rd_addr(buf_rd_addr), .buf_rd_data(buf_rd_data),
    .m_axis_tdata(gen_tdata), .m_axis_tvalid(gen_tvalid),
    .m_axis_tready(gen_tready), .m_axis_tlast(gen_tlast),
    .free_valid(free_valid), .free_slot(free_slot),
    .tx_frame_stb(tx_frame_stb)
);

// duplicate the frame into both network FIFOs (lock-step).
// ARINC 664: last src-MAC byte = {netID[2:0], 5'b00000}, A=001, B=010.
// Byte index 11 of the frame is patched per network.
wire       fifo_a_tready, fifo_b_tready;
assign gen_tready = fifo_a_tready && fifo_b_tready;
wire gen_fire = gen_tvalid && gen_tready;

reg [11:0] gb_idx;
always @(posedge clk) begin
    if (rst)
        gb_idx <= 12'd0;
    else if (gen_fire)
        gb_idx <= gen_tlast ? 12'd0 : gb_idx + 12'd1;
end

wire [7:0] gen_tdata_a = (gb_idx == 12'd11) ? {3'b001, gen_tdata[4:0]}
                                            : gen_tdata;
wire [7:0] gen_tdata_b = (gb_idx == 12'd11) ? {3'b010, gen_tdata[4:0]}
                                            : gen_tdata;

wire [7:0] fefa_tdata, fefb_tdata;
wire       fefa_tvalid, fefb_tvalid, fefa_tlast, fefb_tlast;
wire       fefa_tready, fefb_tready;

axis_fifo #(.DEPTH(2048), .DATA_WIDTH(8), .KEEP_ENABLE(0),
            .USER_ENABLE(0), .FRAME_FIFO(0)) tx_fifo_a (
    .clk(clk), .rst(rst),
    .s_axis_tdata(gen_tdata_a), .s_axis_tkeep(1'b1),
    .s_axis_tvalid(gen_fire), .s_axis_tready(fifo_a_tready),
    .s_axis_tlast(gen_tlast), .s_axis_tid(8'd0), .s_axis_tdest(8'd0),
    .s_axis_tuser(1'b0),
    .m_axis_tdata(fefa_tdata), .m_axis_tkeep(),
    .m_axis_tvalid(fefa_tvalid), .m_axis_tready(fefa_tready),
    .m_axis_tlast(fefa_tlast), .m_axis_tid(), .m_axis_tdest(),
    .m_axis_tuser(),
    .pause_req(1'b0), .pause_ack(),
    .status_depth(), .status_depth_commit(),
    .status_overflow(), .status_bad_frame(), .status_good_frame()
);

axis_fifo #(.DEPTH(2048), .DATA_WIDTH(8), .KEEP_ENABLE(0),
            .USER_ENABLE(0), .FRAME_FIFO(0)) tx_fifo_b (
    .clk(clk), .rst(rst),
    .s_axis_tdata(gen_tdata_b), .s_axis_tkeep(1'b1),
    .s_axis_tvalid(gen_fire), .s_axis_tready(fifo_b_tready),
    .s_axis_tlast(gen_tlast), .s_axis_tid(8'd0), .s_axis_tdest(8'd0),
    .s_axis_tuser(1'b0),
    .m_axis_tdata(fefb_tdata), .m_axis_tkeep(),
    .m_axis_tvalid(fefb_tvalid), .m_axis_tready(fefb_tready),
    .m_axis_tlast(fefb_tlast), .m_axis_tid(), .m_axis_tdest(),
    .m_axis_tuser(),
    .pause_req(1'b0), .pause_ack(),
    .status_depth(), .status_depth_commit(),
    .status_overflow(), .status_bad_frame(), .status_good_frame()
);

// ------------------------------------------------------------------
// MACs
// ------------------------------------------------------------------
wire [7:0] maca_rx_tdata;
wire       maca_rx_tvalid, maca_rx_tlast, maca_rx_tuser;
wire [7:0] macb_rx_tdata;
wire       macb_rx_tvalid, macb_rx_tlast, macb_rx_tuser;
wire       maca_rx_badfcs, macb_rx_badfcs;

eth_mac_1g #(
    .DATA_WIDTH(8), .ENABLE_PADDING(1), .MIN_FRAME_LENGTH(64),
    .PTP_TS_ENABLE(0), .PFC_ENABLE(0), .PAUSE_ENABLE(0)
) mac_a (
    .rx_clk(clk), .rx_rst(rst), .tx_clk(clk), .tx_rst(rst),
    .tx_axis_tdata(fefa_tdata), .tx_axis_tvalid(fefa_tvalid),
    .tx_axis_tready(fefa_tready), .tx_axis_tlast(fefa_tlast),
    .tx_axis_tuser(1'b0),
    .rx_axis_tdata(maca_rx_tdata), .rx_axis_tvalid(maca_rx_tvalid),
    .rx_axis_tlast(maca_rx_tlast), .rx_axis_tuser(maca_rx_tuser),
    .gmii_rxd(gmii_a_rxd), .gmii_rx_dv(gmii_a_rx_dv),
    .gmii_rx_er(gmii_a_rx_er),
    .gmii_txd(gmii_a_txd), .gmii_tx_en(gmii_a_tx_en),
    .gmii_tx_er(gmii_a_tx_er),
    .tx_ptp_ts(96'd0), .rx_ptp_ts(96'd0),
    .tx_axis_ptp_ts(), .tx_axis_ptp_ts_tag(), .tx_axis_ptp_ts_valid(),
    .tx_lfc_req(1'b0), .tx_lfc_resend(1'b0), .rx_lfc_en(1'b0),
    .rx_lfc_req(), .rx_lfc_ack(),
    .tx_pfc_req(8'd0), .tx_pfc_resend(1'b0), .rx_pfc_en(8'd0),
    .rx_pfc_req(), .rx_pfc_ack(),
    .tx_lfc_pause_en(1'b0), .tx_pause_req(1'b0), .tx_pause_ack(),
    .rx_clk_enable(1'b1), .tx_clk_enable(1'b1),
    .rx_mii_select(1'b0), .tx_mii_select(1'b0),
    .tx_start_packet(), .tx_error_underflow(),
    .rx_start_packet(), .rx_error_bad_frame(), .rx_error_bad_fcs(maca_rx_badfcs),
    .stat_tx_mcf(), .stat_rx_mcf(), .stat_tx_lfc_pkt(),
    .stat_tx_lfc_xon(), .stat_tx_lfc_xoff(), .stat_tx_lfc_paused(),
    .stat_tx_pfc_pkt(), .stat_tx_pfc_xon(), .stat_tx_pfc_xoff(),
    .stat_tx_pfc_paused(), .stat_rx_lfc_pkt(), .stat_rx_lfc_xon(),
    .stat_rx_lfc_xoff(), .stat_rx_lfc_paused(), .stat_rx_pfc_pkt(),
    .stat_rx_pfc_xon(), .stat_rx_pfc_xoff(), .stat_rx_pfc_paused(),
    .cfg_ifg(8'd12), .cfg_tx_enable(1'b1), .cfg_rx_enable(1'b1),
    .cfg_mcf_rx_eth_dst_mcast(48'd0), .cfg_mcf_rx_check_eth_dst_mcast(1'b0),
    .cfg_mcf_rx_eth_dst_ucast(48'd0), .cfg_mcf_rx_check_eth_dst_ucast(1'b0),
    .cfg_mcf_rx_eth_src(48'd0), .cfg_mcf_rx_check_eth_src(1'b0),
    .cfg_mcf_rx_eth_type(16'd0), .cfg_mcf_rx_opcode_lfc(16'd0),
    .cfg_mcf_rx_check_opcode_lfc(1'b0), .cfg_mcf_rx_opcode_pfc(16'd0),
    .cfg_mcf_rx_check_opcode_pfc(1'b0), .cfg_mcf_rx_forward(1'b0),
    .cfg_mcf_rx_enable(1'b0),
    .cfg_tx_lfc_eth_dst(48'd0), .cfg_tx_lfc_eth_src(48'd0),
    .cfg_tx_lfc_eth_type(16'd0), .cfg_tx_lfc_opcode(16'd0),
    .cfg_tx_lfc_en(1'b0), .cfg_tx_lfc_quanta(16'd0),
    .cfg_tx_lfc_refresh(16'd0), .cfg_tx_pfc_eth_dst(48'd0),
    .cfg_tx_pfc_eth_src(48'd0), .cfg_tx_pfc_eth_type(16'd0),
    .cfg_tx_pfc_opcode(16'd0), .cfg_tx_pfc_en(1'b0),
    .cfg_tx_pfc_quanta(128'd0), .cfg_tx_pfc_refresh(128'd0),
    .cfg_rx_lfc_opcode(16'd0), .cfg_rx_lfc_en(1'b0),
    .cfg_rx_pfc_opcode(16'd0), .cfg_rx_pfc_en(1'b0)
);

eth_mac_1g #(
    .DATA_WIDTH(8), .ENABLE_PADDING(1), .MIN_FRAME_LENGTH(64),
    .PTP_TS_ENABLE(0), .PFC_ENABLE(0), .PAUSE_ENABLE(0)
) mac_b (
    .rx_clk(clk), .rx_rst(rst), .tx_clk(clk), .tx_rst(rst),
    .tx_axis_tdata(fefb_tdata), .tx_axis_tvalid(fefb_tvalid),
    .tx_axis_tready(fefb_tready), .tx_axis_tlast(fefb_tlast),
    .tx_axis_tuser(1'b0),
    .rx_axis_tdata(macb_rx_tdata), .rx_axis_tvalid(macb_rx_tvalid),
    .rx_axis_tlast(macb_rx_tlast), .rx_axis_tuser(macb_rx_tuser),
    .gmii_rxd(gmii_b_rxd), .gmii_rx_dv(gmii_b_rx_dv),
    .gmii_rx_er(gmii_b_rx_er),
    .gmii_txd(gmii_b_txd), .gmii_tx_en(gmii_b_tx_en),
    .gmii_tx_er(gmii_b_tx_er),
    .tx_ptp_ts(96'd0), .rx_ptp_ts(96'd0),
    .tx_axis_ptp_ts(), .tx_axis_ptp_ts_tag(), .tx_axis_ptp_ts_valid(),
    .tx_lfc_req(1'b0), .tx_lfc_resend(1'b0), .rx_lfc_en(1'b0),
    .rx_lfc_req(), .rx_lfc_ack(),
    .tx_pfc_req(8'd0), .tx_pfc_resend(1'b0), .rx_pfc_en(8'd0),
    .rx_pfc_req(), .rx_pfc_ack(),
    .tx_lfc_pause_en(1'b0), .tx_pause_req(1'b0), .tx_pause_ack(),
    .rx_clk_enable(1'b1), .tx_clk_enable(1'b1),
    .rx_mii_select(1'b0), .tx_mii_select(1'b0),
    .tx_start_packet(), .tx_error_underflow(),
    .rx_start_packet(), .rx_error_bad_frame(), .rx_error_bad_fcs(macb_rx_badfcs),
    .stat_tx_mcf(), .stat_rx_mcf(), .stat_tx_lfc_pkt(),
    .stat_tx_lfc_xon(), .stat_tx_lfc_xoff(), .stat_tx_lfc_paused(),
    .stat_tx_pfc_pkt(), .stat_tx_pfc_xon(), .stat_tx_pfc_xoff(),
    .stat_tx_pfc_paused(), .stat_rx_lfc_pkt(), .stat_rx_lfc_xon(),
    .stat_rx_lfc_xoff(), .stat_rx_lfc_paused(), .stat_rx_pfc_pkt(),
    .stat_rx_pfc_xon(), .stat_rx_pfc_xoff(), .stat_rx_pfc_paused(),
    .cfg_ifg(8'd12), .cfg_tx_enable(1'b1), .cfg_rx_enable(1'b1),
    .cfg_mcf_rx_eth_dst_mcast(48'd0), .cfg_mcf_rx_check_eth_dst_mcast(1'b0),
    .cfg_mcf_rx_eth_dst_ucast(48'd0), .cfg_mcf_rx_check_eth_dst_ucast(1'b0),
    .cfg_mcf_rx_eth_src(48'd0), .cfg_mcf_rx_check_eth_src(1'b0),
    .cfg_mcf_rx_eth_type(16'd0), .cfg_mcf_rx_opcode_lfc(16'd0),
    .cfg_mcf_rx_check_opcode_lfc(1'b0), .cfg_mcf_rx_opcode_pfc(16'd0),
    .cfg_mcf_rx_check_opcode_pfc(1'b0), .cfg_mcf_rx_forward(1'b0),
    .cfg_mcf_rx_enable(1'b0),
    .cfg_tx_lfc_eth_dst(48'd0), .cfg_tx_lfc_eth_src(48'd0),
    .cfg_tx_lfc_eth_type(16'd0), .cfg_tx_lfc_opcode(16'd0),
    .cfg_tx_lfc_en(1'b0), .cfg_tx_lfc_quanta(16'd0),
    .cfg_tx_lfc_refresh(16'd0), .cfg_tx_pfc_eth_dst(48'd0),
    .cfg_tx_pfc_eth_src(48'd0), .cfg_tx_pfc_eth_type(16'd0),
    .cfg_tx_pfc_opcode(16'd0), .cfg_tx_pfc_en(1'b0),
    .cfg_tx_pfc_quanta(128'd0), .cfg_tx_pfc_refresh(128'd0),
    .cfg_rx_lfc_opcode(16'd0), .cfg_rx_lfc_en(1'b0),
    .cfg_rx_pfc_opcode(16'd0), .cfg_rx_pfc_en(1'b0)
);

// ------------------------------------------------------------------
// RX path: parsers + staging buffers + IC/RM + ports
// ------------------------------------------------------------------
wire        pa_wr_en, pb_wr_en;
wire [7:0]  pa_wr_data, pb_wr_data;
wire        pa_wr_commit, pb_wr_commit;
wire        pa_wr_abort, pb_wr_abort;
wire [11:0] pa_wr_len, pb_wr_len;
wire        pa_eval_valid, pb_eval_valid;
wire        pa_eval_resp, pb_eval_resp;
wire        pa_eval_accept, pb_eval_accept;
wire [15:0] pa_eval_vlid, pb_eval_vlid;
wire [15:0] pa_eval_dport, pb_eval_dport;
wire [15:0] pa_eval_sport, pb_eval_sport;
wire [31:0] pa_eval_src_ip, pb_eval_src_ip;
wire [7:0]  pa_eval_sn, pb_eval_sn;
wire [11:0] pa_eval_plen, pb_eval_plen;
wire [15:0] pa_eval_ip_id, pb_eval_ip_id;
wire [12:0] pa_eval_frag_offset, pb_eval_frag_offset;
wire        pa_eval_mf, pb_eval_mf, pa_eval_first, pb_eval_first;
wire [15:0] pa_eval_udp_total_len, pb_eval_udp_total_len;
wire [15:0] pa_eval_udp_checksum, pb_eval_udp_checksum;
wire        st_rx_frame_a, st_rx_frame_b;
wire        st_rx_drop_a, st_rx_drop_b;
wire        maca_rx_tready, macb_rx_tready;
wire [7:0] parse_a_data,parse_b_data;
wire parse_a_valid,parse_a_last,parse_a_error,parse_b_valid,parse_b_last,parse_b_error;
wire stage_a_can_start,stage_b_can_start;
reg rx_stream_active_a,rx_stream_active_b;
wire rx_gate_a=rx_stream_active_a||stage_a_can_start;
wire rx_gate_b=rx_stream_active_b||stage_b_can_start;
always @(posedge clk)begin
 if(rst)begin rx_stream_active_a<=0;rx_stream_active_b<=0;end
 else begin
  if(parse_a_valid&&maca_rx_tready&&rx_gate_a)rx_stream_active_a<=!parse_a_last;
  if(parse_b_valid&&macb_rx_tready&&rx_gate_b)rx_stream_active_b<=!parse_b_last;
 end
end
wire rx_elastic_overflow_a,rx_elastic_overflow_b;
localparam RX_ELASTIC_AW=$clog2(RX_ELASTIC_DEPTH>0?RX_ELASTIC_DEPTH:1);
wire [RX_ELASTIC_AW:0] rx_elastic_depth_a,rx_elastic_depth_b;
generate if(RX_ELASTIC_DEPTH>0)begin : g_rx_elastic
 afdx_rx_elastic #(.DEPTH(RX_ELASTIC_DEPTH)) a(
  .clk(clk),.rst(rst),.s_data(maca_rx_tdata),.s_valid(maca_rx_tvalid),.s_last(maca_rx_tlast),.s_error(maca_rx_tuser),
  .m_data(parse_a_data),.m_valid(parse_a_valid),.m_last(parse_a_last),.m_error(parse_a_error),.m_ready(maca_rx_tready&&rx_gate_a),
  .overflow(rx_elastic_overflow_a),.depth(rx_elastic_depth_a));
 afdx_rx_elastic #(.DEPTH(RX_ELASTIC_DEPTH)) b(
  .clk(clk),.rst(rst),.s_data(macb_rx_tdata),.s_valid(macb_rx_tvalid),.s_last(macb_rx_tlast),.s_error(macb_rx_tuser),
  .m_data(parse_b_data),.m_valid(parse_b_valid),.m_last(parse_b_last),.m_error(parse_b_error),.m_ready(macb_rx_tready&&rx_gate_b),
  .overflow(rx_elastic_overflow_b),.depth(rx_elastic_depth_b));
end else begin : g_rx_unbuffered
 assign parse_a_data=maca_rx_tdata;assign parse_a_valid=maca_rx_tvalid;assign parse_a_last=maca_rx_tlast;assign parse_a_error=maca_rx_tuser;
 assign parse_b_data=macb_rx_tdata;assign parse_b_valid=macb_rx_tvalid;assign parse_b_last=macb_rx_tlast;assign parse_b_error=macb_rx_tuser;
 assign rx_elastic_overflow_a=0;assign rx_elastic_overflow_b=0;assign rx_elastic_depth_a=0;assign rx_elastic_depth_b=0;
end endgenerate
wire        a_buf_tready, b_buf_tready;
wire [7:0]  a_buf_tdata, b_buf_tdata;
wire        a_buf_tvalid, b_buf_tvalid, a_buf_tlast, b_buf_tlast;
wire        a_frame_avail, b_frame_avail;
wire [11:0] a_frame_len, b_frame_len;
wire        pa_wr_blocked, pb_wr_blocked;

afdx_rx_parse parse_a (
    .clk(clk), .rst(rst), .es_enable(es_enable),
    .s_axis_tdata(parse_a_data), .s_axis_tvalid(parse_a_valid&&rx_gate_a),
    .s_axis_tready(maca_rx_tready), .s_axis_tlast(parse_a_last),
    .s_axis_tuser(parse_a_error),
    .wr_en(pa_wr_en), .wr_data(pa_wr_data), .wr_commit(pa_wr_commit),
    .wr_abort(pa_wr_abort), .wr_len(pa_wr_len),
    .wr_blocked(pa_wr_blocked),
    .eval_valid(pa_eval_valid), .eval_resp(pa_eval_resp),
    .eval_accept(pa_eval_accept), .eval_vlid(pa_eval_vlid),
    .eval_dport(pa_eval_dport), .eval_sn(pa_eval_sn),
    .eval_plen(pa_eval_plen),
    .eval_ip_id(pa_eval_ip_id), .eval_frag_offset(pa_eval_frag_offset),
    .eval_mf(pa_eval_mf), .eval_first(pa_eval_first),
    .eval_udp_total_len(pa_eval_udp_total_len),
    .eval_udp_checksum(pa_eval_udp_checksum),
    .eval_sport(pa_eval_sport), .eval_src_ip(pa_eval_src_ip),
    .st_rx_frame(st_rx_frame_a), .st_rx_drop_parse(st_rx_drop_a)
);

afdx_rx_parse parse_b (
    .clk(clk), .rst(rst), .es_enable(es_enable),
    .s_axis_tdata(parse_b_data), .s_axis_tvalid(parse_b_valid&&rx_gate_b),
    .s_axis_tready(macb_rx_tready), .s_axis_tlast(parse_b_last),
    .s_axis_tuser(parse_b_error),
    .wr_en(pb_wr_en), .wr_data(pb_wr_data), .wr_commit(pb_wr_commit),
    .wr_abort(pb_wr_abort), .wr_len(pb_wr_len),
    .wr_blocked(pb_wr_blocked),
    .eval_valid(pb_eval_valid), .eval_resp(pb_eval_resp),
    .eval_accept(pb_eval_accept), .eval_vlid(pb_eval_vlid),
    .eval_dport(pb_eval_dport), .eval_sn(pb_eval_sn),
    .eval_plen(pb_eval_plen),
    .eval_ip_id(pb_eval_ip_id), .eval_frag_offset(pb_eval_frag_offset),
    .eval_mf(pb_eval_mf), .eval_first(pb_eval_first),
    .eval_udp_total_len(pb_eval_udp_total_len),
    .eval_udp_checksum(pb_eval_udp_checksum),
    .eval_sport(pb_eval_sport), .eval_src_ip(pb_eval_src_ip),
    .st_rx_frame(st_rx_frame_b), .st_rx_drop_parse(st_rx_drop_b)
);

afdx_frame_buf #(.DEPTH(2048)) buf_a (
    .clk(clk), .rst(rst),
    .wr_en(pa_wr_en), .wr_data(pa_wr_data),
    .wr_full(), .wr_blocked(pa_wr_blocked),
    .wr_commit(pa_wr_commit), .wr_abort(pa_wr_abort), .wr_len(pa_wr_len),
    .frame_avail(a_frame_avail), .frame_len(a_frame_len),
    .m_axis_tdata(a_buf_tdata), .m_axis_tvalid(a_buf_tvalid),
    .m_axis_tready(a_buf_tready), .m_axis_tlast(a_buf_tlast), .can_start(stage_a_can_start)
);

afdx_frame_buf #(.DEPTH(2048)) buf_b (
    .clk(clk), .rst(rst),
    .wr_en(pb_wr_en), .wr_data(pb_wr_data),
    .wr_full(), .wr_blocked(pb_wr_blocked),
    .wr_commit(pb_wr_commit), .wr_abort(pb_wr_abort), .wr_len(pb_wr_len),
    .frame_avail(b_frame_avail), .frame_len(b_frame_len),
    .m_axis_tdata(b_buf_tdata), .m_axis_tvalid(b_buf_tvalid),
    .m_axis_tready(b_buf_tready), .m_axis_tlast(b_buf_tlast), .can_start(stage_b_can_start)
);

wire        dlv_valid, dlv_ready, dlv_net, dlv_type;
wire [5:0]  dlv_port;
wire [11:0] dlv_len;
wire [15:0] dlv_vlid, dlv_sport, dlv_dport;
wire [15:0] dlv_ip_id, dlv_udp_total_len, dlv_udp_checksum;
wire [12:0] dlv_frag_offset;
wire        dlv_mf, dlv_first;
wire [31:0] dlv_src_ip;
wire        st_ic_drop, st_rm_drop, st_cfg_drop, st_fwd, st_lmax_drop, st_police_drop;

afdx_rx_check #(.N_RX_VL(N_RX_VL), .TICK_NS(TICK_NS)) rx_check (
    .clk(clk), .rst(rst),
    .a_eval_valid(pa_eval_valid), .a_eval_resp(pa_eval_resp),
    .a_eval_accept(pa_eval_accept), .a_eval_vlid(pa_eval_vlid),
    .a_eval_dport(pa_eval_dport), .a_eval_sn(pa_eval_sn),
    .a_eval_plen(pa_eval_plen),
    .a_eval_ip_id(pa_eval_ip_id), .a_eval_frag_offset(pa_eval_frag_offset),
    .a_eval_mf(pa_eval_mf), .a_eval_first(pa_eval_first),
    .a_eval_udp_total_len(pa_eval_udp_total_len),
    .a_eval_udp_checksum(pa_eval_udp_checksum),
    .a_eval_sport(pa_eval_sport), .a_eval_src_ip(pa_eval_src_ip),
    .b_eval_valid(pb_eval_valid), .b_eval_resp(pb_eval_resp),
    .b_eval_accept(pb_eval_accept), .b_eval_vlid(pb_eval_vlid),
    .b_eval_dport(pb_eval_dport), .b_eval_sn(pb_eval_sn),
    .b_eval_plen(pb_eval_plen),
    .b_eval_ip_id(pb_eval_ip_id), .b_eval_frag_offset(pb_eval_frag_offset),
    .b_eval_mf(pb_eval_mf), .b_eval_first(pb_eval_first),
    .b_eval_udp_total_len(pb_eval_udp_total_len),
    .b_eval_udp_checksum(pb_eval_udp_checksum),
    .b_eval_sport(pb_eval_sport), .b_eval_src_ip(pb_eval_src_ip),
    .rxvl_vlid(rxvl_vlid), .rxvl_valid(rxvl_valid), .rxvl_type(rxvl_type),
    .rxvl_ic_dis(rxvl_ic_dis), .rxvl_no_rm(rxvl_no_rm),
    .rxvl_port(rxvl_port), .rxvl_dst_port(rxvl_dst_port),
    .rxvl_police_enable(rxvl_police_enable), .rxvl_bag(rxvl_bag),
    .rxvl_max_payload(rxvl_max_payload),
    .rxvl_idx(rxvl_idx),
    .dlv_valid(dlv_valid), .dlv_ready(dlv_ready),
    .dlv_net(dlv_net), .dlv_port(dlv_port),
    .dlv_type(dlv_type), .dlv_len(dlv_len),
    .dlv_vlid(dlv_vlid),
    .dlv_ip_id(dlv_ip_id), .dlv_frag_offset(dlv_frag_offset),
    .dlv_mf(dlv_mf), .dlv_first(dlv_first),
    .dlv_udp_total_len(dlv_udp_total_len),
    .dlv_udp_checksum(dlv_udp_checksum),
    .dlv_sport(dlv_sport), .dlv_dport(dlv_dport), .dlv_src_ip(dlv_src_ip),
    .rm_skew_us(rm_skew_us), .now_us(tick_us), .now_tick(now_tick),
    .st_ic_drop(st_ic_drop), .st_rm_drop(st_rm_drop),
    .st_cfg_drop(st_cfg_drop), .st_fwd(st_fwd),
    .st_lmax_drop(st_lmax_drop), .st_police_drop(st_police_drop)
);

wire [31:0] stat_qfull_drop, stat_deliver;

afdx_rx_port #(.N_PORTS(N_RX_PORT), .N_SLOTS(N_RX_SLOT),
               .SLOT_B(2048)) rx_port (
    .clk(clk), .rst(rst),
    .dlv_valid(dlv_valid), .dlv_ready(dlv_ready),
    .dlv_net(dlv_net), .dlv_port(dlv_port),
    .dlv_type(dlv_type), .dlv_len(dlv_len),
    .dlv_vlid(dlv_vlid),
    .dlv_ip_id(dlv_ip_id), .dlv_frag_offset(dlv_frag_offset),
    .dlv_mf(dlv_mf), .dlv_first(dlv_first),
    .dlv_udp_total_len(dlv_udp_total_len),
    .dlv_udp_checksum(dlv_udp_checksum),
    .dlv_sport(dlv_sport), .dlv_dport(dlv_dport), .dlv_src_ip(dlv_src_ip),
    .a_buf_tdata(a_buf_tdata), .a_buf_tvalid(a_buf_tvalid),
    .a_buf_tready(a_buf_tready), .a_buf_tlast(a_buf_tlast),
    .b_buf_tdata(b_buf_tdata), .b_buf_tvalid(b_buf_tvalid),
    .b_buf_tready(b_buf_tready), .b_buf_tlast(b_buf_tlast),
    .host_port(host_rx_port), .host_ready(host_rx_ready),
    .host_tdata(host_rx_tdata), .host_tvalid(host_rx_tvalid),
    .host_tlast(host_rx_tlast), .host_avail(host_rx_avail),
    .host_flen(host_rx_flen), .host_frame_port(host_rx_frame_port),
    .host_vlid(host_rx_vlid),
    .host_ip_id(host_rx_ip_id), .host_frag_offset(host_rx_frag_offset),
    .host_mf(host_rx_mf), .host_first(host_rx_first),
    .host_udp_total_len(host_rx_udp_total_len),
    .host_udp_checksum(host_rx_udp_checksum),
    .host_src_ip(host_rx_src_ip), .host_src_port(host_rx_src_port), .host_dst_port(host_rx_dst_port),
    .stat_qfull_drop(stat_qfull_drop), .stat_deliver(stat_deliver)
);

// ------------------------------------------------------------------
// RTC
// ------------------------------------------------------------------
wire [31:0] rtc_ns_w;

afdx_rtc #(.TICK_NS(TICK_NS), .RATE_PPB(RTC_RATE_PPB)) rtc (
    .clk(clk), .rst(rst),
    .cfg_wen(cfg_rtc_wen), .cfg_op(cfg_rtc_op), .cfg_wdata(cfg_wdata),
    .adj_valid(rtc_adj_valid), .adj_sign(rtc_adj_sign), .adj_ns(rtc_adj_ns),
    .set_valid(rtc_set_valid), .set_sec(rtc_set_sec), .set_ns(rtc_set_ns),
    .rtc_sec(rtc_sec), .rtc_ns(rtc_ns_w), .tick_us(tick_us), .pps(rtc_pps)
);
assign rtc_ns=rtc_ns_w;

// ------------------------------------------------------------------
// statistics / status read mux (word addressed, offsets 0x20-0x3F)
// ------------------------------------------------------------------
reg [31:0] cnt_tx_frames, cnt_rx_fwd, cnt_ic_drop, cnt_rm_drop,
           cnt_cfg_drop, cnt_parse_drop, cnt_qfull_drop, stat_rx_lmax_drop, stat_rx_police_drop;
reg [31:0] stat_tx_lmax_reject;
reg [31:0] stat_rx_elastic_overflow;
always @(posedge clk)begin
 if(rst)stat_rx_elastic_overflow<=0;
 else stat_rx_elastic_overflow<=stat_rx_elastic_overflow+rx_elastic_overflow_a+rx_elastic_overflow_b;
end
reg tx_lmax_seen;
wire tx_length_rejected=host_tx_len>((tx_commit_max_payload==0 || tx_commit_max_payload>1471) ? 12'd1471:tx_commit_max_payload);
always @(posedge clk)begin
 if(rst)begin stat_tx_lmax_reject<=0;tx_lmax_seen<=0;end
 else begin
  if(!host_tx_commit || !tx_length_rejected)tx_lmax_seen<=0;
  else if(!tx_lmax_seen)begin stat_tx_lmax_reject<=stat_tx_lmax_reject+1'b1;tx_lmax_seen<=1;end
 end
end
always @(posedge clk) begin
    if (rst) begin
        cnt_tx_frames  <= 32'd0; cnt_rx_fwd     <= 32'd0;
        cnt_ic_drop    <= 32'd0; cnt_rm_drop    <= 32'd0;
        cnt_cfg_drop   <= 32'd0; cnt_parse_drop <= 32'd0;
        cnt_qfull_drop <= 32'd0;
        stat_rx_lmax_drop <= 32'd0; stat_rx_police_drop <= 32'd0;
    end else begin
        if (tx_frame_stb)              cnt_tx_frames  <= cnt_tx_frames + 1;
        if (st_fwd)                    cnt_rx_fwd     <= cnt_rx_fwd + 1;
        if (st_ic_drop)                cnt_ic_drop    <= cnt_ic_drop + 1;
        if (st_rm_drop)                cnt_rm_drop    <= cnt_rm_drop + 1;
        if (st_cfg_drop)               cnt_cfg_drop   <= cnt_cfg_drop + 1;
        if (st_lmax_drop)              stat_rx_lmax_drop  <= stat_rx_lmax_drop + 1;
        if (st_police_drop)            stat_rx_police_drop <= stat_rx_police_drop + 1;
        if (st_rx_drop_a || st_rx_drop_b)
                                       cnt_parse_drop <= cnt_parse_drop + 1;
        cnt_qfull_drop <= stat_qfull_drop;
    end
end

always @(*) begin
    case (cfg_addr[7:0])
        8'h00:   cfg_rdata = {30'd0, tx_enable, es_enable};
        8'h01:   cfg_rdata = src_mac[31:0];
        8'h02:   cfg_rdata = {16'd0, src_mac[47:32]};
        8'h03:   cfg_rdata = src_ip;
        8'h04:   cfg_rdata = {24'd0, ip_ttl};
        8'h05:   cfg_rdata = {16'd0, rm_skew_us};
        8'h20:   cfg_rdata = cnt_tx_frames;
        8'h21:   cfg_rdata = cnt_rx_fwd;
        8'h22:   cfg_rdata = cnt_ic_drop;
        8'h23:   cfg_rdata = cnt_rm_drop;
        8'h24:   cfg_rdata = cnt_cfg_drop;
        8'h25:   cfg_rdata = cnt_parse_drop;
        8'h26:   cfg_rdata = cnt_qfull_drop;
        8'h27:   cfg_rdata = {31'd0, err_vl_overflow};
        8'h2B:   cfg_rdata = stat_rx_lmax_drop;
        8'h2C:   cfg_rdata = stat_rx_police_drop;
        8'h2D:   cfg_rdata = stat_tx_lmax_reject;
        8'h2E:   cfg_rdata = stat_rx_elastic_overflow;
        8'h28:   cfg_rdata = tick_us;
        8'h29:   cfg_rdata = rtc_sec;
        8'h2A:   cfg_rdata = rtc_ns_w;
        default: cfg_rdata = 32'd0;
    endcase
end

endmodule
`default_nettype wire
