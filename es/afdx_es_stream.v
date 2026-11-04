`timescale 1ns/1ps
`default_nettype none
// Fixed-port application demonstration: GMII/FCS input -> configured AFDX
// end-system RX -> payload queue -> BAG-shaped TX -> MAC/FCS output.
// Startup maps RX VLIDs 1..N_RX_VL to ports (VLID-1)%N_RX_PORT and TX
// VLIDs 1..N_TX_VL to the same destination UDP port. One physical A lane
// is exposed; the core's independent B MAC remains instantiated internally.
// rx_valid is GMII RX_DV: no gaps/backpressure inside an admitted input frame.
// tx_valid/tx_data is a buffered wire-frame stream; consume with rx_ready.
module afdx_es_stream #(
    parameter N_TX_VL=128,
    parameter N_RX_VL=4096,
    parameter N_RX_PORT=64,
    parameter TICK_NS=8,
    parameter OUTPUT_DEPTH=8192,
    parameter ENABLE_SNMP=0,
    parameter [31:0] SNMP_MANAGER_IP=32'h0a000002,
    parameter [15:0] SNMP_MANAGER_PORT=16'd40000,
    parameter ENABLE_TIME_SYNC=0, TIME_MASTER=0,
    parameter TIME_POLL_US=8000, TIME_TIMEOUT_US=4000, TIME_HOLDOVER_US=32000,
    parameter TIME_LOCK_THRESHOLD_NS=25000, TIME_LOCK_SAMPLES=3,
    parameter [31:0] TIME_NODE_ID=1, TIME_LOCAL_IP=32'h0a000001,
    parameter [31:0] TIME_PEER_IP=32'h0a000002,
    parameter [31:0] TIME_INITIAL_SEC=0, TIME_INITIAL_NS=0,
    parameter RTC_RATE_PPB=0,
    parameter ENABLE_LOADER=0, LOADER_IMAGE_BYTES=4096,
    parameter LOADER_TIMEOUT_US=20000, LOADER_MAX_RETRIES=3,
    parameter TRAFFIC_GUARD=0, TRAFFIC_GAP_US=64, TRAFFIC_BURST=2,
    parameter MAX_OUTPUT_STALL_US=8
) (
    input wire clk, input wire reset,
    input wire [7:0] rx_data, input wire rx_valid,
    output wire tx_ready,
    output wire [7:0] tx_data, output wire tx_valid,
    input wire rx_ready
);
localparam B_BOOT=0, B_SCAN=1, B_ALLOC=2, B_COPY=3, B_COMMIT=4, B_WAIT=5,
           B_MGMT_RX=6, B_MGMT_WAIT=7, B_MGMT_ALLOC=8, B_MGMT_COPY=9,
           B_MGMT_COMMIT=10, B_TIME_RX=11, B_TIME_ALLOC=12,
           B_TIME_COPY=13, B_TIME_COMMIT=14, B_LOAD_RX=15,
           B_LOAD_PORT=16, B_LOAD_IP=17, B_LOAD_ALLOC=18, B_LOAD_COPY=19, B_LOAD_COMMIT=20;
reg [4:0] state;
reg [14:0] boot_word;
reg boot_done;
reg [5:0] port_sel;
reg [3:0] slot;
reg [11:0] offset, length;
reg alloc_sent;
wire cfg_wen = (state==B_BOOT || state==B_LOAD_PORT || state==B_LOAD_IP) && !reset;
reg [19:0] cfg_addr;
reg [31:0] cfg_wdata;
wire [19:0] snmp_stats_addr;
wire [31:0] snmp_stats_data;
wire [19:0] core_cfg_addr = cfg_wen ? cfg_addr : snmp_stats_addr;
reg [31:0] loader_ip;
reg [15:0] loader_sport,loader_dport;
wire [14:0] rx_boot_offset = boot_word - (N_TX_VL*4+1);
wire ordinary_boot_vl=(rx_boot_offset/2 >= (ENABLE_LOADER?3:(ENABLE_TIME_SYNC?2:(ENABLE_SNMP?1:0))));
localparam BOOT_TABLE_END=N_TX_VL*4+N_RX_VL*2;
wire rtc_boot_set=ENABLE_TIME_SYNC && state==B_BOOT && boot_word==BOOT_TABLE_END+2;
always @* begin
    cfg_addr=20'h00006; cfg_wdata=0;
    if(boot_word==0) begin cfg_addr=20'h00006; cfg_wdata=0; end
    else if(boot_word<=N_TX_VL*4) begin
        cfg_addr=20'h01000+boot_word-1;
        case ((boot_word-1)%4)
            0: cfg_wdata=32'h80000000+((boot_word-1)/4+1);
            1: cfg_wdata=ENABLE_TIME_SYNC && boot_word==6 ? {16'd55000,16'd55000} :
                        (ENABLE_SNMP && boot_word==2 ? {16'd161,SNMP_MANAGER_PORT} : 32'h12345678);
            2: cfg_wdata=ENABLE_TIME_SYNC && boot_word==7 ? TIME_PEER_IP :
                        (ENABLE_SNMP && boot_word==3 ? SNMP_MANAGER_IP : 32'h0a000002);
            default: cfg_wdata=0;
        endcase
    end else if(boot_word<=N_TX_VL*4+N_RX_VL*2) begin
        cfg_addr=20'h02000+rx_boot_offset;
        if(!rx_boot_offset[0])
            cfg_wdata=32'hc0000000 | (((rx_boot_offset/2)%N_RX_PORT)<<16) |
                      (rx_boot_offset/2+1);
        else cfg_wdata=32'h00005678;
        // MODE=2 reserves host port 0 exclusively for VLID 1 management.
        // Other VLs use ports 1..63, so ordinary UDP never enters BER parsing.
        if(ENABLE_SNMP) begin
            if(!rx_boot_offset[0])
                cfg_wdata=32'hc0000000 | ((rx_boot_offset==0 ? 0 :
                    (1+((rx_boot_offset/2-1)%(N_RX_PORT-1))))<<16) | (rx_boot_offset/2+1);
            else if(rx_boot_offset==1) cfg_wdata=32'd161;
        end
        if(ENABLE_TIME_SYNC) begin
            if(!rx_boot_offset[0]) begin
                if(rx_boot_offset==0 && ENABLE_SNMP) cfg_wdata=32'hc0000001;
                else if(rx_boot_offset==2) cfg_wdata=32'hc0010002;
                else cfg_wdata=32'hc0000000 | ((2+((rx_boot_offset/2-2)%(N_RX_PORT-2)))<<16) | (rx_boot_offset/2+1);
            end else if(rx_boot_offset==3) cfg_wdata=32'd55000;
        end
        if(ENABLE_LOADER) begin
            if(!rx_boot_offset[0]) begin
                if(rx_boot_offset==0) cfg_wdata=32'hc0000001;
                else if(rx_boot_offset==2) cfg_wdata=32'hc0010002;
                else if(rx_boot_offset==4) cfg_wdata=32'hc0020003;
                else cfg_wdata=32'hc0000000 | ((3+((rx_boot_offset/2-3)%(N_RX_PORT-3)))<<16) | (rx_boot_offset/2+1);
            end else if(rx_boot_offset==5) cfg_wdata=0; // explicit per-VL UDP wildcard
        end
        // Guarded ordinary echo VLs use a 1ms receive BAG and 1471-byte Lmax.
        // Protocol services retain independent transport timing policies.
        if(TRAFFIC_GUARD && rx_boot_offset[0] && ordinary_boot_vl)
            cfg_wdata=cfg_wdata | 32'h80000000;
    end else begin cfg_addr=20'h00006; cfg_wdata=3; end
    if(ENABLE_TIME_SYNC && boot_word==BOOT_TABLE_END+1) begin cfg_addr=20'h00003; cfg_wdata=TIME_LOCAL_IP; end
    if(rtc_boot_set) begin cfg_addr=20'h00000; cfg_wdata=0; end
    if(state==B_LOAD_PORT) begin cfg_addr=20'h01009; cfg_wdata={loader_sport,loader_dport}; end
    if(state==B_LOAD_IP) begin cfg_addr=20'h0100a; cfg_wdata=loader_ip; end
end

wire ingress_reject;
wire [31:0] ingress_admitted,ingress_dropped;
afdx_ingress_guard #(.TICK_NS(TICK_NS),.GAP_US(TRAFFIC_GAP_US),.BURST(TRAFFIC_BURST)) u_ingress_guard(
 .clk(clk),.rst(reset),.enable(TRAFFIC_GUARD!=0),.rx_dv(rx_valid&&tx_ready),
 .reject_error(ingress_reject),.stat_admitted(ingress_admitted),.stat_rejected(ingress_dropped));
reg [31:0] output_stall_ticks,output_stall_violations;
localparam integer STALL_LIMIT_TICKS=(MAX_OUTPUT_STALL_US*1000+TICK_NS-1)/TICK_NS;
always @(posedge clk)begin
 if(reset)begin output_stall_ticks<=0;output_stall_violations<=0;end
 else if(TRAFFIC_GUARD && !rx_ready)begin
  if(output_stall_ticks!=32'hffffffff)output_stall_ticks<=output_stall_ticks+1'b1;
  if(output_stall_ticks==STALL_LIMIT_TICKS)output_stall_violations<=output_stall_violations+1'b1;
 end else output_stall_ticks<=0;
end
wire [3:0] alloc_slot;
wire alloc_ack, alloc_fail, commit_ready;
wire [7:0] host_data;
wire host_valid, host_last, host_avail;
wire [11:0] host_len;
wire [5:0] host_frame_port;
wire [15:0] host_vlid;
wire [15:0] host_ip_id, host_udp_total_len, host_udp_checksum;
wire [12:0] host_frag_offset;
wire host_mf, host_first;
wire [31:0] host_src_ip;
wire [15:0] host_src_port,host_dst_port;
wire [7:0] mac_data, mac_b_data;
wire mac_valid, mac_b_valid, mac_error, mac_b_error;
wire [$clog2(OUTPUT_DEPTH):0] out_depth;
// Charge every submitted frame a maximum 1536-byte wire reservation until
// the MAC has committed it to the output FIFO. FIFO depth also counts the
// currently arriving MAC frame, so the estimate is deliberately conservative.
// This bounds occupied + in-flight bytes with an 8192-byte output memory.
reg [4:0] pending_wire_frames;
wire [31:0] reserved_output_bytes = out_depth + pending_wire_frames*1536;
wire out_room = reserved_output_bytes <= OUTPUT_DEPTH-1536;
wire snmp_in_ready, snmp_out_valid, snmp_out_last, snmp_busy;
wire [7:0] snmp_out_data;
wire time_in_ready, time_out_valid, time_out_last, time_busy;
wire [7:0] time_out_data;
wire [31:0] rtc_sec,rtc_ns,tick_us;
wire rtc_pps, time_set_valid, time_synced, time_sync_pulse;
wire [31:0] time_set_sec,time_set_ns,time_applied,time_rejected,time_timeout;
wire signed [63:0] time_offset_ns;
wire [63:0] time_delay_ns;
wire loader_in_ready,loader_out_valid,loader_out_last;
wire [7:0] loader_out_data;
wire [31:0] loader_out_ip;
wire [15:0] loader_out_sport,loader_out_dport;
wire [3:0] loader_state;
wire [15:0] loader_status;
wire [7:0] loader_progress;
wire loader_image_valid;
wire [12:0] loader_image_size;
wire [31:0] loader_image_crc,loader_success,loader_failure,loader_retries,loader_errors;
reg loader_inflight;
wire snmp_out_ready = state==B_MGMT_COPY;
wire host_ready = state==B_COPY || (state==B_ALLOC && alloc_ack && length==0) ||
                  (state==B_MGMT_RX && snmp_in_ready) ||
                  (state==B_TIME_RX && time_in_ready) || (state==B_LOAD_RX && loader_in_ready);
wire host_write = (state==B_COPY && host_valid) ||
                  (state==B_MGMT_COPY && snmp_out_valid) ||
                  (state==B_TIME_COPY && time_out_valid) || (state==B_LOAD_COPY && loader_out_valid);
wire [7:0] tx_write_data = state==B_LOAD_COPY ? loader_out_data : (state==B_TIME_COPY ? time_out_data :
                          (state==B_MGMT_COPY ? snmp_out_data : host_data));
wire alloc_req = (state==B_ALLOC || state==B_MGMT_ALLOC || state==B_TIME_ALLOC || state==B_LOAD_ALLOC) && !alloc_sent;
wire commit = (state==B_COMMIT || state==B_MGMT_COMMIT || state==B_TIME_COMMIT || state==B_LOAD_COMMIT) && commit_ready && out_room;
wire [6:0] commit_vl = state==B_LOAD_COMMIT ? 7'd2 : (state==B_TIME_COMMIT ? 7'd1 : (state==B_MGMT_COMMIT ? 7'd0 : {1'b0,port_sel}));
generate if(ENABLE_LOADER) begin : g_loader
    afdx_loader #(.IMAGE_BYTES(LOADER_IMAGE_BYTES),.TIMEOUT_US(LOADER_TIMEOUT_US),.MAX_RETRIES(LOADER_MAX_RETRIES)) u_loader (
        .clk(clk),.rst(reset),.enable(boot_done&&!reset),.tick_us(tick_us),
        .s_data(host_data),.s_valid(state==B_LOAD_RX&&host_valid),.s_last(host_last),.s_ready(loader_in_ready),
        .s_src_ip(host_src_ip),.s_src_port(host_src_port),.s_dst_port(host_dst_port),
        .m_data(loader_out_data),.m_valid(loader_out_valid),.m_last(loader_out_last),.m_ready(state==B_LOAD_COPY),
        .m_dst_ip(loader_out_ip),.m_src_port(loader_out_sport),.m_dst_port(loader_out_dport),
        .load_state(loader_state),.operation_status(loader_status),.progress(loader_progress),
        .image_valid(loader_image_valid),.image_size(loader_image_size),.image_crc(loader_image_crc),
        .stat_success(loader_success),.stat_failure(loader_failure),.stat_retries(loader_retries),.stat_errors(loader_errors));
end else begin : g_no_loader
    assign loader_in_ready=1'b0;assign loader_out_valid=1'b0;assign loader_out_last=1'b0;
    assign loader_out_data=0;assign loader_out_ip=0;assign loader_out_sport=0;assign loader_out_dport=0;
    assign loader_state=0;assign loader_status=0;assign loader_progress=0;assign loader_image_valid=0;
    assign loader_image_size=0;assign loader_image_crc=0;assign loader_success=0;assign loader_failure=0;
    assign loader_retries=0;assign loader_errors=0;
end endgenerate
generate if(ENABLE_TIME_SYNC) begin : g_time
    afdx_time_sync #(.IS_MASTER(TIME_MASTER), .TICK_NS(TICK_NS),
        .POLL_US(TIME_POLL_US), .TIMEOUT_US(TIME_TIMEOUT_US), .HOLDOVER_US(TIME_HOLDOVER_US),
        .LOCK_THRESHOLD_NS(TIME_LOCK_THRESHOLD_NS), .LOCK_SAMPLES(TIME_LOCK_SAMPLES),
        .NODE_ID(TIME_NODE_ID)) u_sync (
        .clk(clk), .rst(reset), .enable(boot_done && !reset),
        .rtc_sec(rtc_sec), .rtc_ns(rtc_ns), .tick_us(tick_us),
        .s_data(host_data), .s_valid(state==B_TIME_RX && host_valid),
        .s_last(host_last), .s_ready(time_in_ready),
        .m_data(time_out_data), .m_valid(time_out_valid), .m_last(time_out_last),
        .m_ready(state==B_TIME_COPY), .busy(time_busy),
        .set_valid(time_set_valid), .set_sec(time_set_sec), .set_ns(time_set_ns),
        .synced(time_synced), .sync_pulse(time_sync_pulse), .last_offset_ns(time_offset_ns),
        .last_delay_ns(time_delay_ns), .stat_applied(time_applied),
        .stat_rejected(time_rejected), .stat_timeout(time_timeout));
end else begin : g_no_time
    assign time_in_ready=1'b0; assign time_out_valid=1'b0; assign time_out_last=1'b0;
    assign time_out_data=8'd0; assign time_busy=1'b0; assign time_set_valid=1'b0;
    assign time_set_sec=32'd0; assign time_set_ns=32'd0; assign time_synced=1'b0;
    assign time_sync_pulse=1'b0; assign time_offset_ns=64'd0; assign time_delay_ns=64'd0;
    assign time_applied=32'd0; assign time_rejected=32'd0; assign time_timeout=32'd0;
end endgenerate
generate if(ENABLE_SNMP) begin : g_snmp
    afdx_snmp_agent #(.MAX_PACKET(1471), .TICK_NS(TICK_NS),
        .N_TX_VL(N_TX_VL), .N_RX_VL(N_RX_VL)) u_agent (
        .clk(clk), .rst(reset), .s_data(host_data),
        .s_valid(state==B_MGMT_RX && host_valid), .s_ready(snmp_in_ready), .s_last(host_last),
        .m_data(snmp_out_data), .m_valid(snmp_out_valid), .m_ready(snmp_out_ready),
        .m_last(snmp_out_last), .busy(snmp_busy),
        .stats_addr(snmp_stats_addr), .stats_data(snmp_stats_data));
end else begin : g_no_snmp
    assign snmp_in_ready=1'b0;
    assign snmp_out_data=8'd0;
    assign snmp_out_valid=1'b0;
    assign snmp_out_last=1'b0;
    assign snmp_busy=1'b0;
    assign snmp_stats_addr=20'd0;
end endgenerate
reg input_active;
assign tx_ready = boot_done && !reset && (input_active || out_room);
always @(posedge clk) begin
    if(reset) input_active<=0;
    else if(!rx_valid) input_active<=0;
    else if(tx_ready) input_active<=1;
end

afdx_es #(.N_TX_VL(N_TX_VL), .N_RX_VL(N_RX_VL), .N_RX_PORT(N_RX_PORT),
          .N_SLOTS(8), .N_RX_SLOT(8), .TICK_NS(TICK_NS), .RTC_RATE_PPB(RTC_RATE_PPB)) u_core (
    .clk(clk), .rst(reset),
    .gmii_a_rxd(rx_data), .gmii_a_rx_dv(rx_valid && tx_ready), .gmii_a_rx_er(ingress_reject),
    .gmii_a_txd(mac_data), .gmii_a_tx_en(mac_valid), .gmii_a_tx_er(mac_error),
    .gmii_b_rxd(8'd0), .gmii_b_rx_dv(1'b0), .gmii_b_rx_er(1'b0),
    .gmii_b_txd(mac_b_data), .gmii_b_tx_en(mac_b_valid), .gmii_b_tx_er(mac_b_error),
    .host_tx_alloc_req(alloc_req), .host_tx_alloc_slot(alloc_slot),
    .host_tx_alloc_ack(alloc_ack), .host_tx_alloc_fail(alloc_fail),
    .host_tx_wr_en(host_write), .host_tx_wr_addr({slot,11'd0}+offset),
    .host_tx_wr_data(tx_write_data), .host_tx_commit(commit),
    .host_tx_vl(commit_vl), .host_tx_slot(slot), .host_tx_len(length),
    .host_tx_ip_id(16'd0),.host_tx_frag_offset(13'd0),
    .host_tx_mf(1'b0),.host_tx_first(1'b1),
    .host_tx_udp_total_len({4'd0,length}+16'd8),
    .host_tx_commit_ready(commit_ready),
    .host_rx_port(port_sel), .host_rx_ready(host_ready),
    .host_rx_tdata(host_data), .host_rx_tvalid(host_valid), .host_rx_tlast(host_last),
    .host_rx_avail(host_avail), .host_rx_flen(host_len),
    .host_rx_frame_port(host_frame_port),
    .host_rx_vlid(host_vlid),
    .host_rx_ip_id(host_ip_id), .host_rx_frag_offset(host_frag_offset),
    .host_rx_mf(host_mf), .host_rx_first(host_first),
    .host_rx_udp_total_len(host_udp_total_len),
    .host_rx_udp_checksum(host_udp_checksum),
    .host_rx_src_ip(host_src_ip),.host_rx_src_port(host_src_port),.host_rx_dst_port(host_dst_port),
    .cfg_wen(cfg_wen), .cfg_addr(core_cfg_addr), .cfg_wdata(cfg_wdata),
    .cfg_rtc_op(2'd0), .cfg_rtc_wen(1'b0), .cfg_rdata(snmp_stats_data),
    .rtc_adj_valid(1'b0), .rtc_adj_sign(1'b0), .rtc_adj_ns(32'd0),
    .rtc_set_valid(rtc_boot_set || time_set_valid),
    .rtc_set_sec(rtc_boot_set ? TIME_INITIAL_SEC : time_set_sec),
    .rtc_set_ns(rtc_boot_set ? TIME_INITIAL_NS : time_set_ns),
    .rtc_sec(rtc_sec), .rtc_ns(rtc_ns), .tick_us(tick_us), .rtc_pps(rtc_pps)
);

always @(posedge clk) begin
    if(reset) begin
        state<=B_BOOT; boot_word<=0; boot_done<=0; port_sel<=0;
        slot<=0; offset<=0; length<=0; alloc_sent<=0;
        loader_ip<=0;loader_sport<=0;loader_dport<=0;
    end else case(state)
        B_BOOT: begin
            if(boot_word==BOOT_TABLE_END+1+(ENABLE_TIME_SYNC?2:0)) begin
                boot_done<=1; state<=B_SCAN;
            end else boot_word<=boot_word+1'b1;
        end
        B_SCAN: begin
            if(time_out_valid && out_room) begin offset<=0; alloc_sent<=0; state<=B_TIME_ALLOC; end
            else if(loader_out_valid && !loader_inflight && out_room) begin
                loader_ip<=loader_out_ip;loader_sport<=loader_out_sport;loader_dport<=loader_out_dport;
                offset<=0;alloc_sent<=0;state<=B_LOAD_PORT;
            end
            else if(host_avail && out_room) begin
                length<=host_len; offset<=0; alloc_sent<=0;
                port_sel<=host_frame_port;
                if(ENABLE_LOADER && host_frame_port==2) state<=B_LOAD_RX;
                else if(ENABLE_TIME_SYNC && host_frame_port==1) state<=B_TIME_RX;
                else state<=ENABLE_SNMP && host_frame_port==0 ? B_MGMT_RX : B_ALLOC;
            end else port_sel <= (port_sel==N_RX_PORT-1) ? 0 : port_sel+1'b1;
        end
        B_ALLOC: begin
            if(alloc_req) alloc_sent<=1;
            if(alloc_ack) begin slot<=alloc_slot; state<=length==0 ? B_COMMIT : B_COPY; end
            else if(alloc_fail) begin alloc_sent<=0; state<=B_WAIT; end
        end
        B_COPY: if(host_write) begin
            offset<=offset+1'b1;
            if(host_last) state<=B_COMMIT;
        end
        B_COMMIT: if(commit) begin state<=B_SCAN; port_sel<= (port_sel==N_RX_PORT-1) ? 0 : port_sel+1'b1; end
        B_WAIT: begin alloc_sent<=0; state<=B_ALLOC; end
        B_MGMT_RX: if(length==0 || (host_valid && host_ready && host_last)) state<=B_MGMT_WAIT;
        B_MGMT_WAIT: begin
            if(snmp_out_valid && out_room) begin offset<=0; alloc_sent<=0; state<=B_MGMT_ALLOC; end
            else if(!snmp_busy && !snmp_out_valid) begin state<=B_SCAN; port_sel<=1; end
        end
        B_MGMT_ALLOC: begin
            if(alloc_req) alloc_sent<=1;
            if(alloc_ack) begin slot<=alloc_slot; state<=B_MGMT_COPY; end
            else if(alloc_fail) alloc_sent<=0;
        end
        B_MGMT_COPY: if(snmp_out_valid && snmp_out_ready) begin
            offset<=offset+1'b1;
            if(snmp_out_last) begin length<=offset+1'b1; state<=B_MGMT_COMMIT; end
        end
        B_MGMT_COMMIT: if(commit) begin state<=B_SCAN; port_sel<=1; end
        B_TIME_RX: begin
            // A periodic request may become valid on the same edge SCAN
            // selects a prefetched response. Drain TX before resuming that
            // unchanged RX frame; the protocol cannot launch TX mid-RX.
            if(time_out_valid && !time_in_ready) begin offset<=0; alloc_sent<=0; state<=B_TIME_ALLOC; end
            else if(length==0 || (host_valid && host_ready && host_last)) begin state<=B_SCAN; port_sel<=2; end
        end
        B_TIME_ALLOC: begin
            if(alloc_req) alloc_sent<=1;
            if(alloc_ack) begin slot<=alloc_slot; state<=B_TIME_COPY; end
            else if(alloc_fail) alloc_sent<=0;
        end
        B_TIME_COPY: if(time_out_valid) begin
            offset<=offset+1'b1;
            if(time_out_last) begin length<=offset+1'b1; state<=B_TIME_COMMIT; end
        end
        B_TIME_COMMIT: if(commit) begin state<=B_SCAN; port_sel<=2; end
        B_LOAD_RX: begin
            if(loader_out_valid && !loader_in_ready && !loader_inflight && out_room) begin
                loader_ip<=loader_out_ip;loader_sport<=loader_out_sport;loader_dport<=loader_out_dport;
                offset<=0;alloc_sent<=0;state<=B_LOAD_PORT;
            end else if(length==0 || (host_valid&&host_ready&&host_last)) begin state<=B_SCAN;port_sel<=3;end
        end
        B_LOAD_PORT: state<=B_LOAD_IP;
        B_LOAD_IP: state<=B_LOAD_ALLOC;
        B_LOAD_ALLOC: begin
            if(alloc_req)alloc_sent<=1;
            if(alloc_ack)begin slot<=alloc_slot;state<=B_LOAD_COPY;end
            else if(alloc_fail)alloc_sent<=0;
        end
        B_LOAD_COPY: if(loader_out_valid) begin
            offset<=offset+1'b1;
            if(loader_out_last)begin length<=offset+1'b1;state<=B_LOAD_COMMIT;end
        end
        B_LOAD_COMMIT: if(commit)begin state<=B_SCAN;port_sel<=3;end
        default: state<=B_BOOT;
    endcase
end

// Preserve whole-frame boundaries. The internal MAC has already enforced
// BAG, but buffering can compress those gaps after an output pause. Shape
// again at the external first-byte handshake using each frame's wire VLID.
reg [7:0] prev_data;
reg prev_valid, prev_error;
reg [11:0] mac_offset;
reg [15:0] frame_vlid;
always @(posedge clk) begin
    if(reset) begin
        prev_data<=0; prev_valid<=0; prev_error<=0; mac_offset<=0; frame_vlid<=0;
    end else begin
        prev_data<=mac_data; prev_valid<=mac_valid; prev_error<=mac_error;
        if(!mac_valid) mac_offset<=0;
        else begin
            mac_offset<=mac_offset+1'b1;
            // Seven preamble bytes and SFD precede destination MAC bytes.
            if(mac_offset==12) frame_vlid[15:8]<=mac_data;
            if(mac_offset==13) frame_vlid[7:0]<=mac_data;
        end
    end
end
wire fifo_valid, fifo_last;
wire [7:0] fifo_data;
wire fifo_good, fifo_bad, fifo_overflow;
wire wire_frame_finished = fifo_good || fifo_bad || fifo_overflow;
// Reconfigure the loader VL only once no older loader descriptor can still
// consult its config. Output-buffered frames already contain their headers.
always @(posedge clk)begin
    if(reset)loader_inflight<=0;
    else begin
        if(wire_frame_finished&&frame_vlid==3)loader_inflight<=0;
        if(commit&&state==B_LOAD_COMMIT)loader_inflight<=1;
    end
end
always @(posedge clk) begin
    if(reset) pending_wire_frames<=0;
    else case({commit,wire_frame_finished})
        2'b10: pending_wire_frames<=pending_wire_frames+1'b1;
        2'b01: pending_wire_frames<=pending_wire_frames-1'b1;
        default:;
    endcase
end
// At least 72 wire bytes per frame, plus FIFO read-pipeline headroom.
// This is 128 entries with the default 8192-byte FIFO.
localparam TAG_AW = ($clog2(OUTPUT_DEPTH/72+8) > 0) ? $clog2(OUTPUT_DEPTH/72+8) : 1;
localparam TAG_DEPTH = 1 << TAG_AW;
reg [15:0] frame_tags [0:TAG_DEPTH-1];
reg [TAG_AW-1:0] tag_wptr, tag_rptr;
reg [TAG_AW:0] tag_count;
wire [15:0] head_vlid = frame_tags[tag_rptr];
wire head_vlid_valid = head_vlid != 0 && head_vlid <= N_TX_VL;
wire [6:0] head_vl_idx = head_vlid-1'b1;
reg [31:0] egress_tick;
reg [31:0] egress_next [0:N_TX_VL-1];
reg [N_TX_VL-1:0] deadline_valid;
localparam [31:0] EGRESS_BAG_TICKS = (1000000+TICK_NS-1)/TICK_NS;
wire [31:0] egress_delta = egress_tick - egress_next[head_vl_idx];
wire bag_ready = !head_vlid_valid || !deadline_valid[head_vl_idx] || !egress_delta[31];
reg [3:0] gap;
reg frame_presented, frame_started;
// Once valid is presented, latch admission even if ready stays low. This
// prevents changing valid at a timer wrap before the first-byte handshake.
wire present = tag_count!=0 && (frame_presented || (gap==0 && bag_ready));
wire pop = rx_ready && present;
wire first_fire = fifo_valid && pop && !frame_started;
wire last_fire = fifo_valid && pop && fifo_last;
integer ev;
always @(posedge clk) begin
    if(reset) begin
        gap<=0; frame_presented<=0; frame_started<=0; egress_tick<=0;
        tag_wptr<=0; tag_rptr<=0; tag_count<=0;
        deadline_valid<={N_TX_VL{1'b0}};
        for(ev=0;ev<N_TX_VL;ev=ev+1) egress_next[ev]<=0;
    end else begin
        egress_tick<=egress_tick+1'b1;
        // Expire deadlines promptly, so an idle VL remains eligible even
        // after more than half of the 32-bit timestamp range has passed.
        for(ev=0;ev<N_TX_VL;ev=ev+1)
            if(deadline_valid[ev] && ((egress_tick-egress_next[ev]) & 32'h80000000)==0)
                deadline_valid[ev]<=0;
        if(fifo_good) begin frame_tags[tag_wptr]<=frame_vlid; tag_wptr<=tag_wptr+1'b1; end
        if(last_fire) tag_rptr<=tag_rptr+1'b1;
        case({fifo_good,last_fire})
            2'b10: tag_count<=tag_count+1'b1;
            2'b01: tag_count<=tag_count-1'b1;
            default:;
        endcase
        if(fifo_valid && present) frame_presented<=1;
        if(first_fire) begin
            frame_started<=1;
            if(head_vlid_valid) begin
                egress_next[head_vl_idx]<=egress_tick+EGRESS_BAG_TICKS;
                deadline_valid[head_vl_idx]<=1;
            end
        end
        if(last_fire) begin
            gap<=12; frame_presented<=0; frame_started<=0;
        end else if(gap!=0) gap<=gap-1'b1;
    end
end
axis_fifo #(.DEPTH(OUTPUT_DEPTH), .DATA_WIDTH(8), .KEEP_ENABLE(0),
    .FRAME_FIFO(1), .DROP_OVERSIZE_FRAME(1), .DROP_BAD_FRAME(1),
    .DROP_WHEN_FULL(1)) u_wire_fifo (
    .clk(clk), .rst(reset), .s_axis_tdata(prev_data), .s_axis_tkeep(1'b1),
    .s_axis_tvalid(prev_valid), .s_axis_tready(), .s_axis_tlast(prev_valid && !mac_valid),
    .s_axis_tid(8'd0), .s_axis_tdest(8'd0), .s_axis_tuser(prev_error),
    .m_axis_tdata(fifo_data), .m_axis_tkeep(), .m_axis_tvalid(fifo_valid),
    .m_axis_tready(pop), .m_axis_tlast(fifo_last), .m_axis_tid(), .m_axis_tdest(), .m_axis_tuser(),
    .pause_req(1'b0), .pause_ack(), .status_depth(out_depth), .status_depth_commit(),
    .status_overflow(fifo_overflow), .status_bad_frame(fifo_bad), .status_good_frame(fifo_good)
);
assign tx_data=fifo_data;
assign tx_valid=fifo_valid && present;
endmodule
`default_nettype wire
