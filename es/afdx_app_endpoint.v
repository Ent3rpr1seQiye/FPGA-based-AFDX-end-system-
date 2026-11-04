`timescale 1ns/1ps
`default_nettype none
module afdx_app_endpoint #(
    parameter integer TICK_NS=8,APP_MAX_BYTES=4096,APP_RAM_DEPTH=8192,
    parameter integer REASSEMBLY_TIMEOUT_US=1000000,
    parameter [31:0] LOCAL_IP=32'h0a000001,PEER_IP=32'h0a000002,
    parameter ENABLE_SERVICES=0,ENABLE_TIME_SYNC=1,TIME_MASTER=0,
    parameter integer TIME_POLL_US=8000,TIME_TIMEOUT_US=4000,
    parameter [31:0] RTC_INITIAL_SEC=0,RTC_INITIAL_NS=0,
    parameter integer RTC_RATE_PPB=0,LOADER_IMAGE_BYTES=4096
) (
    input wire clk,input wire rst,
    input wire [7:0] app_tx_data,input wire app_tx_valid,output wire app_tx_ready,
    output wire [7:0] app_rx_data,output wire app_rx_valid,input wire app_rx_ready,
    input wire [7:0] gmii_a_rxd,input wire gmii_a_rx_dv,input wire gmii_a_rx_er,
    output wire [7:0] gmii_a_txd,output wire gmii_a_tx_en,output wire gmii_a_tx_er,
    input wire [7:0] gmii_b_rxd,input wire gmii_b_rx_dv,input wire gmii_b_rx_er,
    output wire [7:0] gmii_b_txd,output wire gmii_b_tx_en,output wire gmii_b_tx_er,
    output reg boot_done
);
localparam integer N_TX_VL=128,N_RX_VL=4096,N_RX_PORT=64;
localparam integer TX_WORDS=N_TX_VL*4,RX_WORDS=N_RX_VL*2;
localparam integer BOOT_LOCAL=1+TX_WORDS+RX_WORDS,BOOT_ENABLE=BOOT_LOCAL+1;
reg [14:0] boot_count;
reg [19:0] boot_cfg_addr;
reg [31:0] boot_cfg_data;
wire boot_cfg_wen=!boot_done;
wire [14:0] tx_boot_offset=boot_count-1;
wire [14:0] rx_boot_offset=boot_count-(TX_WORDS+1);
always @* begin
    boot_cfg_addr=20'h00006;boot_cfg_data=0;
    if(boot_count==0)begin boot_cfg_addr=20'h00006;boot_cfg_data=0;end
    else if(boot_count<=TX_WORDS)begin
        boot_cfg_addr=20'h01000+tx_boot_offset;
        case(tx_boot_offset[1:0])
        0:boot_cfg_data=32'h80000000+((tx_boot_offset>>2)+1);
        1:begin
            if((tx_boot_offset>>2)==0)
                boot_cfg_data=ENABLE_SERVICES?{16'd161,16'd40000}:{16'd40000,16'd161};
            else if((tx_boot_offset>>2)==1)boot_cfg_data={16'd55000,16'd55000};
            else if((tx_boot_offset>>2)==2)boot_cfg_data={16'd40000,16'd69};
            else boot_cfg_data={16'h1234,16'h5678};
        end
        2:boot_cfg_data=PEER_IP;
        default:boot_cfg_data=0;
        endcase
    end else if(boot_count<=TX_WORDS+RX_WORDS)begin
        boot_cfg_addr=20'h02000+rx_boot_offset;
        if(!rx_boot_offset[0])
            boot_cfg_data=32'hc0000000|(((rx_boot_offset>>1)%N_RX_PORT)<<16)|((rx_boot_offset>>1)+1);
        else if((rx_boot_offset>>1)==0)boot_cfg_data=ENABLE_SERVICES?16'd161:16'd40000;
        else if((rx_boot_offset>>1)==1)boot_cfg_data=16'd55000;
        else if((rx_boot_offset>>1)==2)boot_cfg_data=0;
        else boot_cfg_data=32'h00005678;
    end else if(boot_count==BOOT_LOCAL)begin boot_cfg_addr=20'h00003;boot_cfg_data=LOCAL_IP;end
    else begin boot_cfg_addr=20'h00006;boot_cfg_data=3;end
end
always @(posedge clk)begin
    if(rst)begin boot_count<=0;boot_done<=0;end
    else if(!boot_done)begin
        if(boot_count==BOOT_ENABLE)boot_done<=1;
        else boot_count<=boot_count+1'b1;
    end
end
wire rtc_boot_set=!boot_done&&(boot_count==BOOT_ENABLE);

// Application adapter side of the shared core host interface.
wire ad_tx_ready,ad_tx_busy,ad_alloc_req,ad_wr_en,ad_commit;
wire [14:0] ad_wr_addr;wire [7:0] ad_wr_data;wire [6:0] ad_commit_vl;
wire [3:0] ad_commit_slot;wire [11:0] ad_commit_len;
wire [15:0] ad_commit_ip_id,ad_commit_udp_len;wire [12:0] ad_commit_off;
wire ad_commit_mf,ad_commit_first;
wire [3:0] core_alloc_slot;wire core_alloc_ack,core_alloc_fail,core_commit_ready;
assign app_tx_ready=boot_done&&ad_tx_ready;

// Core RX descriptor and scanner.
reg [5:0] port_sel;
wire [7:0] host_data;wire host_valid,host_last,host_avail;wire [11:0] host_len;
wire [5:0] host_frame_port;wire [15:0] host_vlid,host_ip_id,host_udp_len,host_udp_checksum;
wire [12:0] host_frag_offset;wire host_mf,host_first;wire [31:0] host_src_ip;
wire [15:0] host_src_port,host_dst_port;
wire ad_host_ready;
wire route_snmp=ENABLE_SERVICES&&(host_frame_port==0);
wire route_time=ENABLE_TIME_SYNC&&(host_frame_port==1);
wire route_loader=ENABLE_SERVICES&&(host_frame_port==2);
wire route_app=!(route_snmp||route_time||route_loader);

// Service protocol streams.
wire snmp_in_ready,snmp_out_valid,snmp_out_last,snmp_busy;wire [7:0] snmp_out_data;
wire [19:0] snmp_stats_addr;wire [31:0] core_cfg_rdata;
wire time_in_ready,time_out_valid,time_out_last,time_busy;wire [7:0] time_out_data;
wire time_set_valid,time_synced,time_sync_pulse;wire [31:0] time_set_sec,time_set_ns;
wire [31:0] time_applied,time_rejected,time_timeout;wire signed [63:0] time_offset_ns;
wire [63:0] time_delay_ns;
wire [31:0] rtc_sec,rtc_ns,tick_us;wire rtc_pps;
wire loader_in_ready,loader_out_valid,loader_out_last;wire [7:0] loader_out_data;
wire [31:0] loader_out_ip;wire [15:0] loader_out_sport,loader_out_dport;
wire [3:0] loader_state;wire [15:0] loader_status;wire [7:0] loader_progress;
wire loader_image_valid;wire [12:0] loader_image_size;wire [31:0] loader_image_crc;
wire [31:0] loader_success,loader_failure,loader_retries,loader_errors;

wire core_host_ready=route_snmp?snmp_in_ready:(route_time?time_in_ready:
                         (route_loader?loader_in_ready:ad_host_ready));
always @(posedge clk)begin
    if(rst)port_sel<=0;
    else if(boot_done&&(!host_avail||(host_valid&&core_host_ready&&host_last)))
        port_sel<=(port_sel==N_RX_PORT-1)?0:port_sel+1'b1;
end

// A complete service response owns the host TX interface until commit.
localparam [2:0] SV_IDLE=0,SV_CFG1=1,SV_CFG2=2,SV_ALLOC=3,SV_COPY=4,SV_COMMIT=5,SV_WAIT=6;
localparam [1:0] K_TIME=0,K_LOAD=1,K_SNMP=2;
reg [2:0] svc_state;reg [1:0] svc_kind;reg [3:0] svc_slot;
reg [11:0] svc_offset,svc_length;reg [31:0] svc_ip;reg [15:0] svc_sport,svc_dport;
wire svc_active=(svc_state!=SV_IDLE);
wire svc_stream_valid=(svc_kind==K_TIME)?time_out_valid:
                      ((svc_kind==K_LOAD)?loader_out_valid:snmp_out_valid);
wire svc_stream_last=(svc_kind==K_TIME)?time_out_last:
                     ((svc_kind==K_LOAD)?loader_out_last:snmp_out_last);
wire [7:0] svc_stream_data=(svc_kind==K_TIME)?time_out_data:
                           ((svc_kind==K_LOAD)?loader_out_data:snmp_out_data);
wire svc_copy_ready=(svc_state==SV_COPY);
wire time_out_ready=svc_copy_ready&&(svc_kind==K_TIME);
wire loader_out_ready=svc_copy_ready&&(svc_kind==K_LOAD);
wire snmp_out_ready=svc_copy_ready&&(svc_kind==K_SNMP);
wire svc_cfg_wen=(svc_state==SV_CFG1)||(svc_state==SV_CFG2);
wire [19:0] svc_cfg_addr=(svc_state==SV_CFG1)?20'h01009:20'h0100a;
wire [31:0] svc_cfg_data=(svc_state==SV_CFG1)?{svc_sport,svc_dport}:svc_ip;

always @(posedge clk)begin
    if(rst)begin svc_state<=SV_IDLE;svc_kind<=0;svc_slot<=0;svc_offset<=0;svc_length<=0;
        svc_ip<=0;svc_sport<=0;svc_dport<=0;end
    else case(svc_state)
    SV_IDLE:if(boot_done&&!ad_tx_busy)begin
        if(time_out_valid)begin svc_kind<=K_TIME;svc_offset<=0;svc_state<=SV_ALLOC;end
        else if(loader_out_valid)begin svc_kind<=K_LOAD;svc_offset<=0;svc_ip<=loader_out_ip;
            svc_sport<=loader_out_sport;svc_dport<=loader_out_dport;svc_state<=SV_CFG1;end
        else if(snmp_out_valid)begin svc_kind<=K_SNMP;svc_offset<=0;svc_state<=SV_ALLOC;end
    end
    SV_CFG1:svc_state<=SV_CFG2;
    SV_CFG2:svc_state<=SV_ALLOC;
    SV_ALLOC:begin
        if(core_alloc_ack)begin svc_slot<=core_alloc_slot;svc_offset<=0;svc_state<=SV_COPY;end
        else if(core_alloc_fail)svc_state<=SV_WAIT;
    end
    SV_WAIT:svc_state<=SV_ALLOC;
    SV_COPY:if(svc_stream_valid)begin
        svc_offset<=svc_offset+1'b1;
        if(svc_stream_last)begin svc_length<=svc_offset+1'b1;svc_state<=SV_COMMIT;end
    end
    SV_COMMIT:if(core_commit_ready)svc_state<=SV_IDLE;
    default:svc_state<=SV_IDLE;
    endcase
end

wire core_alloc_req=svc_active?(svc_state==SV_ALLOC):ad_alloc_req;
wire core_wr_en=svc_active?(svc_state==SV_COPY&&svc_stream_valid):ad_wr_en;
wire [14:0] core_wr_addr=svc_active?({svc_slot,11'd0}+svc_offset):ad_wr_addr;
wire [7:0] core_wr_data=svc_active?svc_stream_data:ad_wr_data;
wire core_commit=svc_active?(svc_state==SV_COMMIT):ad_commit;
wire [6:0] core_commit_vl=svc_active?((svc_kind==K_TIME)?7'd1:((svc_kind==K_LOAD)?7'd2:7'd0)):ad_commit_vl;
wire [3:0] core_commit_slot=svc_active?svc_slot:ad_commit_slot;
wire [11:0] core_commit_len=svc_active?svc_length:ad_commit_len;
wire [15:0] core_commit_ip_id=svc_active?16'd0:ad_commit_ip_id;
wire [12:0] core_commit_off=svc_active?13'd0:ad_commit_off;
wire core_commit_mf=svc_active?1'b0:ad_commit_mf;
wire core_commit_first=svc_active?1'b1:ad_commit_first;
wire [15:0] core_commit_udp_len=svc_active?({4'd0,svc_length}+16'd8):ad_commit_udp_len;

afdx_app_adapter #(.TICK_NS(TICK_NS),.APP_MAX_BYTES(APP_MAX_BYTES),.APP_RAM_DEPTH(APP_RAM_DEPTH),
    .REASSEMBLY_TIMEOUT_US(REASSEMBLY_TIMEOUT_US),.LOCAL_IP(LOCAL_IP)) u_adapter(
    .clk(clk),.rst(rst),.app_tx_data(app_tx_data),.app_tx_valid(app_tx_valid&&boot_done),
    .app_tx_ready(ad_tx_ready),.app_rx_data(app_rx_data),.app_rx_valid(app_rx_valid),.app_rx_ready(app_rx_ready),
    .tx_alloc_req(ad_alloc_req),.tx_alloc_slot(core_alloc_slot),
    .tx_alloc_ack(core_alloc_ack&&!svc_active),.tx_alloc_fail(core_alloc_fail&&!svc_active),
    .tx_wr_en(ad_wr_en),.tx_wr_addr(ad_wr_addr),.tx_wr_data(ad_wr_data),
    .tx_commit(ad_commit),.tx_vl(ad_commit_vl),.tx_slot(ad_commit_slot),.tx_len(ad_commit_len),
    .tx_ip_id(ad_commit_ip_id),.tx_frag_offset(ad_commit_off),.tx_mf(ad_commit_mf),
    .tx_first(ad_commit_first),.tx_udp_total_len(ad_commit_udp_len),
    .tx_commit_ready(core_commit_ready&&!svc_active),.tx_busy(ad_tx_busy),
    .host_rx_tdata(host_data),.host_rx_tvalid(host_valid&&boot_done&&route_app),.host_rx_tlast(host_last),
    .host_rx_avail(host_avail&&route_app),.host_rx_ready(ad_host_ready),.host_rx_flen(host_len),
    .host_rx_vlid(host_vlid),.host_rx_ip_id(host_ip_id),.host_rx_frag_offset(host_frag_offset),
    .host_rx_mf(host_mf),.host_rx_first(host_first),.host_rx_udp_total_len(host_udp_len),
    .host_rx_udp_checksum(host_udp_checksum),.host_rx_src_ip(host_src_ip),
    .host_rx_src_port(host_src_port),.host_rx_dst_port(host_dst_port),
    .stat_tx_drop(),.stat_rx_drop(),.stat_rx_timeout(),.stat_rx_duplicate(),.stat_rx_busy());

generate if(ENABLE_SERVICES)begin:g_services
 afdx_snmp_agent #(.MAX_PACKET(1471),.TICK_NS(TICK_NS),.N_TX_VL(N_TX_VL),.N_RX_VL(N_RX_VL)) u_snmp(
  .clk(clk),.rst(rst),.s_data(host_data),.s_valid(host_valid&&route_snmp),.s_ready(snmp_in_ready),
  .s_last(host_last),.m_data(snmp_out_data),.m_valid(snmp_out_valid),.m_ready(snmp_out_ready),
  .m_last(snmp_out_last),.busy(snmp_busy),.stats_addr(snmp_stats_addr),.stats_data(core_cfg_rdata));
 afdx_loader #(.IMAGE_BYTES(LOADER_IMAGE_BYTES)) u_loader(
  .clk(clk),.rst(rst),.enable(boot_done),.tick_us(tick_us),
  .s_data(host_data),.s_valid(host_valid&&route_loader),.s_last(host_last),.s_ready(loader_in_ready),
  .s_src_ip(host_src_ip),.s_src_port(host_src_port),.s_dst_port(host_dst_port),
  .m_data(loader_out_data),.m_valid(loader_out_valid),.m_last(loader_out_last),.m_ready(loader_out_ready),
  .m_dst_ip(loader_out_ip),.m_src_port(loader_out_sport),.m_dst_port(loader_out_dport),
  .load_state(loader_state),.operation_status(loader_status),.progress(loader_progress),
  .image_valid(loader_image_valid),.image_size(loader_image_size),.image_crc(loader_image_crc),
  .stat_success(loader_success),.stat_failure(loader_failure),.stat_retries(loader_retries),.stat_errors(loader_errors));
end else begin:g_no_services
 assign snmp_in_ready=0;assign snmp_out_valid=0;assign snmp_out_last=0;assign snmp_out_data=0;
 assign snmp_busy=0;assign snmp_stats_addr=0;assign loader_in_ready=0;assign loader_out_valid=0;
 assign loader_out_last=0;assign loader_out_data=0;assign loader_out_ip=0;assign loader_out_sport=0;
 assign loader_out_dport=0;assign loader_state=0;assign loader_status=0;assign loader_progress=0;
 assign loader_image_valid=0;assign loader_image_size=0;assign loader_image_crc=0;assign loader_success=0;
 assign loader_failure=0;assign loader_retries=0;assign loader_errors=0;
end endgenerate

generate if(ENABLE_TIME_SYNC)begin:g_time
 afdx_time_sync #(.IS_MASTER(TIME_MASTER),.TICK_NS(TICK_NS),.POLL_US(TIME_POLL_US),
  .TIMEOUT_US(TIME_TIMEOUT_US),.NODE_ID(TIME_MASTER?2:1)) u_time(
  .clk(clk),.rst(rst),.enable(boot_done),.rtc_sec(rtc_sec),.rtc_ns(rtc_ns),.tick_us(tick_us),
  .s_data(host_data),.s_valid(host_valid&&route_time),.s_last(host_last),.s_ready(time_in_ready),
  .m_data(time_out_data),.m_valid(time_out_valid),.m_last(time_out_last),.m_ready(time_out_ready),
  .busy(time_busy),.set_valid(time_set_valid),.set_sec(time_set_sec),.set_ns(time_set_ns),
  .synced(time_synced),.sync_pulse(time_sync_pulse),.last_offset_ns(time_offset_ns),
  .last_delay_ns(time_delay_ns),.stat_applied(time_applied),.stat_rejected(time_rejected),.stat_timeout(time_timeout));
end else begin:g_no_time
 assign time_in_ready=0;assign time_out_valid=0;assign time_out_last=0;assign time_out_data=0;
 assign time_busy=0;assign time_set_valid=0;assign time_set_sec=0;assign time_set_ns=0;
 assign time_synced=0;assign time_sync_pulse=0;assign time_offset_ns=0;assign time_delay_ns=0;
 assign time_applied=0;assign time_rejected=0;assign time_timeout=0;
end endgenerate

wire [19:0] core_cfg_addr=boot_cfg_wen?boot_cfg_addr:(svc_cfg_wen?svc_cfg_addr:snmp_stats_addr);
wire [31:0] core_cfg_data=boot_cfg_wen?boot_cfg_data:svc_cfg_data;
wire core_cfg_wen=boot_cfg_wen||svc_cfg_wen;
afdx_es #(.N_TX_VL(N_TX_VL),.N_RX_VL(N_RX_VL),.N_RX_PORT(N_RX_PORT),
 .N_SLOTS(4),.N_RX_SLOT(4),.TICK_NS(TICK_NS),.RTC_RATE_PPB(RTC_RATE_PPB),.RX_ELASTIC_DEPTH(4096)) u_core(
 .clk(clk),.rst(rst),.gmii_a_rxd(gmii_a_rxd),.gmii_a_rx_dv(gmii_a_rx_dv),.gmii_a_rx_er(gmii_a_rx_er),
 .gmii_a_txd(gmii_a_txd),.gmii_a_tx_en(gmii_a_tx_en),.gmii_a_tx_er(gmii_a_tx_er),
 .gmii_b_rxd(gmii_b_rxd),.gmii_b_rx_dv(gmii_b_rx_dv),.gmii_b_rx_er(gmii_b_rx_er),
 .gmii_b_txd(gmii_b_txd),.gmii_b_tx_en(gmii_b_tx_en),.gmii_b_tx_er(gmii_b_tx_er),
 .host_tx_alloc_req(core_alloc_req),.host_tx_alloc_slot(core_alloc_slot),
 .host_tx_alloc_ack(core_alloc_ack),.host_tx_alloc_fail(core_alloc_fail),
 .host_tx_wr_en(core_wr_en),.host_tx_wr_addr(core_wr_addr),.host_tx_wr_data(core_wr_data),
 .host_tx_commit(core_commit),.host_tx_vl(core_commit_vl),.host_tx_slot(core_commit_slot),
 .host_tx_len(core_commit_len),.host_tx_ip_id(core_commit_ip_id),.host_tx_frag_offset(core_commit_off),
 .host_tx_mf(core_commit_mf),.host_tx_first(core_commit_first),.host_tx_udp_total_len(core_commit_udp_len),
 .host_tx_commit_ready(core_commit_ready),.host_rx_port(port_sel),.host_rx_ready(boot_done&&core_host_ready),
 .host_rx_tdata(host_data),.host_rx_tvalid(host_valid),.host_rx_tlast(host_last),.host_rx_avail(host_avail),
 .host_rx_flen(host_len),.host_rx_frame_port(host_frame_port),.host_rx_vlid(host_vlid),
 .host_rx_ip_id(host_ip_id),.host_rx_frag_offset(host_frag_offset),.host_rx_mf(host_mf),
 .host_rx_first(host_first),.host_rx_udp_total_len(host_udp_len),.host_rx_udp_checksum(host_udp_checksum),
 .host_rx_src_ip(host_src_ip),.host_rx_src_port(host_src_port),.host_rx_dst_port(host_dst_port),
 .cfg_wen(core_cfg_wen),.cfg_addr(core_cfg_addr),.cfg_wdata(core_cfg_data),
 .cfg_rtc_op(2'd0),.cfg_rtc_wen(1'b0),.cfg_rdata(core_cfg_rdata),
 .rtc_adj_valid(1'b0),.rtc_adj_sign(1'b0),.rtc_adj_ns(0),
 .rtc_set_valid(rtc_boot_set||time_set_valid),.rtc_set_sec(rtc_boot_set?RTC_INITIAL_SEC:time_set_sec),
 .rtc_set_ns(rtc_boot_set?RTC_INITIAL_NS:time_set_ns),.rtc_sec(rtc_sec),.rtc_ns(rtc_ns),
 .tick_us(tick_us),.rtc_pps(rtc_pps));
endmodule
`default_nettype wire
