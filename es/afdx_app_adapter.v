`timescale 1ns/1ps
`default_nettype none
// Application-message adapter.  The only application payload store is the
// fixed 8192-byte array below: TX uses 0..4095 and RX uses 4096..8191.
module afdx_app_adapter #(
    parameter integer TICK_NS=8,
    parameter integer APP_MAX_BYTES=4096,
    parameter integer APP_RAM_DEPTH=8192,
    parameter integer REASSEMBLY_TIMEOUT_US=1000000,
    parameter [31:0] LOCAL_IP=32'h0a000001
) (
    input wire clk,input wire rst,
    input wire [7:0] app_tx_data,input wire app_tx_valid,output wire app_tx_ready,
    output wire [7:0] app_rx_data,output wire app_rx_valid,input wire app_rx_ready,

    output wire tx_alloc_req,input wire [3:0] tx_alloc_slot,
    input wire tx_alloc_ack,input wire tx_alloc_fail,
    output wire tx_wr_en,output wire [14:0] tx_wr_addr,output wire [7:0] tx_wr_data,
    output wire tx_commit,output wire [6:0] tx_vl,output wire [3:0] tx_slot,
    output wire [11:0] tx_len,output wire [15:0] tx_ip_id,
    output wire [12:0] tx_frag_offset,output wire tx_mf,output wire tx_first,
    output wire [15:0] tx_udp_total_len,input wire tx_commit_ready,output wire tx_busy,

    input wire [7:0] host_rx_tdata,input wire host_rx_tvalid,input wire host_rx_tlast,
    input wire host_rx_avail,output wire host_rx_ready,input wire [11:0] host_rx_flen,
    input wire [15:0] host_rx_vlid,input wire [15:0] host_rx_ip_id,
    input wire [12:0] host_rx_frag_offset,input wire host_rx_mf,input wire host_rx_first,
    input wire [15:0] host_rx_udp_total_len,input wire [15:0] host_rx_udp_checksum,
    input wire [31:0] host_rx_src_ip,input wire [15:0] host_rx_src_port,
    input wire [15:0] host_rx_dst_port,

    output reg [31:0] stat_tx_drop,output reg [31:0] stat_rx_drop,
    output reg [31:0] stat_rx_timeout,output reg [31:0] stat_rx_duplicate,
    output reg [31:0] stat_rx_busy
);

generate
if(APP_MAX_BYTES>4096 || APP_MAX_BYTES<1 || APP_RAM_DEPTH>8192 || APP_RAM_DEPTH<8192) begin: g_bad_parameters
    initial begin
        $display("ERROR afdx_app_adapter requires APP_MAX_BYTES<=4096 and APP_RAM_DEPTH=8192");
        $finish;
    end
end
endgenerate

reg [7:0] app_mem [0:8191];

// ----------------------------- TX ---------------------------------
localparam [2:0] TX_CAPTURE=3'd0,TX_ALLOC=3'd1,TX_RETRY=3'd2,
                 TX_COPY=3'd3,TX_COMMIT=3'd4;
reg [2:0] tx_state;
reg tx_in_active,tx_overflow;
reg [12:0] tx_byte_count;
reg [7:0] tx_vlid_hi,tx_vlid_lo;
reg [12:0] tx_msg_len_r,tx_frag_pos_r,tx_frag_len_r,tx_copy_count;
reg [15:0] tx_ip_id_r,tx_next_ip_id;
reg [3:0] tx_slot_r;

assign app_tx_ready=(tx_state==TX_CAPTURE);
assign tx_alloc_req=(tx_state==TX_ALLOC);
assign tx_wr_en=(tx_state==TX_COPY);
assign tx_wr_addr={tx_slot_r,11'd0}+tx_copy_count;
assign tx_wr_data=app_mem[tx_frag_pos_r+tx_copy_count];
assign tx_commit=(tx_state==TX_COMMIT);
assign tx_vl={tx_vlid_hi,tx_vlid_lo}-16'd1;
assign tx_slot=tx_slot_r;
assign tx_len=tx_frag_len_r[11:0];
assign tx_ip_id=tx_ip_id_r;
assign tx_first=(tx_frag_pos_r==0);
assign tx_frag_offset=(tx_frag_pos_r==0)?13'd0:((tx_frag_pos_r+13'd8)>>3);
assign tx_mf=(tx_frag_pos_r+tx_frag_len_r<tx_msg_len_r);
assign tx_udp_total_len=tx_msg_len_r+16'd8;
assign tx_busy=(tx_state!=TX_CAPTURE);

// ----------------------------- RX ---------------------------------
localparam [3:0] RX_IDLE=4'd0,RX_COPY=4'd1,RX_DUP=4'd2,RX_COMMIT=4'd3,
                 RX_CHECK=4'd4,RX_CSUM=4'd5,RX_DRAIN=4'd6,RX_HOLD=4'd7;
reg [3:0] rx_state;
reg ctx_active,first_seen,last_seen,output_active;
reg [15:0] ctx_vlid,ctx_ip_id,ctx_udp_len,ctx_udp_checksum;
reg [31:0] ctx_src_ip;
reg [15:0] ctx_src_port,ctx_dst_port;
reg [12:0] expected_len,final_end;
reg [31:0] ctx_start_us;
reg [2:0] range_count;
reg [12:0] range_start[0:3];
reg [12:0] range_end[0:3];
reg [12:0] pending_start,pending_end,rx_count;
reg [2:0] pending_insert;
reg pending_first,pending_mf;
reg [15:0] pending_udp_len,pending_udp_checksum,pending_src_port,pending_dst_port;
reg [12:0] out_index,out_length;
reg [31:0] csum_acc;
reg [12:0] csum_index;

localparam integer TICKS_PER_US=(1000+TICK_NS-1)/TICK_NS;
reg [15:0] us_div;
reg [31:0] now_us;

wire [15:0] rx_offset_bytes={host_rx_frag_offset,3'b000};
wire [15:0] rx_start_w=host_rx_first?16'd0:(rx_offset_bytes-16'd8);
wire [16:0] rx_end_ext={1'b0,rx_start_w}+{5'd0,host_rx_flen};
wire key_match=(host_rx_vlid==ctx_vlid)&&(host_rx_ip_id==ctx_ip_id)&&
               (host_rx_src_ip==ctx_src_ip);
wire first_meta_match=!first_seen ||
    (host_rx_udp_total_len==ctx_udp_len && host_rx_udp_checksum==ctx_udp_checksum &&
     host_rx_src_port==ctx_src_port && host_rx_dst_port==ctx_dst_port);
wire nonfinal_aligned=host_rx_first ? (((host_rx_flen+12'd8)&12'd7)==0) :
                                      ((host_rx_flen&12'd7)==0);
wire header_shape_ok=(host_rx_flen!=0)&&(host_rx_flen<=1471)&&
    ((host_rx_first&&(host_rx_frag_offset==0))||(!host_rx_first&&(host_rx_frag_offset!=0)))&&
    (rx_end_ext<=APP_MAX_BYTES)&&(!host_rx_mf||nonfinal_aligned)&&
    (!host_rx_first||((host_rx_udp_total_len>=9)&&(host_rx_udp_total_len<=APP_MAX_BYTES+8)&&
                      (rx_end_ext<=host_rx_udp_total_len-8)))&&
    (!(host_rx_first&&!host_rx_mf)||(rx_end_ext==host_rx_udp_total_len-8))&&
    (!first_seen||(rx_end_ext<=expected_len))&&
    (!(last_seen&&!host_rx_mf)||(rx_end_ext==final_end))&&
    (!(first_seen&&!host_rx_mf)||(rx_end_ext==expected_len));

integer ri;
reg scan_exact,scan_overlap;
reg [2:0] scan_insert;
always @* begin
    scan_exact=1'b0;scan_overlap=1'b0;scan_insert=0;
    for(ri=0;ri<4;ri=ri+1)begin
        if(ri<range_count)begin
            if(rx_start_w==range_start[ri]&&rx_end_ext[12:0]==range_end[ri])scan_exact=1'b1;
            else if(rx_start_w<range_end[ri]&&rx_end_ext[12:0]>range_start[ri])scan_overlap=1'b1;
            if(range_start[ri]<rx_start_w)scan_insert=scan_insert+1'b1;
        end
    end
end

reg coverage_complete,coverage_gap;
reg [12:0] coverage_end;
always @* begin
    coverage_end=0;coverage_gap=0;
    for(ri=0;ri<4;ri=ri+1)begin
        if(ri<range_count)begin
            if(range_start[ri]!=coverage_end)coverage_gap=1;
            coverage_end=range_end[ri];
        end
    end
    coverage_complete=ctx_active&&first_seen&&last_seen&&(range_count!=0)&&
                      !coverage_gap&&(coverage_end==expected_len)&&(final_end==expected_len);
end

assign host_rx_ready=!output_active&&
    (rx_state==RX_IDLE||rx_state==RX_COPY||rx_state==RX_DUP||rx_state==RX_DRAIN);
assign app_rx_valid=output_active;
assign app_rx_data=(out_index==0)?ctx_vlid[15:8]:
                   (out_index==1)?ctx_vlid[7:0]:app_mem[4096+out_index-2];

function [15:0] fold_sum;
    input [31:0] value;
    reg [31:0] t;
    begin
        t=(value&32'hffff)+(value>>16);
        t=(t&32'hffff)+(t>>16);
        t=(t&32'hffff)+(t>>16);
        fold_sum=t[15:0];
    end
endfunction

integer k;
reg [31:0] csum_next;
always @(posedge clk) begin
    if(rst)begin
        tx_state<=TX_CAPTURE;tx_in_active<=0;tx_overflow<=0;tx_byte_count<=0;
        tx_vlid_hi<=0;tx_vlid_lo<=0;tx_msg_len_r<=0;tx_frag_pos_r<=0;
        tx_frag_len_r<=0;tx_copy_count<=0;tx_ip_id_r<=0;tx_next_ip_id<=1;tx_slot_r<=0;
        rx_state<=RX_IDLE;ctx_active<=0;first_seen<=0;last_seen<=0;output_active<=0;
        ctx_vlid<=0;ctx_ip_id<=0;ctx_udp_len<=0;ctx_udp_checksum<=0;ctx_src_ip<=0;
        ctx_src_port<=0;ctx_dst_port<=0;expected_len<=0;final_end<=0;ctx_start_us<=0;
        range_count<=0;pending_start<=0;pending_end<=0;rx_count<=0;pending_insert<=0;
        pending_first<=0;pending_mf<=0;pending_udp_len<=0;pending_udp_checksum<=0;
        pending_src_port<=0;pending_dst_port<=0;out_index<=0;out_length<=0;
        csum_acc<=0;csum_index<=0;us_div<=0;now_us<=0;
        stat_tx_drop<=0;stat_rx_drop<=0;stat_rx_timeout<=0;
        stat_rx_duplicate<=0;stat_rx_busy<=0;
        for(k=0;k<4;k=k+1)begin range_start[k]<=0;range_end[k]<=0;end
    end else begin
        // Local microsecond timebase for the bounded reassembly context.
        if(us_div==TICKS_PER_US-1)begin us_div<=0;now_us<=now_us+1'b1;end
        else us_div<=us_div+1'b1;

        // Capture is deliberately complete-message-first so UDP length is known.
        case(tx_state)
        TX_CAPTURE:begin
            if(app_tx_valid&&app_tx_ready)begin
                tx_in_active<=1;
                if(tx_byte_count==0)tx_vlid_hi<=app_tx_data;
                else if(tx_byte_count==1)tx_vlid_lo<=app_tx_data;
                else if(tx_byte_count<APP_MAX_BYTES+2)app_mem[tx_byte_count-2]<=app_tx_data;
                else tx_overflow<=1;
                if(tx_byte_count<APP_MAX_BYTES+3)tx_byte_count<=tx_byte_count+1'b1;
            end else if(!app_tx_valid&&tx_in_active)begin
                tx_in_active<=0;
                if(!tx_overflow&&tx_byte_count>=3&&tx_byte_count<=APP_MAX_BYTES+2&&
                   ({tx_vlid_hi,tx_vlid_lo}>=1)&&({tx_vlid_hi,tx_vlid_lo}<=128))begin
                    tx_msg_len_r<=tx_byte_count-2;
                    tx_frag_pos_r<=0;
                    tx_frag_len_r<=((tx_byte_count-2)<=1471)?(tx_byte_count-2):13'd1464;
                    tx_ip_id_r<=tx_next_ip_id;
                    tx_next_ip_id<=(tx_next_ip_id==16'hffff)?16'd1:tx_next_ip_id+1'b1;
                    tx_state<=TX_ALLOC;
                end else begin
                    stat_tx_drop<=stat_tx_drop+1'b1;
                    tx_byte_count<=0;tx_overflow<=0;
                end
            end
        end
        TX_ALLOC:begin
            if(tx_alloc_ack)begin tx_slot_r<=tx_alloc_slot;tx_copy_count<=0;tx_state<=TX_COPY;end
            else if(tx_alloc_fail)tx_state<=TX_RETRY;
        end
        TX_RETRY:tx_state<=TX_ALLOC;
        TX_COPY:begin
            if(tx_copy_count+1>=tx_frag_len_r)begin tx_copy_count<=0;tx_state<=TX_COMMIT;end
            else tx_copy_count<=tx_copy_count+1'b1;
        end
        TX_COMMIT:if(tx_commit_ready)begin
            if(tx_frag_pos_r+tx_frag_len_r<tx_msg_len_r)begin
                tx_frag_pos_r<=tx_frag_pos_r+tx_frag_len_r;
                if(tx_msg_len_r-(tx_frag_pos_r+tx_frag_len_r)>1464)tx_frag_len_r<=1464;
                else tx_frag_len_r<=tx_msg_len_r-(tx_frag_pos_r+tx_frag_len_r);
                tx_state<=TX_ALLOC;
            end else begin
                tx_byte_count<=0;tx_overflow<=0;tx_state<=TX_CAPTURE;
            end
        end
        default:tx_state<=TX_CAPTURE;
        endcase

        // Output is a direct view of the RX half of app_mem; no output FIFO exists.
        if(output_active&&app_rx_ready)begin
            if(out_index==out_length+1)begin
                output_active<=0;ctx_active<=0;first_seen<=0;last_seen<=0;
                range_count<=0;rx_state<=RX_IDLE;out_index<=0;
            end else out_index<=out_index+1'b1;
        end

        if(ctx_active&&!output_active&&((now_us-ctx_start_us)>=REASSEMBLY_TIMEOUT_US))begin
            ctx_active<=0;first_seen<=0;last_seen<=0;range_count<=0;rx_state<=RX_IDLE;
            stat_rx_timeout<=stat_rx_timeout+1'b1;
        end else if(!output_active)begin
            case(rx_state)
            RX_IDLE:if(host_rx_tvalid&&host_rx_ready)begin
                if(ctx_active&&!key_match)begin
                    stat_rx_busy<=stat_rx_busy+1'b1;
                    rx_state<=host_rx_tlast?RX_IDLE:RX_DRAIN;
                end else if(!header_shape_ok||(host_rx_first&&!first_meta_match))begin
                    stat_rx_drop<=stat_rx_drop+1'b1;
                    if(ctx_active)begin ctx_active<=0;first_seen<=0;last_seen<=0;range_count<=0;end
                    rx_state<=host_rx_tlast?RX_IDLE:RX_DRAIN;
                end else if(scan_overlap)begin
                    stat_rx_drop<=stat_rx_drop+1'b1;
                    ctx_active<=0;first_seen<=0;last_seen<=0;range_count<=0;
                    rx_state<=host_rx_tlast?RX_IDLE:RX_DRAIN;
                end else if(scan_exact)begin
                    pending_start<=rx_start_w[12:0];pending_end<=rx_end_ext[12:0];rx_count<=1;
                    if(app_mem[4096+rx_start_w]!==host_rx_tdata)begin
                        stat_rx_drop<=stat_rx_drop+1'b1;
                        ctx_active<=0;first_seen<=0;last_seen<=0;range_count<=0;
                        rx_state<=host_rx_tlast?RX_IDLE:RX_DRAIN;
                    end else if(host_rx_tlast)begin
                        if(host_rx_flen==1)begin stat_rx_duplicate<=stat_rx_duplicate+1'b1;rx_state<=RX_CHECK;end
                        else begin stat_rx_drop<=stat_rx_drop+1'b1;ctx_active<=0;range_count<=0;rx_state<=RX_IDLE;end
                    end else rx_state<=RX_DUP;
                end else if(range_count>=4)begin
                    stat_rx_drop<=stat_rx_drop+1'b1;
                    ctx_active<=0;first_seen<=0;last_seen<=0;range_count<=0;
                    rx_state<=host_rx_tlast?RX_IDLE:RX_DRAIN;
                end else begin
                    if(!ctx_active)begin
                        ctx_active<=1;ctx_vlid<=host_rx_vlid;ctx_ip_id<=host_rx_ip_id;
                        ctx_src_ip<=host_rx_src_ip;ctx_start_us<=now_us;
                    end
                    pending_start<=rx_start_w[12:0];pending_end<=rx_end_ext[12:0];
                    pending_insert<=scan_insert;pending_first<=host_rx_first;pending_mf<=host_rx_mf;
                    pending_udp_len<=host_rx_udp_total_len;pending_udp_checksum<=host_rx_udp_checksum;
                    pending_src_port<=host_rx_src_port;pending_dst_port<=host_rx_dst_port;
                    app_mem[4096+rx_start_w]<=host_rx_tdata;rx_count<=1;
                    if(host_rx_tlast)begin
                        if(host_rx_flen==1)rx_state<=RX_COMMIT;
                        else begin stat_rx_drop<=stat_rx_drop+1'b1;ctx_active<=0;range_count<=0;rx_state<=RX_IDLE;end
                    end else rx_state<=RX_COPY;
                end
            end
            RX_COPY:if(host_rx_tvalid&&host_rx_ready)begin
                if(rx_count>=pending_end-pending_start)begin
                    stat_rx_drop<=stat_rx_drop+1'b1;ctx_active<=0;range_count<=0;
                    rx_state<=host_rx_tlast?RX_IDLE:RX_DRAIN;
                end else begin
                    app_mem[4096+pending_start+rx_count]<=host_rx_tdata;
                    if(host_rx_tlast)begin
                        if(rx_count+1==pending_end-pending_start)rx_state<=RX_COMMIT;
                        else begin stat_rx_drop<=stat_rx_drop+1'b1;ctx_active<=0;range_count<=0;rx_state<=RX_IDLE;end
                    end
                    rx_count<=rx_count+1'b1;
                end
            end
            RX_DUP:if(host_rx_tvalid&&host_rx_ready)begin
                if(rx_count>=pending_end-pending_start||
                   app_mem[4096+pending_start+rx_count]!==host_rx_tdata)begin
                    stat_rx_drop<=stat_rx_drop+1'b1;ctx_active<=0;first_seen<=0;last_seen<=0;range_count<=0;
                    rx_state<=host_rx_tlast?RX_IDLE:RX_DRAIN;
                end else if(host_rx_tlast)begin
                    if(rx_count+1==pending_end-pending_start)begin
                        stat_rx_duplicate<=stat_rx_duplicate+1'b1;rx_state<=RX_CHECK;
                    end else begin stat_rx_drop<=stat_rx_drop+1'b1;ctx_active<=0;range_count<=0;rx_state<=RX_IDLE;end
                    rx_count<=rx_count+1'b1;
                end else rx_count<=rx_count+1'b1;
            end
            RX_COMMIT:begin
                case(pending_insert)
                0:begin range_start[3]<=range_start[2];range_end[3]<=range_end[2];
                        range_start[2]<=range_start[1];range_end[2]<=range_end[1];
                        range_start[1]<=range_start[0];range_end[1]<=range_end[0];
                        range_start[0]<=pending_start;range_end[0]<=pending_end;end
                1:begin range_start[3]<=range_start[2];range_end[3]<=range_end[2];
                        range_start[2]<=range_start[1];range_end[2]<=range_end[1];
                        range_start[1]<=pending_start;range_end[1]<=pending_end;end
                2:begin range_start[3]<=range_start[2];range_end[3]<=range_end[2];
                        range_start[2]<=pending_start;range_end[2]<=pending_end;end
                default:begin range_start[3]<=pending_start;range_end[3]<=pending_end;end
                endcase
                range_count<=range_count+1'b1;
                if(pending_first)begin
                    first_seen<=1;ctx_udp_len<=pending_udp_len;expected_len<=pending_udp_len-8;
                    ctx_udp_checksum<=pending_udp_checksum;ctx_src_port<=pending_src_port;
                    ctx_dst_port<=pending_dst_port;
                end
                if(!pending_mf)begin last_seen<=1;final_end<=pending_end;end
                rx_state<=RX_CHECK;
            end
            RX_CHECK:begin
                if(first_seen&&last_seen&&expected_len!=final_end)begin
                    stat_rx_drop<=stat_rx_drop+1'b1;ctx_active<=0;first_seen<=0;last_seen<=0;
                    range_count<=0;rx_state<=RX_IDLE;
                end else if(coverage_complete)begin
                    if(ctx_udp_checksum==0)begin
                        output_active<=1;out_index<=0;out_length<=expected_len;rx_state<=RX_HOLD;
                    end else begin
                        csum_acc<=ctx_src_ip[31:16]+ctx_src_ip[15:0]+LOCAL_IP[31:16]+LOCAL_IP[15:0]+
                                  16'd17+ctx_udp_len+ctx_src_port+ctx_dst_port+ctx_udp_len+ctx_udp_checksum;
                        csum_index<=0;rx_state<=RX_CSUM;
                    end
                end else rx_state<=RX_IDLE;
            end
            RX_CSUM:begin
                csum_next=csum_acc+{app_mem[4096+csum_index],
                    ((csum_index+1)<expected_len)?app_mem[4096+csum_index+1]:8'd0};
                if(csum_index+2>=expected_len)begin
                    if(fold_sum(csum_next)==16'hffff)begin
                        output_active<=1;out_index<=0;out_length<=expected_len;rx_state<=RX_HOLD;
                    end else begin
                        stat_rx_drop<=stat_rx_drop+1'b1;ctx_active<=0;first_seen<=0;
                        last_seen<=0;range_count<=0;rx_state<=RX_IDLE;
                    end
                end else begin csum_acc<=csum_next;csum_index<=csum_index+2;end
            end
            RX_DRAIN:if(host_rx_tvalid&&host_rx_ready&&host_rx_tlast)rx_state<=RX_IDLE;
            default:;
            endcase
        end
    end
end
endmodule
`default_nettype wire
