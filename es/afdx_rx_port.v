`timescale 1ns / 1ps
`default_nettype none
// Shared receive pool with per-port queuing or latest-pending sampling data.
// A presented host frame owns its slot until its final AXIS handshake; a
// sampling update replaces only a descriptor which has not been presented.
module afdx_rx_port #(
    parameter N_PORTS=8, N_SLOTS=8, SLOT_B=2048, Q_DEPTH=4
) (
    input wire clk, rst,
    input wire dlv_valid,
    output wire dlv_ready,
    input wire dlv_net,
    input wire [5:0] dlv_port,
    input wire dlv_type,
    input wire [11:0] dlv_len,
    input wire [15:0] dlv_vlid,
    input wire [15:0] dlv_ip_id,
    input wire [12:0] dlv_frag_offset,
    input wire dlv_mf,dlv_first,
    input wire [15:0] dlv_udp_total_len,dlv_udp_checksum,
    input wire [31:0] dlv_src_ip,
    input wire [15:0] dlv_sport, dlv_dport,
    input wire [7:0] a_buf_tdata,
    input wire a_buf_tvalid,
    output wire a_buf_tready,
    input wire a_buf_tlast,
    input wire [7:0] b_buf_tdata,
    input wire b_buf_tvalid,
    output wire b_buf_tready,
    input wire b_buf_tlast,
    input wire [5:0] host_port,
    input wire host_ready,
    output wire [7:0] host_tdata,
    output wire host_tvalid, host_tlast, host_avail,
    output wire [11:0] host_flen,
    output wire [5:0] host_frame_port,
    output wire [15:0] host_vlid,
    output wire [15:0] host_ip_id,
    output wire [12:0] host_frag_offset,
    output wire host_mf,host_first,
    output wire [15:0] host_udp_total_len,host_udp_checksum,
    output wire [31:0] host_src_ip,
    output wire [15:0] host_src_port, host_dst_port,
    output reg [31:0] stat_qfull_drop, stat_deliver
);
localparam S_IDLE=2'd0, S_COPY=2'd1, S_PUSH=2'd2;
localparam QDW=(Q_DEPTH > 1) ? $clog2(Q_DEPTH) : 1;
localparam FDW=(N_SLOTS > 1) ? $clog2(N_SLOTS) : 1;
reg [7:0] pool [0:N_SLOTS*SLOT_B-1];
reg [3:0] free_mem [0:N_SLOTS-1];
reg [FDW-1:0] free_wptr, free_rptr;
reg [4:0] free_cnt;
reg [15:0] desc_mem [0:N_PORTS*Q_DEPTH-1];
reg [31:0] slot_src_ip [0:N_SLOTS-1];
reg [15:0] slot_vlid [0:N_SLOTS-1];
reg [15:0] slot_ip_id [0:N_SLOTS-1];
reg [12:0] slot_frag_offset [0:N_SLOTS-1];
reg slot_mf [0:N_SLOTS-1],slot_first [0:N_SLOTS-1];
reg [15:0] slot_udp_total_len [0:N_SLOTS-1],slot_udp_checksum [0:N_SLOTS-1];
reg [15:0] slot_src_port [0:N_SLOTS-1], slot_dst_port [0:N_SLOTS-1];
reg [QDW-1:0] p_head [0:N_PORTS-1], p_tail [0:N_PORTS-1];
reg [QDW:0] p_cnt [0:N_PORTS-1];
function [QDW-1:0] q_next;
    input [QDW-1:0] ptr;
    begin q_next=(ptr == Q_DEPTH-1) ? 0 : ptr+1'b1; end
endfunction
function [FDW-1:0] f_next;
    input [FDW-1:0] ptr;
    begin f_next=(ptr == N_SLOTS-1) ? 0 : ptr+1'b1; end
endfunction
reg [1:0] state;
reg [5:0] port_r;
reg type_r, net_r, drop_r, allocated_r;
reg [11:0] len_r, cp_cnt;
reg [3:0] slot_r;
reg h_active;
reg [5:0] h_port;
reg [3:0] h_slot;
reg [11:0] h_len, h_rd_cnt;
wire sel_valid=(host_port < N_PORTS);
wire [15:0] head_desc=sel_valid ? desc_mem[host_port*Q_DEPTH+p_head[host_port]] : 16'd0;
wire pending=sel_valid && (p_cnt[host_port] != 0);
// Empty payloads expose metadata but no AXIS byte. Consume them when the
// host is ready, without underflowing a length counter.
wire h_start=!h_active && pending && ((head_desc[11:0] != 0) || host_ready);
wire h_done=h_active && host_ready && host_tlast;
wire h_empty=h_start && (head_desc[11:0] == 0);
assign host_avail=h_active || pending;
assign host_flen=h_active ? h_len : (pending ? head_desc[11:0] : 12'd0);
// A prefetched frame retains its original port while host_port scans.
assign host_frame_port=h_active ? h_port : host_port;
wire [3:0] metadata_slot=h_active ? h_slot : head_desc[15:12];
assign host_vlid=host_avail ? slot_vlid[metadata_slot] : 16'd0;
assign host_ip_id=host_avail ? slot_ip_id[metadata_slot] : 16'd0;
assign host_frag_offset=host_avail ? slot_frag_offset[metadata_slot] : 13'd0;
assign host_mf=host_avail ? slot_mf[metadata_slot] : 1'b0;
assign host_first=host_avail ? slot_first[metadata_slot] : 1'b1;
assign host_udp_total_len=host_avail ? slot_udp_total_len[metadata_slot] : 16'd0;
assign host_udp_checksum=host_avail ? slot_udp_checksum[metadata_slot] : 16'd0;
assign host_src_ip=host_avail ? slot_src_ip[metadata_slot] : 32'd0;
assign host_src_port=host_avail ? slot_src_port[metadata_slot] : 16'd0;
assign host_dst_port=host_avail ? slot_dst_port[metadata_slot] : 16'd0;
assign host_tvalid=h_active;
assign host_tdata=h_active ? pool[h_slot*SLOT_B+h_rd_cnt] : 8'd0;
assign host_tlast=h_active && (h_rd_cnt == h_len-1'b1);
wire dlv_port_valid=(dlv_port < N_PORTS);
wire queue_full=dlv_port_valid && dlv_type &&
    (p_cnt[dlv_port]+((h_active && h_port == dlv_port) ? 1 : 0) >= Q_DEPTH) &&
    !(h_done && h_port == dlv_port) && !(h_empty && host_port == dlv_port);
wire reject_delivery=!dlv_port_valid || queue_full || free_cnt == 0 || dlv_len > SLOT_B;
assign dlv_ready=(state == S_IDLE);
wire allocate=dlv_ready && dlv_valid && !reject_delivery;
wire [7:0] src_data=net_r ? b_buf_tdata : a_buf_tdata;
wire src_valid=net_r ? b_buf_tvalid : a_buf_tvalid;
wire src_last=net_r ? b_buf_tlast : a_buf_tlast;
assign a_buf_tready=(state == S_COPY) && !net_r;
assign b_buf_tready=(state == S_COPY) && net_r;
wire src_fire=(state == S_COPY) && src_valid;
wire push=(state == S_PUSH) && !drop_r;
wire pop_same=h_start && (host_port == port_r);
wire replace_pending=push && !type_r && (p_cnt[port_r] > (pop_same ? 1 : 0));
wire [QDW-1:0] replace_index=pop_same ? q_next(p_head[port_r]) : p_head[port_r];
wire return_copy=(state == S_PUSH) && ((drop_r && allocated_r) || replace_pending);
wire [3:0] return_copy_slot=drop_r ? slot_r : desc_mem[port_r*Q_DEPTH+replace_index][15:12];
wire return_host=h_done || h_empty;
wire [3:0] return_host_slot=h_done ? h_slot : head_desc[15:12];
integer i;
always @(posedge clk) begin
    if (rst) begin
        state<=S_IDLE; port_r<=0; type_r<=0; net_r<=0;
        drop_r<=0; allocated_r<=0; len_r<=0; cp_cnt<=0; slot_r<=0;
        h_active<=0; h_port<=0; h_slot<=0; h_len<=0; h_rd_cnt<=0;
        stat_qfull_drop<=0; stat_deliver<=0;
        free_wptr<=0; free_rptr<=0; free_cnt<=N_SLOTS;
        for (i=0;i<N_SLOTS;i=i+1) free_mem[i]<=i;
        for (i=0;i<N_PORTS;i=i+1) begin p_head[i]<=0; p_tail[i]<=0; p_cnt[i]<=0; end
    end else begin
        case (state)
            S_IDLE: if (dlv_valid) begin
                port_r<=dlv_port; type_r<=dlv_type; net_r<=dlv_net;
                len_r<=dlv_len; cp_cnt<=0;
                drop_r<=reject_delivery; allocated_r<=!reject_delivery;
                if (!reject_delivery) begin
                    slot_r<=free_mem[free_rptr];
                    slot_vlid[free_mem[free_rptr]]<=dlv_vlid;
                    slot_ip_id[free_mem[free_rptr]]<=dlv_ip_id;
                    slot_frag_offset[free_mem[free_rptr]]<=dlv_frag_offset;
                    slot_mf[free_mem[free_rptr]]<=dlv_mf;
                    slot_first[free_mem[free_rptr]]<=dlv_first;
                    slot_udp_total_len[free_mem[free_rptr]]<=dlv_udp_total_len;
                    slot_udp_checksum[free_mem[free_rptr]]<=dlv_udp_checksum;
                    slot_src_ip[free_mem[free_rptr]]<=dlv_src_ip;
                    slot_src_port[free_mem[free_rptr]]<=dlv_sport;
                    slot_dst_port[free_mem[free_rptr]]<=dlv_dport;
                end
                else stat_qfull_drop<=stat_qfull_drop+1'b1;
                state<=(dlv_len == 0) ? S_PUSH : S_COPY;
            end
            S_COPY: if (src_fire) begin
                if (!drop_r && cp_cnt < len_r) pool[slot_r*SLOT_B+cp_cnt]<=src_data;
                if (src_last) begin
                    if (!drop_r && cp_cnt+1 != len_r) begin
                        drop_r<=1; stat_qfull_drop<=stat_qfull_drop+1'b1;
                    end
                    state<=S_PUSH;
                end
                // Drain malformed overlength input until its actual tlast.
                if (cp_cnt != 12'hfff) cp_cnt<=cp_cnt+1'b1;
            end
            S_PUSH: begin
                if (push) begin
                    desc_mem[port_r*Q_DEPTH+p_tail[port_r]]<={slot_r,len_r};
                    stat_deliver<=stat_deliver+1'b1;
                end
                state<=S_IDLE;
            end
            default: state<=S_IDLE;
        endcase
        if (h_start) begin
            h_port<=host_port; h_slot<=head_desc[15:12]; h_len<=head_desc[11:0];
            h_rd_cnt<=0; h_active<=(head_desc[11:0] != 0);
        end else if (h_active && host_ready) begin
            if (host_tlast) begin h_active<=0; h_rd_cnt<=0; end
            else h_rd_cnt<=h_rd_cnt+1'b1;
        end
        // Merge concurrent queue events; every counter has one procedural owner.
        for (i=0;i<N_PORTS;i=i+1) begin
            if (push && port_r == i) p_tail[i]<=q_next(p_tail[i]);
            if (h_start && host_port == i && replace_pending && port_r == i)
                p_head[i]<=q_next(q_next(p_head[i]));
            else if ((h_start && host_port == i) || (replace_pending && port_r == i))
                p_head[i]<=q_next(p_head[i]);
            p_cnt[i]<=p_cnt[i]+((push && port_r == i) ? 1 : 0)
                     -((h_start && host_port == i) ? 1 : 0)
                     -((replace_pending && port_r == i) ? 1 : 0);
        end
        if (return_copy) free_mem[free_wptr]<=return_copy_slot;
        if (return_host) free_mem[return_copy ? f_next(free_wptr) : free_wptr]<=return_host_slot;
        if (return_copy && return_host) free_wptr<=f_next(f_next(free_wptr));
        else if (return_copy || return_host) free_wptr<=f_next(free_wptr);
        if (allocate) free_rptr<=f_next(free_rptr);
        free_cnt<=free_cnt+(return_copy ? 1 : 0)+(return_host ? 1 : 0)-(allocate ? 1 : 0);
    end
end
endmodule
`default_nettype wire
