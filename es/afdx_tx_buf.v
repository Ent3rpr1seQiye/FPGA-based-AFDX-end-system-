`timescale 1ns / 1ps
`default_nettype none
//-----------------------------------------------------------------------------
// afdx_tx_buf.v - AFDX end-system transmit buffer manager
//
// Shared pool of N_SLOTS frame slots (SLOT_BYTES each).  Host flow:
//   1) alloc_req          -> returns a free slot id
//   2) wr_en/wr_addr/     -> write payload bytes into the slot
//      wr_data              (byte address = slot*SLOT_BYTES + offset)
//   3) commit             -> push {slot,len} descriptor onto the TX VL queue
//
// Scheduler pops descriptors (sched_pop).  Frame generator returns the slot
// to the free list via slot_free when transmission completes.
//-----------------------------------------------------------------------------
module afdx_tx_buf #(
    parameter N_TX_VL     = 128,
    parameter N_SLOTS     = 16,
    parameter SLOT_BYTES  = 2048,
    parameter VL_QDEPTH   = 4                // descriptors per VL
) (
    input  wire        clk,
    input  wire        rst,

    // slot allocation
    input  wire        alloc_req,
    output reg  [3:0]  alloc_slot,
    output reg         alloc_ack,
    output reg         alloc_fail,

    // host payload write port (byte addressed across whole pool)
    input  wire        wr_en,
    input  wire [14:0] wr_addr,
    input  wire [7:0]  wr_data,

    // commit descriptor to a TX VL queue
    input  wire        commit_valid,
    input  wire [6:0]  commit_vl,
    input  wire [3:0]  commit_slot,
    input  wire [11:0] commit_len,
    input  wire [11:0] commit_max_payload,
    input  wire [15:0] commit_ip_id,
    input  wire [12:0] commit_frag_offset,
    input  wire        commit_mf,
    input  wire        commit_first,
    input  wire [15:0] commit_udp_total_len,
    output wire        commit_ready,         // VL queue not full

    // per-VL pending status for scheduler
    output wire [N_TX_VL-1:0] vl_pending,

    // scheduler descriptor read / pop (registered read, 1 clk latency)
    input  wire [6:0]  rd_vl,
    input  wire        rd_pop,
    output reg  [3:0]  rd_slot,
    output reg  [11:0] rd_len,
    output reg  [15:0] rd_ip_id,
    output reg  [12:0] rd_frag_offset,
    output reg         rd_mf,
    output reg         rd_first,
    output reg  [15:0] rd_udp_total_len,
    output reg         rd_valid,

    // slot return from frame generator
    input  wire        free_valid,
    input  wire [3:0]  free_slot,

    // frame buffer read port for packet generator (registered read)
    input  wire [14:0] buf_rd_addr,
    output reg  [7:0]  buf_rd_data,

    output reg         err_vl_overflow       // commit to full VL queue
);

localparam SLOT_AW = $clog2(SLOT_BYTES);     // 11 for 2048

// ------------------------------------------------------------------
// frame RAM
// ------------------------------------------------------------------
reg [7:0] frame_mem [0:N_SLOTS*SLOT_BYTES-1];

always @(posedge clk) begin
    if (wr_en && wr_addr < N_SLOTS*SLOT_BYTES)
        frame_mem[wr_addr] <= wr_data;
    buf_rd_data <= (buf_rd_addr < N_SLOTS*SLOT_BYTES) ? frame_mem[buf_rd_addr] : 8'd0;
end

// ------------------------------------------------------------------
// free slot list (FIFO)
// ------------------------------------------------------------------
reg [3:0] free_mem [0:N_SLOTS-1];
reg [3:0] free_wptr, free_rptr;
reg [4:0] free_cnt;
reg alloc_seen;
integer fi;

wire alloc_do  = alloc_req && !alloc_seen && (free_cnt != 0);
wire free_do   = free_valid && (free_slot < N_SLOTS) &&
                 ((free_cnt < N_SLOTS) || alloc_do);
function [3:0] next_free;
    input [3:0] ptr;
    begin next_free = (ptr == N_SLOTS-1) ? 4'd0 : ptr + 4'd1; end
endfunction

always @(posedge clk) begin
    if (rst) begin
        for (fi = 0; fi < N_SLOTS; fi = fi + 1)
            free_mem[fi] <= fi[3:0];
        free_wptr <= 4'd0;
        free_rptr <= 4'd0;
        free_cnt  <= N_SLOTS[4:0];
        alloc_slot <= 4'd0;
        alloc_ack  <= 1'b0;
        alloc_fail <= 1'b0;
        alloc_seen <= 1'b0;
    end else begin
        alloc_ack  <= 1'b0;
        alloc_fail <= 1'b0;
        if (!alloc_req) alloc_seen <= 1'b0;
        if (alloc_req && !alloc_seen) begin
            alloc_seen <= 1'b1;
            if (free_cnt != 0) begin
                alloc_slot <= free_mem[free_rptr];
                alloc_ack  <= 1'b1;
            end else begin
                alloc_fail <= 1'b1;
            end
        end
        case ({alloc_do, free_do})
            2'b10: begin
                free_rptr <= next_free(free_rptr);
                free_cnt  <= free_cnt - 5'd1;
            end
            2'b01: begin
                free_mem[free_wptr] <= free_slot;
                free_wptr <= next_free(free_wptr);
                free_cnt  <= free_cnt + 5'd1;
            end
            2'b11: begin
                // allocate and free in same cycle
                free_rptr <= next_free(free_rptr);
                free_mem[free_wptr] <= free_slot;
                free_wptr <= next_free(free_wptr);
            end
            default: ;
        endcase
    end
end

// ------------------------------------------------------------------
// per-VL descriptor queues: flat RAM, VL v owns entries [v*QD, v*QD+QD)
// ------------------------------------------------------------------
localparam QD   = VL_QDEPTH;
localparam QPTR = (QD > 1) ? $clog2(QD) : 1;
localparam MAX_PAYLOAD = (SLOT_BYTES < 1471) ? SLOT_BYTES : 1471;

function [QPTR-1:0] next_desc;
    input [QPTR-1:0] ptr;
    begin next_desc = (ptr == QD-1) ? 0 : ptr + 1'b1; end
endfunction

// {slot[3:0],len[11:0],ip_id[15:0],frag_offset[12:0],mf,first,udp_len[15:0]}
reg [62:0] desc_mem [0:N_TX_VL*QD-1];
reg [QPTR-1:0] vl_head [0:N_TX_VL-1];
reg [QPTR-1:0] vl_tail [0:N_TX_VL-1];
reg [QPTR:0]   vl_cnt  [0:N_TX_VL-1];

genvar gv;
generate
    for (gv = 0; gv < N_TX_VL; gv = gv + 1) begin : g_pending
        assign vl_pending[gv] = (vl_cnt[gv] != 0);
    end
endgenerate

wire rd_in_range = (rd_vl < N_TX_VL);
wire pop_do = rd_in_range ? (rd_pop && vl_cnt[rd_vl] != 0) : 1'b0;
wire [11:0] configured_max=(commit_max_payload==0 || commit_max_payload>MAX_PAYLOAD) ? MAX_PAYLOAD:commit_max_payload;
assign commit_ready = (commit_vl < N_TX_VL) ?
                      ((commit_slot < N_SLOTS) && (commit_len <= configured_max) &&
                       ((vl_cnt[commit_vl] < QD) || (pop_do && rd_vl == commit_vl))) : 1'b0;
wire push_do = commit_valid && commit_ready;

integer vi;
always @(posedge clk) begin
    if (rst) begin
        for (vi = 0; vi < N_TX_VL; vi = vi + 1) begin
            vl_head[vi] <= {QPTR{1'b0}};
            vl_tail[vi] <= {QPTR{1'b0}};
            vl_cnt[vi]  <= {(QPTR+1){1'b0}};
        end
        err_vl_overflow <= 1'b0;
        rd_slot  <= 4'd0;
        rd_len   <= 12'd0;
        rd_ip_id <= 16'd0;
        rd_frag_offset <= 13'd0;
        rd_mf <= 1'b0;
        rd_first <= 1'b1;
        rd_udp_total_len <= 16'd0;
        rd_valid <= 1'b0;
    end else begin
        // registered descriptor read (head entry of selected VL)
        rd_valid <= rd_in_range ? (vl_cnt[rd_vl] != 0) : 1'b0;
        if (rd_in_range && vl_cnt[rd_vl] != 0) begin
            rd_slot <= desc_mem[rd_vl*QD + vl_head[rd_vl]][62:59];
            rd_len  <= desc_mem[rd_vl*QD + vl_head[rd_vl]][58:47];
            rd_ip_id <= desc_mem[rd_vl*QD + vl_head[rd_vl]][46:31];
            rd_frag_offset <= desc_mem[rd_vl*QD + vl_head[rd_vl]][30:18];
            rd_mf <= desc_mem[rd_vl*QD + vl_head[rd_vl]][17];
            rd_first <= desc_mem[rd_vl*QD + vl_head[rd_vl]][16];
            rd_udp_total_len <= desc_mem[rd_vl*QD + vl_head[rd_vl]][15:0];
        end else begin
            rd_slot <= 4'd0;
            rd_len <= 12'd0;
            rd_ip_id <= 16'd0;
            rd_frag_offset <= 13'd0;
            rd_mf <= 1'b0;
            rd_first <= 1'b1;
            rd_udp_total_len <= 16'd0;
        end

        // commit push
        if (push_do) begin
            desc_mem[commit_vl*QD + vl_tail[commit_vl]] <=
                {commit_slot,commit_len,commit_ip_id,commit_frag_offset,
                 commit_mf,commit_first,commit_udp_total_len};
            vl_tail[commit_vl] <= next_desc(vl_tail[commit_vl]);
        end
        if (commit_valid && !commit_ready)
            err_vl_overflow <= 1'b1;

        // pop on scheduler request
        if (pop_do)
            vl_head[rd_vl] <= next_desc(vl_head[rd_vl]);

        // counters (commit and pop may target different VLs)
        if (push_do && !(pop_do && rd_vl == commit_vl))
            vl_cnt[commit_vl] <= vl_cnt[commit_vl] + 1'b1;
        if (pop_do && !(push_do && commit_vl == rd_vl))
            vl_cnt[rd_vl] <= vl_cnt[rd_vl] - 1'b1;
    end
end

endmodule
`default_nettype wire
