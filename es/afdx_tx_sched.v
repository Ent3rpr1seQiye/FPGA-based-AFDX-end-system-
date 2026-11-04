`timescale 1ns / 1ps
`default_nettype none
//-----------------------------------------------------------------------------
// afdx_tx_sched.v - AFDX transmit scheduler (per-VL BAG traffic regulator)
//
// ARINC 664 P7: frames on a Virtual Link are separated by at least the BAG
// (Bandwidth Allocation Gap), measured first-bit to first-bit.  Per VL we
// keep next_time[]; a VL is eligible when its descriptor queue is non-empty
// and now >= next_time.  Among eligible VLs a round-robin arbiter picks the
// next frame. With line-start feedback enabled, a granted VL remains blocked
// until its actual MAC start, then next_time <= line_start_time + BAG.
//
// Time is kept in clk ticks (32-bit, wrap-safe signed delta compare).
//-----------------------------------------------------------------------------
module afdx_tx_sched #(
    parameter N_TX_VL = 128,
    parameter TICK_US = 0,                   // legacy integer ticks/us override
    parameter TICK_NS = 80,                  // actual clock period; 80ns=12.5MHz
    parameter LINE_START_FEEDBACK = 0        // enforce BAG from actual MAC start
) (
    input  wire              clk,
    input  wire              rst,
    input  wire              tx_enable,

    input  wire [N_TX_VL-1:0] vl_pending,

    // descriptor read interface of afdx_tx_buf
    output reg  [6:0]        rd_vl,
    output reg               rd_pop,
    input  wire [3:0]        rd_slot,
    input  wire [11:0]       rd_len,
    input  wire [15:0]       rd_ip_id,
    input  wire [12:0]       rd_frag_offset,
    input  wire              rd_mf,
    input  wire              rd_first,
    input  wire [15:0]       rd_udp_total_len,
    input  wire              rd_valid,

    // TX VL table read of afdx_vl_cfg
    output reg  [6:0]        txvl_idx,
    input  wire              txvl_valid,
    input  wire [15:0]       txvl_vlid,
    input  wire [2:0]        txvl_bag,
    input  wire [15:0]       txvl_src_port,
    input  wire [15:0]       txvl_dst_port,
    input  wire [31:0]       txvl_dst_ip,

    // request to frame generator (held until gen_ack pulses)
    output reg               gen_req,
    input  wire              gen_ack,
    output reg  [3:0]        gen_slot,
    output reg  [11:0]       gen_len,
    output reg  [15:0]       gen_ip_id,
    output reg  [12:0]       gen_frag_offset,
    output reg               gen_mf,
    output reg               gen_first,
    output reg  [15:0]       gen_udp_total_len,
    output reg  [6:0]        gen_vl_idx,
    output reg  [15:0]       gen_vlid,
    output reg  [15:0]       gen_src_port,
    output reg  [15:0]       gen_dst_port,
    output reg  [31:0]       gen_dst_ip,

    output wire [31:0]       now_tick,
    input  wire              line_start_valid,
    input  wire [6:0]        line_start_vl
);

localparam S_IDLE   = 2'd0,
           S_WAIT   = 2'd1,
           S_LOOKUP = 2'd2,
           S_REQ    = 2'd3;

reg [1:0]  state;
reg [6:0]  rr_ptr;
reg [6:0]  winner;
reg [31:0] now_r;
reg [31:0] next_time [0:N_TX_VL-1];
reg [31:0] cached_bag [0:N_TX_VL-1];
reg [N_TX_VL-1:0] awaiting_start;
reg [N_TX_VL-1:0] deadline_active;
reg [31:0] bag_tick_r;

// BAG is 2**bag milliseconds, rounded up to avoid an early transmission.
function [31:0] bag_ticks;
    input [2:0] bag;
    reg [63:0] interval_ns;
    begin
        interval_ns = 64'd1000000 << bag;
        if (TICK_US != 0)
            bag_ticks = (64'd1000 << bag) * TICK_US;
        else
            bag_ticks = (interval_ns + TICK_NS - 1) / TICK_NS;
    end
endfunction

assign now_tick = now_r;

always @(posedge clk) begin
    if (rst) now_r <= 32'd0;
    else     now_r <= now_r + 32'd1;
end

// parallel eligibility vector (wrap-safe compare)
wire [N_TX_VL-1:0] eligible;
genvar gi;
generate
    for (gi = 0; gi < N_TX_VL; gi = gi + 1) begin : g_elig
        assign eligible[gi] = vl_pending[gi] &&
                              (!LINE_START_FEEDBACK || !awaiting_start[gi]) &&
                              (!deadline_active[gi] ||
                               (((now_r - next_time[gi]) & 32'h8000_0000) == 32'd0));
    end
endgenerate

// round-robin pick: first eligible VL at/after rr_ptr (priority chain)
reg [6:0] pick;
reg       pick_found;
integer   k;
always @(*) begin
    pick       = 7'd0;
    pick_found = 1'b0;
    for (k = 0; k < N_TX_VL; k = k + 1) begin
        if (!pick_found && eligible[(rr_ptr + k[6:0]) % N_TX_VL]) begin
            pick       = (rr_ptr + k[6:0]) % N_TX_VL;
            pick_found = 1'b1;
        end
    end
end

integer i;

always @(posedge clk) begin
    if (rst) begin
        for (i = 0; i < N_TX_VL; i = i + 1) begin
            next_time[i] <= 32'd0;
            cached_bag[i] <= 32'd0;
        end
        awaiting_start <= {N_TX_VL{1'b0}};
        deadline_active <= {N_TX_VL{1'b0}};
        state   <= S_IDLE;
        rr_ptr  <= 7'd0;
        winner  <= 7'd0;
        rd_vl   <= 7'd0;
        rd_pop  <= 1'b0;
        txvl_idx <= 7'd0;
        gen_req <= 1'b0;
        bag_tick_r <= 32'd0;
        gen_slot <= 4'd0;
        gen_len <= 12'd0;
        gen_ip_id <= 16'd0;
        gen_frag_offset <= 13'd0;
        gen_mf <= 1'b0;
        gen_first <= 1'b1;
        gen_udp_total_len <= 16'd0;
        gen_vl_idx <= 7'd0;
        gen_vlid <= 16'd0;
        gen_src_port <= 16'd0;
        gen_dst_port <= 16'd0;
        gen_dst_ip <= 32'd0;
    end else begin
        rd_pop <= 1'b0;
        // Expire every deadline while time advances, even without pending
        // data. A stale timestamp must not become a future deadline again
        // after an idle interval exceeds half the 32-bit tick range.
        for (i = 0; i < N_TX_VL; i = i + 1)
            if (deadline_active[i] &&
                (((now_r-next_time[i]) & 32'h8000_0000) == 32'd0))
                deadline_active[i] <= 1'b0;
        if (LINE_START_FEEDBACK && line_start_valid && line_start_vl < N_TX_VL) begin
            next_time[line_start_vl] <= now_r + cached_bag[line_start_vl];
            awaiting_start[line_start_vl] <= 1'b0;
            deadline_active[line_start_vl] <= 1'b1;
        end
        case (state)
            S_IDLE: begin
                gen_req <= 1'b0;
                if (tx_enable && pick_found) begin
                    winner   <= pick;
                    rd_vl    <= pick;
                    txvl_idx <= pick;
                    state    <= S_WAIT;
                end
            end
            S_WAIT: begin
                // Registered descriptor/config outputs arrive after this
                // edge; LOOKUP must not consume the previous VL's response.
                state <= S_LOOKUP;
            end
            S_LOOKUP: begin
                // descriptor + VL cfg fields valid this cycle
                if (rd_valid && txvl_valid) begin
                    gen_vl_idx   <= winner;
                    gen_slot     <= rd_slot;
                    gen_len      <= rd_len;
                    gen_ip_id    <= rd_ip_id;
                    gen_frag_offset <= rd_frag_offset;
                    gen_mf       <= rd_mf;
                    gen_first    <= rd_first;
                    gen_udp_total_len <= rd_udp_total_len;
                    gen_vlid     <= txvl_vlid;
                    gen_src_port <= txvl_src_port;
                    gen_dst_port <= txvl_dst_port;
                    gen_dst_ip   <= txvl_dst_ip;
                    bag_tick_r   <= bag_ticks(txvl_bag);
                    gen_req      <= 1'b1;
                    state        <= S_REQ;
                end else begin
                    // VL disabled or queue emptied -> skip, retry others
                    rr_ptr <= (winner == N_TX_VL-1) ? 7'd0 : winner + 7'd1;
                    state <= S_IDLE;
                end
            end
            S_REQ: begin
                if (gen_ack) begin
                    gen_req <= 1'b0;
                    rd_pop  <= 1'b1;
                    // Keep a provisional deadline, but never allow it to
                    // expire into eligibility before this frame starts.
                    next_time[winner] <= now_r + bag_tick_r;
                    deadline_active[winner] <= 1'b1;
                    if (LINE_START_FEEDBACK) begin
                        cached_bag[winner] <= bag_tick_r;
                        // ACK takes precedence over simultaneous feedback
                        // for an older frame on this VL: the new frame must
                        // wait for its own subsequent line-start event.
                        awaiting_start[winner] <= 1'b1;
                    end
                    rr_ptr <= (winner == N_TX_VL-1) ? 7'd0 : winner + 7'd1;
                    state  <= S_IDLE;
                end
            end
            default: state <= S_IDLE;
        endcase
    end
end

endmodule
`default_nettype wire
