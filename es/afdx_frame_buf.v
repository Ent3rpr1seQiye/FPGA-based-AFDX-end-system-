`timescale 1ns / 1ps
`default_nettype none
//-----------------------------------------------------------------------------
// afdx_frame_buf.v - staging buffer with commit / abort, 2 ping-pong slots
//
// Bytes are written while a frame is being parsed.  When the parser has the
// verdict it either commits (frame becomes readable on the AXIS output) or
// aborts (written bytes are discarded).  Two slots allow one frame to be
// staged while the previous committed frame is still being read out.
// wr_blocked asserts when a write arrives with no free slot -> the parser
// must abort the frame.
//-----------------------------------------------------------------------------
module afdx_frame_buf #(
    parameter DEPTH = 2048
) (
    input  wire        clk,
    input  wire        rst,

    // byte write port
    input  wire        wr_en,
    input  wire [7:0]  wr_data,
    output wire        wr_full,
    output wire        wr_blocked,         // no free slot for current frame

    // frame boundary control
    input  wire        wr_commit,          // commit written bytes as a frame
    input  wire        wr_abort,           // discard written bytes
    input  wire [11:0] wr_len,             // committed frame length
    output wire        frame_avail,        // committed frame present
    output wire [11:0] frame_len,

    // AXIS read port
    output wire [7:0]  m_axis_tdata,
    output wire        m_axis_tvalid,
    input  wire        m_axis_tready,
    output wire        m_axis_tlast,
    output wire        can_start          // space to reserve a new whole frame
);

localparam AW = $clog2(DEPTH);

reg [7:0]  mem [0:2*DEPTH-1];
reg [11:0] len_mem [0:1];
reg [1:0]  slot_valid;
reg [1:0]  cq [0:3];            // committed slot ids, FIFO order
reg [1:0]  cq_w, cq_r;
reg [2:0]  cq_cnt;
reg        wr_active;
reg        wr_slot;
reg [AW-1:0] wptr;
reg [11:0]   rd_cnt;

wire [3:0] rd_slot = cq[cq_r];
wire       rd_ok   = (cq_cnt != 0) && slot_valid[rd_slot];

assign wr_full    = (wptr == DEPTH[AW-1:0] - 1'b1);
assign wr_blocked = wr_en && !wr_active && (slot_valid == 2'b11);
assign can_start  = !wr_active && (slot_valid != 2'b11) && !wr_commit && !wr_abort;
assign frame_avail = rd_ok;
assign frame_len   = len_mem[rd_slot];

// AXIS read side
assign m_axis_tvalid = rd_ok;
assign m_axis_tdata  = mem[{rd_slot[0], {AW{1'b0}}} + rd_cnt];
assign m_axis_tlast  = rd_ok && (rd_cnt == len_mem[rd_slot] - 1'b1);

wire rd_fire = m_axis_tvalid && m_axis_tready;

// free slot pick: prefer slot 0
wire free0 = !slot_valid[0];
wire free1 = !slot_valid[1];

always @(posedge clk) begin
    if (rst) begin
        slot_valid <= 2'b00;
        cq_w    <= 2'd0;
        cq_r    <= 2'd0;
        cq_cnt  <= 3'd0;
        wr_active <= 1'b0;
        wr_slot <= 1'b0;
        wptr    <= {AW{1'b0}};
        rd_cnt  <= 12'd0;
    end else begin
        // ---- write side ----
        if (wr_en && !wr_active && !wr_blocked) begin
            wr_active <= 1'b1;
            wr_slot   <= free0 ? 1'b0 : 1'b1;
            wptr      <= {AW{1'b0}} + 1'b1;
            mem[{free0 ? 1'b0 : 1'b1, {AW{1'b0}}}] <= wr_data;
        end else if (wr_en && wr_active && !wr_full) begin
            mem[{wr_slot, {AW{1'b0}}} + wptr] <= wr_data;
            wptr <= wptr + 1'b1;
        end

        if (wr_abort) begin
            wr_active <= 1'b0;
            wptr      <= {AW{1'b0}};
        end else if (wr_commit && wr_active) begin
            wr_active <= 1'b0;
            wptr      <= {AW{1'b0}};
            slot_valid[wr_slot] <= 1'b1;
            len_mem[wr_slot]    <= wr_len;
            cq[cq_w]  <= {1'b0, wr_slot};
            cq_w      <= cq_w + 2'd1;
        end

        // ---- read side ----
        if (rd_fire) begin
            if (m_axis_tlast) begin
                slot_valid[rd_slot] <= 1'b0;
                cq_r   <= cq_r + 2'd1;
                rd_cnt <= 12'd0;
            end else begin
                rd_cnt <= rd_cnt + 12'd1;
            end
        end

        // commit/pop bookkeeping (both may fire in one cycle)
        case ({wr_commit && wr_active, rd_fire && m_axis_tlast})
            2'b10: cq_cnt <= cq_cnt + 3'd1;
            2'b01: cq_cnt <= cq_cnt - 3'd1;
            default: ;
        endcase
    end
end

endmodule
`default_nettype wire
