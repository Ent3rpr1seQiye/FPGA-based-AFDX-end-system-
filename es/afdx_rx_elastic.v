`timescale 1ns/1ps
`default_nettype none
// GMII MAC RX cannot honor ready. Retain bytes while the parser evaluates a
// prior frame; preserve last/error. On overflow MARK_WHEN_FULL terminates the
// damaged frame with an error marker and drains its remainder to the boundary.
module afdx_rx_elastic #(parameter DEPTH=4096)(
 input wire clk,rst,
 input wire [7:0] s_data,input wire s_valid,s_last,s_error,
 output wire [7:0] m_data,output wire m_valid,m_last,m_error,
 input wire m_ready,output wire overflow,
 output wire [$clog2(DEPTH):0] depth
);
axis_fifo #(.DEPTH(DEPTH),.DATA_WIDTH(8),.KEEP_ENABLE(0),
 .LAST_ENABLE(1),.USER_ENABLE(1),.USER_WIDTH(1),.FRAME_FIFO(0),
 .MARK_WHEN_FULL(1)) u_fifo(
 .clk(clk),.rst(rst),.s_axis_tdata(s_data),.s_axis_tkeep(1'b1),
 .s_axis_tvalid(s_valid),.s_axis_tready(),.s_axis_tlast(s_last),
 .s_axis_tid(8'd0),.s_axis_tdest(8'd0),.s_axis_tuser(s_error),
 .m_axis_tdata(m_data),.m_axis_tkeep(),.m_axis_tvalid(m_valid),
 .m_axis_tready(m_ready),.m_axis_tlast(m_last),.m_axis_tid(),.m_axis_tdest(),.m_axis_tuser(m_error),
 .pause_req(1'b0),.pause_ack(),.status_depth(depth),.status_depth_commit(),
 .status_overflow(overflow),.status_bad_frame(),.status_good_frame());
endmodule
`default_nettype wire
