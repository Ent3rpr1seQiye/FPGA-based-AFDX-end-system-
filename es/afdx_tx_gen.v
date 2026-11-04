`timescale 1ns / 1ps
`default_nettype none
//-----------------------------------------------------------------------------
// afdx_tx_gen.v - AFDX frame generator (ARINC 664 P7 frame format)
//
// Emits one complete Ethernet frame per request on the AXIS output:
//   dstMAC {03000000|VLID} | srcMAC | 0800 | IPv4 | UDP | payload | pad | SN
// The 1-byte Sequence Number is the last byte before FCS.  When the frame
// would be shorter than the 64-byte Ethernet minimum, zero pad bytes are
// inserted between UDP payload and SN (SN always stays last).
// UDP length = 8 + payload (SN/pad not covered).  UDP checksum = 0.
// SN starts at 0 after reset and wraps 255 -> 1.
//-----------------------------------------------------------------------------
module afdx_tx_gen #(
    parameter N_TX_VL = 16
) (
    input  wire        clk,
    input  wire        rst,

    // request handshake from scheduler: request is latched when
    // (state==IDLE && gen_req); gen_ack pulses once at that instant.
    input  wire        gen_req,
    output reg         gen_ack,
    input  wire [6:0]  gen_vl_idx,
    input  wire [3:0]  gen_slot,
    input  wire [11:0] gen_len,
    input  wire [15:0] gen_ip_id,
    input  wire [12:0] gen_frag_offset,
    input  wire        gen_mf,
    input  wire        gen_first,
    input  wire [15:0] gen_udp_total_len,
    input  wire [15:0] gen_vlid,
    input  wire [15:0] gen_src_port,
    input  wire [15:0] gen_dst_port,
    input  wire [31:0] gen_dst_ip,

    // global config
    input  wire [47:0] src_mac,
    input  wire [31:0] src_ip,
    input  wire [7:0]  ip_ttl,

    // frame buffer read port (registered read of afdx_tx_buf)
    output reg  [14:0] buf_rd_addr,
    input  wire [7:0]  buf_rd_data,

    // frame output (complete frame incl. Ethernet header)
    output reg  [7:0]  m_axis_tdata,
    output reg         m_axis_tvalid,
    input  wire        m_axis_tready,
    output reg         m_axis_tlast,

    // slot return
    output reg         free_valid,
    output reg  [3:0]  free_slot,

    output reg         tx_frame_stb      // one pulse per emitted frame
);

localparam S_IDLE  = 3'd0,
           S_HDR   = 3'd1,
           S_PAY   = 3'd2,
           S_PAD   = 3'd3,
           S_SN    = 3'd4,
           S_DONE  = 3'd5;

reg [2:0]  state;
reg [5:0]  hdr_cnt;
reg [11:0] pay_len;
reg [11:0] pay_cnt;
reg [11:0] pay_issued;
reg [3:0]  slot_r;
reg [4:0]  pad_cnt;
reg [15:0] ip_id;

// latched header fields
reg [15:0] r_vlid, r_sport, r_dport, r_itot, r_ulen, r_ick, r_id;
reg [15:0] r_frag;
reg r_first;
reg [6:0]  r_vlidx;
reg [47:0] r_smac;
reg [31:0] r_sip, r_dip;
reg [7:0]  r_ttl;

// per-VL sequence number table (0 on reset, wraps 255 -> 1)
reg [7:0] sn_tab [0:N_TX_VL-1];
integer si;

// IPv4 header checksum
function [15:0] ip_cksum;
    input [15:0] tot;
    input [15:0] id;
    input [15:0] frag;
    input [7:0]  ttl;
    input [31:0] sip;
    input [31:0] dip;
    reg [31:0] sum;
    begin
        sum = 16'h4500 + tot + id + frag + {ttl, 8'd17}
              + sip[31:16] + sip[15:0] + dip[31:16] + dip[15:0];
        sum = (sum & 32'hFFFF) + (sum >> 16);
        sum = (sum & 32'hFFFF) + (sum >> 16);
        ip_cksum = ~sum[15:0];
    end
endfunction

// header byte at index 0..41 (dst MAC | src MAC | type | IPv4 | UDP)
function [7:0] hdr_byte;
    input [5:0] idx;
    begin
        case (idx)
            6'd0:  hdr_byte = 8'h03;
            6'd1:  hdr_byte = 8'h00;
            6'd2:  hdr_byte = 8'h00;
            6'd3:  hdr_byte = 8'h00;
            6'd4:  hdr_byte = r_vlid[15:8];
            6'd5:  hdr_byte = r_vlid[7:0];
            6'd6:  hdr_byte = r_smac[47:40];
            6'd7:  hdr_byte = r_smac[39:32];
            6'd8:  hdr_byte = r_smac[31:24];
            6'd9:  hdr_byte = r_smac[23:16];
            6'd10: hdr_byte = r_smac[15:8];
            6'd11: hdr_byte = r_smac[7:0];
            6'd12: hdr_byte = 8'h08;
            6'd13: hdr_byte = 8'h00;
            6'd14: hdr_byte = 8'h45;
            6'd15: hdr_byte = 8'h00;
            6'd16: hdr_byte = r_itot[15:8];
            6'd17: hdr_byte = r_itot[7:0];
            6'd18: hdr_byte = r_id[15:8];
            6'd19: hdr_byte = r_id[7:0];
            6'd20: hdr_byte = r_frag[15:8];
            6'd21: hdr_byte = r_frag[7:0];
            6'd22: hdr_byte = r_ttl;
            6'd23: hdr_byte = 8'd17;
            6'd24: hdr_byte = r_ick[15:8];
            6'd25: hdr_byte = r_ick[7:0];
            6'd26: hdr_byte = r_sip[31:24];
            6'd27: hdr_byte = r_sip[23:16];
            6'd28: hdr_byte = r_sip[15:8];
            6'd29: hdr_byte = r_sip[7:0];
            6'd30: hdr_byte = r_dip[31:24];
            6'd31: hdr_byte = r_dip[23:16];
            6'd32: hdr_byte = r_dip[15:8];
            6'd33: hdr_byte = r_dip[7:0];
            6'd34: hdr_byte = r_sport[15:8];
            6'd35: hdr_byte = r_sport[7:0];
            6'd36: hdr_byte = r_dport[15:8];
            6'd37: hdr_byte = r_dport[7:0];
            6'd38: hdr_byte = r_ulen[15:8];
            6'd39: hdr_byte = r_ulen[7:0];
            6'd40: hdr_byte = 8'h00;
            default: hdr_byte = 8'h00;   // 41: UDP checksum = 0
        endcase
    end
endfunction

wire [14:0] pay_base = {slot_r, 11'd0};
wire output_ready = !m_axis_tvalid || m_axis_tready;

// Payload RAM takes two edges from issuing an address to consuming its
// response here. Four FIFO entries reserve space for both in-flight reads,
// sustaining one payload byte/clock while preserving all bytes under stalls.
reg [7:0] pay_fifo [0:3];
reg [1:0] pay_wr_ptr, pay_rd_ptr;
reg [2:0] pay_fifo_count;
reg rd_pipe0, rd_pipe1;
wire pay_pop = state == S_PAY && output_ready && pay_fifo_count != 0;
wire [3:0] reserved_slots = {1'b0, pay_fifo_count} +
                           {3'd0, rd_pipe0} + {3'd0, rd_pipe1};
wire issue_read = state != S_IDLE && state != S_DONE &&
                  pay_issued < pay_len &&
                  (reserved_slots < 4 || pay_pop);
wire frame_accept = state == S_IDLE && gen_req;

always @(posedge clk) begin
    if (rst || frame_accept) begin
        pay_wr_ptr <= 2'd0;
        pay_rd_ptr <= 2'd0;
        pay_fifo_count <= 3'd0;
        pay_issued <= 12'd0;
        rd_pipe0 <= 1'b0;
        rd_pipe1 <= 1'b0;
        buf_rd_addr <= 15'd0;
    end else begin
        rd_pipe0 <= issue_read;
        rd_pipe1 <= rd_pipe0;
        if (issue_read) begin
            buf_rd_addr <= pay_base + pay_issued;
            pay_issued <= pay_issued + 12'd1;
        end
        if (rd_pipe1) begin
            pay_fifo[pay_wr_ptr] <= buf_rd_data;
            pay_wr_ptr <= pay_wr_ptr + 2'd1;
        end
        if (pay_pop) pay_rd_ptr <= pay_rd_ptr + 2'd1;
        case ({rd_pipe1, pay_pop})
            2'b10: pay_fifo_count <= pay_fifo_count + 3'd1;
            2'b01: pay_fifo_count <= pay_fifo_count - 3'd1;
            default: begin end
        endcase
    end
end

always @(posedge clk) begin
    if (rst) begin
        state         <= S_IDLE;
        gen_ack       <= 1'b0;
        m_axis_tdata  <= 8'd0;
        m_axis_tvalid <= 1'b0;
        m_axis_tlast  <= 1'b0;
        free_valid    <= 1'b0;
        free_slot     <= 4'd0;
        tx_frame_stb  <= 1'b0;
        hdr_cnt       <= 6'd0;
        pay_cnt       <= 12'd0;
        pay_len       <= 12'd0;
        pad_cnt       <= 5'd0;
        slot_r        <= 4'd0;
        ip_id         <= 16'd0;
        r_vlid <= 16'd0; r_sport <= 16'd0; r_dport <= 16'd0;
        r_itot <= 16'd0; r_ulen  <= 16'd0; r_ick   <= 16'd0;
        r_id   <= 16'd0;
        r_frag <= 16'd0;
        r_first <= 1'b1;
        r_vlidx <= 7'd0;
        r_smac <= 48'd0; r_sip   <= 32'd0; r_dip   <= 32'd0;
        r_ttl  <= 8'd0;
        for (si = 0; si < N_TX_VL; si = si + 1) sn_tab[si] <= 8'd0;
    end else begin
        free_valid   <= 1'b0;
        tx_frame_stb <= 1'b0;
        gen_ack      <= 1'b0;
        if (state == S_IDLE) begin
            m_axis_tvalid <= 1'b0;
            m_axis_tlast  <= 1'b0;
            if (gen_req) begin
                gen_ack   <= 1'b1;
                pay_len   <= gen_len;
                slot_r    <= gen_slot;
                hdr_cnt   <= 6'd0;
                pay_cnt   <= 12'd0;
                ip_id     <= ip_id + 16'd1;
                r_vlid    <= gen_vlid;
                r_vlidx   <= gen_vl_idx;
                r_sport   <= gen_src_port;
                r_dport   <= gen_dst_port;
                r_itot    <= (gen_first ? 16'd28 : 16'd20) + {4'd0,gen_len};
                r_ulen    <= gen_udp_total_len;
                r_frag    <= {2'b00,gen_mf,gen_frag_offset};
                r_first   <= gen_first;
                r_ick     <= ip_cksum((gen_first ? 16'd28 : 16'd20)+{4'd0,gen_len},
                                      (gen_ip_id!=0)?gen_ip_id:(ip_id+16'd1),
                                      {2'b00,gen_mf,gen_frag_offset},ip_ttl,
                                      src_ip, gen_dst_ip);
                r_id      <= (gen_ip_id!=0)?gen_ip_id:(ip_id+16'd1);
                r_smac    <= src_mac;
                r_sip     <= src_ip;
                r_dip     <= gen_dst_ip;
                r_ttl     <= ip_ttl;
                pad_cnt <= gen_first ?
                    ((gen_len<12'd17)?(5'd17-gen_len[4:0]):5'd0) :
                    ((gen_len<12'd25)?(5'd25-gen_len[4:0]):5'd0);
                state <= S_HDR;
            end
        end else if (output_ready) begin
            // A staged byte is replaced only after its handshake, or when
            // this output register is empty. This also permits the first
            // byte to be staged while ready is low.
            m_axis_tvalid <= 1'b0;
            m_axis_tlast <= 1'b0;
            case (state)
                S_HDR: begin
                    m_axis_tdata <= hdr_byte(hdr_cnt);
                    m_axis_tvalid <= 1'b1;
                    hdr_cnt <= hdr_cnt + 6'd1;
                    if (hdr_cnt == (r_first ? 6'd41 : 6'd33))
                        state <= (pay_len != 0) ? S_PAY :
                                 (pad_cnt != 0) ? S_PAD : S_SN;
                end
                S_PAY: begin
                    if (pay_fifo_count != 0) begin
                        m_axis_tdata <= pay_fifo[pay_rd_ptr];
                        m_axis_tvalid <= 1'b1;
                        pay_cnt <= pay_cnt + 12'd1;
                        if (pay_cnt == pay_len - 12'd1)
                            state <= (pad_cnt != 0) ? S_PAD : S_SN;
                    end
                end
                S_PAD: begin
                    m_axis_tdata <= 8'd0;
                    m_axis_tvalid <= 1'b1;
                    pad_cnt <= pad_cnt - 5'd1;
                    if (pad_cnt == 5'd1) state <= S_SN;
                end
                S_SN: begin
                    m_axis_tdata <= sn_tab[r_vlidx];
                    m_axis_tvalid <= 1'b1;
                    m_axis_tlast <= 1'b1;
                    sn_tab[r_vlidx] <= (sn_tab[r_vlidx] == 8'd255) ?
                                       8'd1 : sn_tab[r_vlidx] + 8'd1;
                    state <= S_DONE;
                end
                S_DONE: begin
                    // The last byte was held in the output register until
                    // this edge accepted it. Only now may the slot be freed.
                    free_valid <= 1'b1;
                    free_slot <= slot_r;
                    tx_frame_stb <= 1'b1;
                    state <= S_IDLE;
                end
                default: state <= S_IDLE;
            endcase
        end
    end
end
endmodule
`default_nettype wire
