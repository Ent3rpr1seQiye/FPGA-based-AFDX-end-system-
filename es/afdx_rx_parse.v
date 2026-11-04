`timescale 1ns / 1ps
`default_nettype none
//-----------------------------------------------------------------------------
// afdx_rx_parse.v - AFDX receive frame parser (per redundant network)
//
// Consumes complete MAC frames (AXIS, FCS already checked) and:
//   - verifies AFDX dst MAC constant field {03 00 00 00|VLID}
//   - verifies Ethertype 0x0800, IPv4 (IHL=5, proto=UDP)
//   - captures UDP dst port / UDP length / dst IP
//   - streams UDP payload bytes into an afdx_frame_buf staging buffer
//   - takes the last byte of the frame as the AFDX Sequence Number
// On frame end it raises eval_valid and waits for eval_accept from the
// integrity/redundancy checker, then commits or aborts the staged frame.
//-----------------------------------------------------------------------------
module afdx_rx_parse #(
    // 0: stage UDP payload only (end system)
    // 1: stage the whole frame dst-MAC..SN (switch store-and-forward)
    parameter FULL_FRAME = 0
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        es_enable,

    // MAC frame stream (incl. Ethernet header, FCS removed)
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    output wire        s_axis_tready,
    input  wire        s_axis_tlast,
    input  wire        s_axis_tuser,        // bad frame flag from MAC

    // staging buffer write
    output reg         wr_en,
    output reg  [7:0]  wr_data,
    output reg         wr_commit,
    output reg         wr_abort,
    output reg  [11:0] wr_len,
    input  wire        wr_blocked,        // staging buffer has no free slot

    // integrity/redundancy evaluation
    output reg         eval_valid,
    input  wire        eval_resp,           // response valid
    input  wire        eval_accept,         // 1 = deliver, 0 = drop
    output reg  [15:0] eval_vlid,
    output reg  [15:0] eval_dport,
    output reg  [15:0] eval_sport,
    output reg  [31:0] eval_src_ip,
    output reg  [7:0]  eval_sn,
    output reg  [11:0] eval_plen,
    output reg  [15:0] eval_ip_id,
    output reg  [12:0] eval_frag_offset,
    output reg         eval_mf,
    output reg         eval_first,
    output reg  [15:0] eval_udp_total_len,
    output reg  [15:0] eval_udp_checksum,

    // statistics strobes
    output reg         st_rx_frame,         // frame reached eval
    output reg         st_rx_drop_parse     // dropped during parse
);

localparam S_DST   = 4'd0,
           S_SRC   = 4'd1,
           S_TYPE  = 4'd2,
           S_IP    = 4'd3,
           S_UDP   = 4'd4,
           S_PAY   = 4'd5,
           S_TAIL  = 4'd6,
           S_EVAL  = 4'd7,
           S_DRAIN = 4'd8;

reg [3:0]  state;
reg [4:0]  cnt;            // byte counter within current field
reg [11:0] pay_rem;        // payload bytes remaining
reg [11:0] pay_len_r;
reg [11:0] flen_cnt;       // full-frame byte counter (FULL_FRAME mode)
reg [15:0] ip_tot_len;
reg [31:0] dst_ip_r;
reg        bad;            // any parse error / tuser
reg [31:0] ip_sum;
reg [7:0]  ip_hi, udp_hi;
reg [31:0] udp_sum;
reg [7:0]  udp_word_hi;
reg [15:0] udp_checksum;
reg        udp_pay_odd;
reg        frag_df;
wire       frame_fault = bad || s_axis_tuser || wr_blocked;
wire [31:0] ip_fold1 = (ip_sum & 32'hffff) + (ip_sum >> 16);
wire [31:0] ip_fold2 = (ip_fold1 & 32'hffff) + (ip_fold1 >> 16);
wire [31:0] udp_fold1 = (udp_sum & 32'hffff) + (udp_sum >> 16);
wire [31:0] udp_fold2 = (udp_fold1 & 32'hffff) + (udp_fold1 >> 16);
// IPv4 permits an omitted (zero) UDP checksum. A transmitted checksum covers
// only the UDP datagram and pseudoheader, never Ethernet padding or AFDX SN.
wire       udp_checksum_bad = (udp_checksum != 16'd0) &&
                              (udp_fold2[15:0] != 16'hffff);
wire [16:0] expected_len = (ip_tot_len < 16'd45) ?
                           17'd60 : 17'd15 + ip_tot_len;

assign s_axis_tready = (state != S_EVAL);

wire [7:0] d = s_axis_tdata;
wire       fire = s_axis_tvalid && s_axis_tready;

always @(posedge clk) begin
    if (rst) begin
        state          <= S_DST;
        cnt            <= 5'd0;
        pay_rem        <= 12'd0;
        pay_len_r      <= 12'd0;
        flen_cnt       <= 12'd0;
        ip_tot_len     <= 16'd0;
        dst_ip_r       <= 32'd0;
        bad            <= 1'b0;
        ip_sum         <= 32'd0;
        ip_hi          <= 8'd0;
        udp_hi         <= 8'd0;
        udp_sum        <= 32'd0;
        udp_word_hi    <= 8'd0;
        udp_checksum   <= 16'd0;
        udp_pay_odd    <= 1'b0;
        wr_en          <= 1'b0;
        wr_data        <= 8'd0;
        wr_commit      <= 1'b0;
        wr_abort       <= 1'b0;
        wr_len         <= 12'd0;
        eval_valid     <= 1'b0;
        eval_vlid      <= 16'd0;
        eval_dport     <= 16'd0;
        eval_sport     <= 16'd0;
        eval_src_ip    <= 32'd0;
        eval_sn        <= 8'd0;
        eval_plen      <= 12'd0;
        eval_ip_id     <= 16'd0;
        eval_frag_offset <= 13'd0;
        eval_mf        <= 1'b0;
        eval_first     <= 1'b1;
        eval_udp_total_len <= 16'd0;
        eval_udp_checksum <= 16'd0;
        frag_df        <= 1'b0;
        st_rx_frame    <= 1'b0;
        st_rx_drop_parse <= 1'b0;
    end else begin
        wr_en            <= 1'b0;
        wr_commit        <= 1'b0;
        wr_abort         <= 1'b0;
        st_rx_frame      <= 1'b0;
        st_rx_drop_parse <= 1'b0;

        if (fire) begin
            if (s_axis_tuser || wr_blocked)
                bad <= 1'b1;
            flen_cnt <= flen_cnt + 12'd1;
            if (FULL_FRAME || state == S_PAY) begin
                wr_en   <= 1'b1;
                wr_data <= d;
            end
            case (state)
                S_DST: begin
                    case (cnt)
                        5'd0: bad <= frame_fault || (d != 8'h03);
                        5'd1: bad <= frame_fault || (d != 8'h00);
                        5'd2: bad <= frame_fault || (d != 8'h00);
                        5'd3: bad <= frame_fault || (d != 8'h00);
                        5'd4: eval_vlid[15:8] <= d;
                        5'd5: eval_vlid[7:0]  <= d;
                        default: ;
                    endcase
                    if (cnt == 5'd5) begin
                        cnt   <= 5'd0;
                        state <= S_SRC;
                    end else begin
                        cnt <= cnt + 5'd1;
                    end
                end
                S_SRC: begin
                    if (cnt == 5'd5) begin
                        cnt   <= 5'd0;
                        state <= S_TYPE;
                    end else begin
                        cnt <= cnt + 5'd1;
                    end
                end
                S_TYPE: begin
                    bad <= frame_fault || (cnt == 5'd0 ? (d != 8'h08) : (d != 8'h00));
                    cnt   <= cnt + 5'd1;
                    if (cnt == 5'd1) begin
                        cnt   <= 5'd0;
                        state <= S_IP;
                        ip_sum <= 32'd0;
                        udp_sum <= 32'd17; // pseudoheader zero + UDP protocol
                        udp_checksum <= 16'd0;
                        udp_pay_odd <= 1'b0;
                        eval_sport <= 16'd0;
                        eval_dport <= 16'd0;
                        eval_ip_id <= 16'd0;
                        eval_frag_offset <= 13'd0;
                        eval_mf <= 1'b0;
                        eval_first <= 1'b1;
                        eval_udp_total_len <= 16'd0;
                        eval_udp_checksum <= 16'd0;
                        frag_df <= 1'b0;
                    end
                end
                S_IP: begin
                    if (!cnt[0]) ip_hi <= d;
                    else ip_sum <= ip_sum + {ip_hi, d};
                    // IPv4 source/destination addresses form four words of
                    // the UDP pseudoheader. ip_hi holds the preceding byte.
                    if (cnt >= 5'd12 && cnt[0])
                        udp_sum <= udp_sum + {ip_hi, d};
                    case (cnt)
                        5'd0:  bad <= frame_fault || (d != 8'h45); // ver4/IHL5
                        5'd2:  ip_tot_len[15:8] <= d;
                        5'd3:  ip_tot_len[7:0]  <= d;
                        5'd4:  eval_ip_id[15:8] <= d;
                        5'd5:  eval_ip_id[7:0] <= d;
                        5'd6: begin
                            // Reserved flag must be zero. DF is legal only
                            // when this is not a fragmented datagram.
                            bad <= frame_fault || d[7];
                            frag_df <= d[6];
                            eval_mf <= d[5];
                            eval_frag_offset[12:8] <= d[4:0];
                        end
                        5'd7: begin
                            eval_frag_offset[7:0] <= d;
                            eval_first <= ({eval_frag_offset[12:8],d}==13'd0);
                            bad <= frame_fault ||
                                   (frag_df && (eval_mf || ({eval_frag_offset[12:8],d}!=0)));
                        end
                        5'd9:  bad <= frame_fault || (d != 8'd17); // UDP
                        5'd12, 5'd13, 5'd14, 5'd15:
                            eval_src_ip <= {eval_src_ip[23:0], d};
                        5'd16, 5'd17, 5'd18, 5'd19:
                            dst_ip_r <= {dst_ip_r[23:0], d};
                        default: ;
                    endcase
                    cnt <= cnt + 5'd1;
                    if (cnt == 5'd19) begin
                        cnt   <= 5'd0;
                        if(!eval_first)begin
                            // Non-first fragments contain raw IP payload, not
                            // another UDP header.
                            pay_rem <= ip_tot_len-16'd20;
                            pay_len_r <= ip_tot_len-16'd20;
                            eval_plen <= ip_tot_len-16'd20;
                            wr_len <= ip_tot_len-16'd20;
                            bad <= frame_fault || (ip_tot_len<=16'd20) ||
                                   (ip_tot_len>16'd1499) ||
                                   (eval_mf && ((ip_tot_len-16'd20)&16'd7)!=0);
                            state <= (ip_tot_len==16'd20)?S_TAIL:S_PAY;
                        end else state <= S_UDP;
                    end
                end
                S_UDP: begin
                    if (!cnt[0])
                        udp_word_hi <= d;
                    else if (cnt == 5'd5)
                        // UDP length also occurs once in the pseudoheader.
                        udp_sum <= udp_sum + {udp_word_hi, d} + {udp_word_hi, d};
                    else
                        udp_sum <= udp_sum + {udp_word_hi, d};
                    case (cnt)
                        5'd0: begin
                            eval_sport[15:8] <= d;
                            bad <= frame_fault || (ip_fold2[15:0] != 16'hffff) ||
                                     (ip_tot_len < 16'd28) || (ip_tot_len > 16'd1499);
                        end
                        5'd1: eval_sport[7:0] <= d;
                        5'd2: eval_dport[15:8] <= d;
                        5'd3: eval_dport[7:0]  <= d;
                        5'd4: begin
                            udp_hi <= d;
                            pay_rem[11:8] <= d[3:0];
                        end
                        5'd5: begin
                            bad <= frame_fault || ({udp_hi,d} < 16'd8) ||
                                   (eval_mf ?
                                     (({udp_hi,d}<ip_tot_len-16'd20) ||
                                      (((ip_tot_len-16'd20)&16'd7)!=0)) :
                                     ({udp_hi,d} != ip_tot_len-16'd20));
                            pay_rem[7:0] <= d;
                            eval_udp_total_len <= {udp_hi,d};
                        end
                        5'd6: begin
                            udp_checksum[15:8] <= d;
                            eval_udp_checksum[15:8] <= d;
                        end
                        5'd7: begin
                            udp_checksum[7:0] <= d;
                            eval_udp_checksum[7:0] <= d;
                        end
                        default: ;
                    endcase
                    cnt <= cnt + 5'd1;
                    if (cnt == 5'd7) begin
                        cnt   <= 5'd0;
                        // payload bytes = udp_len - 8 (may be 0)
                        // pay_rem[11:0] already holds udp_len (lo byte latched
                        // at cnt5); do not use d here
                        if (ip_tot_len <= 16'd28)
                            state <= S_TAIL;
                        else
                            state <= S_PAY;
                        pay_rem   <= ip_tot_len - 16'd28;
                        pay_len_r <= ip_tot_len - 16'd28;
                        eval_plen <= ip_tot_len - 16'd28;
                        wr_len    <= ip_tot_len - 16'd28;
                    end
                end
                S_PAY: begin
                    if(eval_first)begin
                        udp_pay_odd <= !udp_pay_odd;
                        if (udp_pay_odd)
                            udp_sum <= udp_sum + {udp_word_hi, d};
                        else if (pay_rem == 12'd1)
                            // Odd UDP payloads are padded with a zero low byte
                            // for the checksum calculation only.
                            udp_sum <= udp_sum + {d, 8'd0};
                        else
                            udp_word_hi <= d;
                    end else if(pay_rem==eval_plen)
                        bad <= frame_fault || (ip_fold2[15:0]!=16'hffff);
                    pay_rem <= pay_rem - 12'd1;
                    if (pay_rem == 12'd1 || s_axis_tlast)
                        state <= S_TAIL;
                end
                S_TAIL: begin
                    eval_sn <= d;              // SN = last byte of frame
                    if (s_axis_tlast) begin
                        if (frame_fault || !es_enable ||
                            (ip_fold2[15:0]!=16'hffff) ||
                            (eval_first && !eval_mf && udp_checksum_bad) ||
                            ({5'd0,flen_cnt} + 17'd1 != expected_len)) begin
                            wr_abort <= 1'b1;
                            st_rx_drop_parse <= 1'b1;
                            state <= S_DST;
                            cnt   <= 5'd0;
                            bad   <= 1'b0;
                            flen_cnt <= 12'd0;
                        end else begin
                            if (FULL_FRAME) begin
                                wr_len    <= flen_cnt + 12'd1;
                                eval_plen <= flen_cnt + 12'd1;
                            end
                            eval_valid <= 1'b1;
                            st_rx_frame <= 1'b1;
                            state <= S_EVAL;
                        end
                    end
                end
                default: state <= S_DST;
            endcase

            // truncated frame anywhere before completion
            if (s_axis_tlast && state != S_TAIL) begin
                wr_abort <= 1'b1;
                st_rx_drop_parse <= 1'b1;
                state <= S_DST;
                cnt   <= 5'd0;
                bad   <= 1'b0;
                flen_cnt <= 12'd0;
            end
        end

        if (state == S_EVAL && eval_resp) begin
            eval_valid <= 1'b0;
            if (eval_accept)
                wr_commit <= 1'b1;
            else
                wr_abort  <= 1'b1;
            state <= S_DST;
            cnt   <= 5'd0;
            bad   <= 1'b0;
            flen_cnt <= 12'd0;
        end
    end
end

endmodule
`default_nettype wire
