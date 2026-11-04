`timescale 1ns / 1ps
`default_nettype none
// Integrity checking is independent for each VL and physical network. RM
// compares IC-passing traffic from both networks against the last delivery.
// Within SkewMAX, only cyclically newer SNs are delivered. The forward
// half-ring is 1..127 steps on the 1..255 sequence ring; the configured skew
// must span fewer than 128 transmitted frames on a VL to make this ordering
// unambiguous. Validated 1/2ms skew and >=1ms BAG are well inside this horizon.
// SN0 restarts the sequence; a second SN0 inside skew is redundant.
// Requests are level-held until response; one assertion produces one response.
module afdx_rx_check #(
    parameter N_RX_VL = 16,
    parameter TICK_NS = 80,
    parameter RX_IDX_WIDTH = (N_RX_VL > 1) ? $clog2(N_RX_VL) : 1
) (
    input wire clk, rst,
    input wire a_eval_valid,
    output reg a_eval_resp, a_eval_accept,
    input wire [15:0] a_eval_vlid, a_eval_dport,
    input wire [7:0] a_eval_sn,
    input wire [11:0] a_eval_plen,
    input wire [15:0] a_eval_ip_id,
    input wire [12:0] a_eval_frag_offset,
    input wire a_eval_mf, a_eval_first,
    input wire [15:0] a_eval_udp_total_len, a_eval_udp_checksum,
    input wire [15:0] a_eval_sport,
    input wire [31:0] a_eval_src_ip,
    input wire b_eval_valid,
    output reg b_eval_resp, b_eval_accept,
    input wire [15:0] b_eval_vlid, b_eval_dport,
    input wire [7:0] b_eval_sn,
    input wire [11:0] b_eval_plen,
    input wire [15:0] b_eval_ip_id,
    input wire [12:0] b_eval_frag_offset,
    input wire b_eval_mf, b_eval_first,
    input wire [15:0] b_eval_udp_total_len, b_eval_udp_checksum,
    input wire [15:0] b_eval_sport,
    input wire [31:0] b_eval_src_ip,
    output reg [15:0] rxvl_vlid,
    input wire rxvl_valid, rxvl_type, rxvl_ic_dis, rxvl_no_rm,
    input wire [5:0] rxvl_port,
    input wire [15:0] rxvl_dst_port,
    input wire rxvl_police_enable,
    input wire [2:0] rxvl_bag,
    input wire [11:0] rxvl_max_payload,
    input wire [RX_IDX_WIDTH-1:0] rxvl_idx,
    output reg dlv_valid,
    input wire dlv_ready,
    output reg dlv_net,
    output reg [5:0] dlv_port,
    output reg dlv_type,
    output reg [11:0] dlv_len,
    output reg [15:0] dlv_vlid,
    output reg [15:0] dlv_ip_id,
    output reg [12:0] dlv_frag_offset,
    output reg dlv_mf, dlv_first,
    output reg [15:0] dlv_udp_total_len, dlv_udp_checksum,
    output reg [15:0] dlv_sport, dlv_dport,
    output reg [31:0] dlv_src_ip,
    input wire [15:0] rm_skew_us,
    input wire [31:0] now_us,
    input wire [31:0] now_tick,
    output reg st_ic_drop, st_rm_drop, st_cfg_drop, st_fwd,
    output reg st_lmax_drop, st_police_drop
);
localparam S_IDLE=2'd0, S_CHK=2'd1, S_RESP=2'd2, S_DLV=2'd3;
reg [1:0] state;
reg cur_net, rr_net, a_busy, b_busy;
reg a_arrival_seen, b_arrival_seen;
reg [31:0] a_arrival_us, b_arrival_us;
reg [31:0] a_arrival_tick, b_arrival_tick;
reg [15:0] vlid_r, dport_r;
reg [15:0] sport_r;
reg [31:0] src_ip_r;
reg [7:0] sn_r;
reg [11:0] plen_r;
reg [15:0] ip_id_r,udp_total_len_r,udp_checksum_r;
reg [12:0] frag_offset_r;
reg mf_r,first_r;
reg [RX_IDX_WIDTH-1:0] idx_r;
reg cfg_valid_r, cfg_type_r, cfg_ic_dis_r, cfg_no_rm_r;
reg [5:0] cfg_port_r;
reg [15:0] cfg_dport_r, skew_r;
reg [31:0] time_r;
reg [31:0] arrival_tick_r, bag_ticks_r;
reg cfg_police_r;
reg [11:0] cfg_max_payload_r;
reg accept_r;
reg [2:0] drop_r;
localparam DROP_CFG=3'd0, DROP_IC=3'd1, DROP_RM=3'd2,
           DROP_LMAX=3'd3, DROP_POLICE=3'd4;
reg st_init_a [0:N_RX_VL-1];
reg st_init_b [0:N_RX_VL-1];
reg [7:0] st_psn_a [0:N_RX_VL-1];
reg [7:0] st_psn_b [0:N_RX_VL-1];
reg st_rm_init [0:N_RX_VL-1];
reg [7:0] st_last_sn [0:N_RX_VL-1];
reg [31:0] st_last_us [0:N_RX_VL-1];
reg [31:0] st_next_tick [0:N_RX_VL-1];
reg [N_RX_VL-1:0] st_police_active;
function [31:0] bag_ticks;
    input [2:0] exponent;
    reg [63:0] interval_ns;
    begin
        interval_ns = 64'd1000000 << exponent;
        bag_ticks = (interval_ns + TICK_NS - 1) / TICK_NS;
    end
endfunction
integer i;
wire a_pending = a_eval_valid && !a_busy;
wire b_pending = b_eval_valid && !b_busy;
wire select_a = a_pending && (!b_pending || !rr_net);
wire select_b = b_pending && !select_a;
// Invalid lookup indices cannot touch state, including non-power-of-two tables.
wire idx_valid = idx_r < N_RX_VL;
wire [7:0] psn = !idx_valid ? 8'd0 :
                  (cur_net ? st_psn_b[idx_r] : st_psn_a[idx_r]);
wire initialized = idx_valid &&
                  (cur_net ? st_init_b[idx_r] : st_init_a[idx_r]);
wire [8:0] sn_diff = (sn_r > psn) ? ({1'b0,sn_r}-{1'b0,psn}) :
                      ({1'b0,sn_r}+9'd255-{1'b0,psn});
wire ic_ok = (sn_r == 8'd0) || !initialized ||
             ((sn_diff >= 9'd1) && (sn_diff <= 9'd2));
wire [7:0] last_sn = idx_valid ? st_last_sn[idx_r] : 8'd0;
wire [8:0] rm_delta = (sn_r == last_sn) ? 9'd0 :
                     (sn_r > last_sn) ? ({1'b0,sn_r}-{1'b0,last_sn}) :
                     ({1'b0,sn_r}+9'd255-{1'b0,last_sn});
wire rm_stale = (sn_r == last_sn) || ((sn_r != 8'd0) && (rm_delta > 9'd127));
wire [31:0] rm_age = idx_valid ? time_r-st_last_us[idx_r] : 32'd0;
// Arbitration can process a newer arrival before an already-pending older
// copy. A negative modular age is not an expired skew window. As for normal
// wrap-aware signed timestamp ordering, the time horizon is <2^31 us.
// An explicitly zero skew still suppresses no frame.
wire rm_within_skew = (skew_r != 16'd0) &&
                      (rm_age[31] || (rm_age < {16'd0,skew_r}));
wire rm_dup = idx_valid && st_rm_init[idx_r] && rm_stale &&
              rm_within_skew;
// A configured destination port of zero explicitly admits all UDP ports.
// The dedicated loader application then validates session IP/TID metadata.
wire cfg_ok = cfg_valid_r && idx_valid &&
              (!first_r || cfg_dport_r==0 || dport_r==cfg_dport_r);
wire lmax_ok = plen_r <= ((cfg_max_payload_r == 0 || cfg_max_payload_r > 1471) ?
                          12'd1471 : cfg_max_payload_r);
wire [31:0] police_delta = idx_valid ? arrival_tick_r-st_next_tick[idx_r] : 32'd0;
wire police_ok = !cfg_police_r || (idx_valid &&
                  (!st_police_active[idx_r] || !police_delta[31]));
wire frame_ok = cfg_ok && (cfg_ic_dis_r || ic_ok) &&
                (cfg_no_rm_r || !rm_dup) && lmax_ok && police_ok;

always @(*) begin
    rxvl_vlid = vlid_r;
    if (state == S_IDLE) begin
        if (select_a) rxvl_vlid = a_eval_vlid;
        else if (select_b) rxvl_vlid = b_eval_vlid;
    end
end

always @(posedge clk) begin
    if (rst) begin
        state <= S_IDLE;
        cur_net <= 1'b0;
        rr_net <= 1'b0;
        a_busy <= 1'b0;
        b_busy <= 1'b0;
        a_arrival_seen <= 1'b0;
        b_arrival_seen <= 1'b0;
        a_arrival_us <= 32'd0;
        b_arrival_us <= 32'd0;
        a_arrival_tick <= 32'd0;
        b_arrival_tick <= 32'd0;
        vlid_r <= 16'd0;
        dport_r <= 16'd0;
        sport_r <= 16'd0;
        src_ip_r <= 32'd0;
        sn_r <= 8'd0;
        plen_r <= 12'd0;
        ip_id_r<=0;frag_offset_r<=0;mf_r<=0;first_r<=1;
        udp_total_len_r<=0;udp_checksum_r<=0;
        idx_r <= {RX_IDX_WIDTH{1'b0}};
        cfg_valid_r <= 1'b0;
        cfg_type_r <= 1'b0;
        cfg_ic_dis_r <= 1'b0;
        cfg_no_rm_r <= 1'b0;
        cfg_port_r <= 6'd0;
        cfg_dport_r <= 16'd0;
        time_r <= 32'd0;
        arrival_tick_r <= 32'd0;
        bag_ticks_r <= 32'd0;
        cfg_police_r <= 1'b0;
        cfg_max_payload_r <= 12'd0;
        skew_r <= 16'd0;
        accept_r <= 1'b0;
        drop_r <= DROP_CFG;
        a_eval_resp <= 1'b0;
        a_eval_accept <= 1'b0;
        b_eval_resp <= 1'b0;
        b_eval_accept <= 1'b0;
        dlv_valid <= 1'b0;
        dlv_net <= 1'b0;
        dlv_port <= 6'd0;
        dlv_type <= 1'b0;
        dlv_len <= 12'd0;
        dlv_vlid <= 16'd0;
        dlv_ip_id<=0;dlv_frag_offset<=0;dlv_mf<=0;dlv_first<=1;
        dlv_udp_total_len<=0;dlv_udp_checksum<=0;
        dlv_sport <= 0; dlv_dport <= 0; dlv_src_ip <= 0;
        st_ic_drop <= 1'b0;
        st_rm_drop <= 1'b0;
        st_cfg_drop <= 1'b0;
        st_fwd <= 1'b0;
        st_lmax_drop <= 1'b0;
        st_police_drop <= 1'b0;
        st_police_active <= {N_RX_VL{1'b0}};
        for (i=0; i<N_RX_VL; i=i+1) begin
            st_init_a[i] <= 1'b0;
            st_init_b[i] <= 1'b0;
            st_psn_a[i] <= 8'd0;
            st_psn_b[i] <= 8'd0;
            st_rm_init[i] <= 1'b0;
            st_last_sn[i] <= 8'd0;
            st_last_us[i] <= 32'd0;
            st_next_tick[i] <= 32'd0;
        end
    end else begin
        a_eval_resp <= 1'b0;
        b_eval_resp <= 1'b0;
        st_ic_drop <= 1'b0;
        st_rm_drop <= 1'b0;
        st_cfg_drop <= 1'b0;
        st_fwd <= 1'b0;
        st_lmax_drop <= 1'b0;
        st_police_drop <= 1'b0;
        // Clear expired deadlines while idle. A held request keeps its
        // captured arrival eligible for comparison even if arbitration or
        // host backpressure lasts past that deadline. Idle expiry also
        // prevents a stale timestamp becoming future after half a wrap.
        if (st_police_active!={N_RX_VL{1'b0}} && !a_eval_valid && !b_eval_valid)
            for (i=0; i<N_RX_VL; i=i+1)
                if (st_police_active[i] && ((now_tick-st_next_tick[i]) & 32'h80000000)==0)
                    st_police_active[i] <= 1'b0;
        if (!a_eval_valid) a_busy <= 1'b0;
        if (!b_eval_valid) b_busy <= 1'b0;
        // Capture both request arrivals even while another transaction or
        // delivery is blocked. Arbitration delay must not consume SkewMAX.
        if (!a_eval_valid) a_arrival_seen <= 1'b0;
        else if (!a_arrival_seen) begin
            a_arrival_seen <= 1'b1;
            a_arrival_us <= now_us;
            a_arrival_tick <= now_tick;
        end
        if (!b_eval_valid) b_arrival_seen <= 1'b0;
        else if (!b_arrival_seen) begin
            b_arrival_seen <= 1'b1;
            b_arrival_us <= now_us;
            b_arrival_tick <= now_tick;
        end
        case (state)
            S_IDLE: begin
                if (select_a || select_b) begin
                    cur_net <= select_b;
                    rr_net <= select_a;
                    if (select_a) begin
                        a_busy <= 1'b1;
                        vlid_r <= a_eval_vlid;
                        dport_r <= a_eval_dport;
                        sport_r <= a_eval_sport;
                        src_ip_r <= a_eval_src_ip;
                        sn_r <= a_eval_sn;
                        plen_r <= a_eval_plen;
                        ip_id_r<=a_eval_ip_id;frag_offset_r<=a_eval_frag_offset;
                        mf_r<=a_eval_mf;first_r<=a_eval_first;
                        udp_total_len_r<=a_eval_udp_total_len;
                        udp_checksum_r<=a_eval_udp_checksum;
                    end else begin
                        b_busy <= 1'b1;
                        vlid_r <= b_eval_vlid;
                        dport_r <= b_eval_dport;
                        sport_r <= b_eval_sport;
                        src_ip_r <= b_eval_src_ip;
                        sn_r <= b_eval_sn;
                        plen_r <= b_eval_plen;
                        ip_id_r<=b_eval_ip_id;frag_offset_r<=b_eval_frag_offset;
                        mf_r<=b_eval_mf;first_r<=b_eval_first;
                        udp_total_len_r<=b_eval_udp_total_len;
                        udp_checksum_r<=b_eval_udp_checksum;
                    end
                    // Snapshot lookup metadata with this arbitration grant.
                    idx_r <= rxvl_idx;
                    cfg_valid_r <= rxvl_valid;
                    cfg_type_r <= rxvl_type;
                    cfg_ic_dis_r <= rxvl_ic_dis;
                    cfg_no_rm_r <= rxvl_no_rm;
                    cfg_port_r <= rxvl_port;
                    cfg_dport_r <= rxvl_dst_port;
                    cfg_police_r <= rxvl_police_enable;
                    cfg_max_payload_r <= rxvl_max_payload;
                    bag_ticks_r <= bag_ticks(rxvl_bag);
                    // On a grant in the first asserted cycle, the arrival
                    // register is being written on this edge: use now_us.
                    time_r <= select_a ? (a_arrival_seen ? a_arrival_us : now_us) :
                                         (b_arrival_seen ? b_arrival_us : now_us);
                    arrival_tick_r <= select_a ? (a_arrival_seen ? a_arrival_tick : now_tick) :
                                                 (b_arrival_seen ? b_arrival_tick : now_tick);
                    skew_r <= rm_skew_us;
                    state <= S_CHK;
                end
            end
            S_CHK: begin
                accept_r <= frame_ok;
                if (!cfg_ok) drop_r <= DROP_CFG;
                else if (!lmax_ok) drop_r <= DROP_LMAX;
                else if (!cfg_ic_dis_r && !ic_ok) drop_r <= DROP_IC;
                else if (!cfg_no_rm_r && rm_dup) drop_r <= DROP_RM;
                else drop_r <= DROP_POLICE;
                // Every frame that belongs to this VL/UDP port updates that
                // network's PSN, including IC and RM rejects. Wrong ports do not.
                if (cfg_ok) begin
                    if (cur_net) begin
                        st_psn_b[idx_r] <= sn_r;
                        st_init_b[idx_r] <= 1'b1;
                    end else begin
                        st_psn_a[idx_r] <= sn_r;
                        st_init_a[idx_r] <= 1'b1;
                    end
                end
                // Rejected redundant copies do not extend the skew window.
                if (frame_ok) begin
                    st_rm_init[idx_r] <= 1'b1;
                    st_last_sn[idx_r] <= sn_r;
                    st_last_us[idx_r] <= time_r;
                    if (cfg_police_r) begin
                        st_next_tick[idx_r] <= arrival_tick_r + bag_ticks_r;
                        st_police_active[idx_r] <= 1'b1;
                    end
                end
                state <= S_RESP;
            end
            S_RESP: begin
                if (!cur_net) begin
                    a_eval_resp <= 1'b1;
                    a_eval_accept <= accept_r;
                end else begin
                    b_eval_resp <= 1'b1;
                    b_eval_accept <= accept_r;
                end
                if (accept_r) begin
                    dlv_valid <= 1'b1;
                    dlv_net <= cur_net;
                    dlv_port <= cfg_port_r;
                    dlv_type <= cfg_type_r;
                    dlv_len <= plen_r;
                    dlv_vlid <= vlid_r;
                    dlv_ip_id<=ip_id_r;dlv_frag_offset<=frag_offset_r;
                    dlv_mf<=mf_r;dlv_first<=first_r;
                    dlv_udp_total_len<=udp_total_len_r;
                    dlv_udp_checksum<=udp_checksum_r;
                    dlv_sport <= sport_r; dlv_dport <= dport_r; dlv_src_ip <= src_ip_r;
                    st_fwd <= 1'b1;
                    state <= S_DLV;
                end else begin
                    case (drop_r)
                        DROP_CFG: st_cfg_drop <= 1'b1;
                        DROP_IC: st_ic_drop <= 1'b1;
                        DROP_LMAX: st_lmax_drop <= 1'b1;
                        DROP_POLICE: st_police_drop <= 1'b1;
                        default: st_rm_drop <= 1'b1;
                    endcase
                    state <= S_IDLE;
                end
            end
            S_DLV: begin
                // Keep descriptor stable until a real valid/ready handshake.
                if (dlv_valid && dlv_ready) begin
                    dlv_valid <= 1'b0;
                    state <= S_IDLE;
                end
            end
            default: begin
                dlv_valid <= 1'b0;
                state <= S_IDLE;
            end
        endcase
    end
end
endmodule
`default_nettype wire
