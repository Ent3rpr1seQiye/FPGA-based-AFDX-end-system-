`timescale 1ns/1ps
`default_nettype none
// Four timestamp synchronization over a private 48-byte datagram format.
// rtc and stream timestamps refer to the values immediately before each edge.
module afdx_time_sync #(
    parameter IS_MASTER=0, TICK_NS=8, POLL_US=8000, TIMEOUT_US=4000,
    parameter HOLDOVER_US=32000, MAX_RTT_NS=2000000,
    parameter LOCK_THRESHOLD_NS=25000, LOCK_SAMPLES=3,
    parameter [31:0] NODE_ID=32'd1
)(
    input wire clk, rst, enable,
    input wire [31:0] rtc_sec, rtc_ns, tick_us,
    input wire [7:0] s_data, input wire s_valid, s_last, output wire s_ready,
    output reg [7:0] m_data, output wire m_valid, m_last, input wire m_ready,
    output wire busy,
    output wire set_valid, output reg [31:0] set_sec, set_ns,
    output reg synced, sync_pulse,
    output reg signed [63:0] last_offset_ns,
    output reg [63:0] last_delay_ns,
    output reg [31:0] stat_applied, stat_rejected, stat_timeout
);
    localparam [1:0] RECEIVE=0, EVALUATE=1, APPLY=2;
    reg [1:0] state;
    reg [7:0] packet[0:47];
    reg [5:0] rx_count, tx_index;
    reg rx_length_ok, tx_active, tx_cancel;
    reg [31:0] rx_time_sec, rx_time_ns;
    reg [31:0] tx_sequence, tx_node, tx_t1_sec, tx_t1_ns;
    reg [31:0] tx_t2_sec, tx_t2_ns, tx_t3_sec, tx_t3_ns;
    reg [31:0] sequence_counter, pending_sequence, pending_t1_sec, pending_t1_ns;
    reg outstanding, first_due, have_sample;
    reg [31:0] poll_reference, request_reference, sample_reference, lock_count;
    reg signed [63:0] correction_sec;
    reg [31:0] correction_ns;

    wire [31:0] p_sequence={packet[8],packet[9],packet[10],packet[11]};
    wire [31:0] p_node={packet[12],packet[13],packet[14],packet[15]};
    wire [31:0] p_t1_sec={packet[16],packet[17],packet[18],packet[19]};
    wire [31:0] p_t1_ns={packet[20],packet[21],packet[22],packet[23]};
    wire [31:0] p_t2_sec={packet[24],packet[25],packet[26],packet[27]};
    wire [31:0] p_t2_ns={packet[28],packet[29],packet[30],packet[31]};
    wire [31:0] p_t3_sec={packet[32],packet[33],packet[34],packet[35]};
    wire [31:0] p_t3_ns={packet[36],packet[37],packet[38],packet[39]};
    wire [31:0] elapsed_request=tick_us-request_reference;
    wire [31:0] elapsed_poll=tick_us-poll_reference;
    wire [31:0] elapsed_sample=tick_us-sample_reference;
    assign s_ready=enable && state==RECEIVE && !tx_active;
    assign m_valid=tx_active;
    assign m_last=tx_active && tx_index==47;
    assign set_valid=enable && !IS_MASTER && state==APPLY;
    assign busy=tx_active || outstanding || state!=RECEIVE || rx_count!=0;

    // Signed modular seconds subtraction: valid within half a 32-bit era.
    function signed [63:0] sec_difference;
        input [31:0] a,b;
        reg signed [31:0] difference;
        begin difference=a-b; sec_difference={{32{difference[31]}},difference}; end
    endfunction
    function signed [63:0] time_difference;
        input [31:0] a_sec,a_ns,b_sec,b_ns;
        begin time_difference=sec_difference(a_sec,b_sec)*64'sd1000000000
              +$signed({32'd0,a_ns})-$signed({32'd0,b_ns}); end
    endfunction
    reg header_ok, fields_ok;
    integer k;
    reg signed [63:0] d21,d34,d41,d32,offset_sum,calculated_offset,calculated_delay;
    reg signed [63:0] sum_sec,sum_ns,normalized_sec,normalized_ns,set_sum;
    always @(*) begin
        header_ok=rx_length_ok && packet[0]==8'h41 && packet[1]==8'h46
            && packet[2]==8'h44 && packet[3]==8'h54 && packet[4]==1
            && packet[5]==(IS_MASTER?1:2) && packet[6]==0 && packet[7]==0;
        for(k=40;k<48;k=k+1) if(packet[k]!=0) header_ok=0;
        fields_ok=p_t1_ns<1000000000 && p_t2_ns<1000000000 && p_t3_ns<1000000000;
        if(IS_MASTER && (p_t2_sec!=0 || p_t2_ns!=0 || p_t3_sec!=0 || p_t3_ns!=0)) fields_ok=0;
        d21=time_difference(p_t2_sec,p_t2_ns,p_t1_sec,p_t1_ns);
        d34=time_difference(p_t3_sec,p_t3_ns,rx_time_sec,rx_time_ns);
        d41=time_difference(rx_time_sec,rx_time_ns,p_t1_sec,p_t1_ns);
        d32=time_difference(p_t3_sec,p_t3_ns,p_t2_sec,p_t2_ns);
        offset_sum=d21+d34;
        calculated_offset=offset_sum/64'sd2; // Signed truncation toward zero.
        calculated_delay=d41-d32;
        // Decompose floor(sum / 2) into seconds and subsecond pieces using
        // only shifts and bounded normalization (no wide constant divider).
        sum_sec=sec_difference(p_t2_sec,p_t1_sec)+sec_difference(p_t3_sec,rx_time_sec);
        sum_ns=$signed({32'd0,p_t2_ns})-$signed({32'd0,p_t1_ns})
              +$signed({32'd0,p_t3_ns})-$signed({32'd0,rx_time_ns});
        normalized_sec=sum_sec >>> 1;
        normalized_ns=(sum_ns+(sum_sec[0]?64'sd1000000000:64'sd0)) >>> 1;
        if(offset_sum<0 && offset_sum[0]) normalized_ns=normalized_ns+1;
        if(normalized_ns<0) begin normalized_ns=normalized_ns+1000000000; normalized_sec=normalized_sec-1; end
        if(normalized_ns>=1000000000) begin normalized_ns=normalized_ns-1000000000; normalized_sec=normalized_sec+1; end
        set_sum=$signed({32'd0,rtc_ns})+$signed({32'd0,correction_ns})+TICK_NS;
        set_sec=rtc_sec+correction_sec[31:0];
        if(set_sum>=1000000000) begin set_sum=set_sum-1000000000; set_sec=set_sec+1; end
        if(set_sum>=1000000000) begin set_sum=set_sum-1000000000; set_sec=set_sec+1; end
        set_ns=set_sum[31:0];
    end

    reg [31:0] tx_word;
    always @(*) begin
        tx_word=0;
        case(tx_index[5:2])
          0:tx_word=32'h41464454;
          1:tx_word=IS_MASTER?32'h01020000:32'h01010000;
          2:tx_word=tx_sequence;
          3:tx_word=tx_node;
          4:tx_word=tx_t1_sec;
          5:tx_word=tx_t1_ns;
          6:tx_word=IS_MASTER?tx_t2_sec:32'd0;
          7:tx_word=IS_MASTER?tx_t2_ns:32'd0;
          8:tx_word=IS_MASTER?tx_t3_sec:32'd0;
          9:tx_word=IS_MASTER?tx_t3_ns:32'd0;
          default:tx_word=0;
        endcase
        case(tx_index[1:0])
          0:m_data=tx_word[31:24]; 1:m_data=tx_word[23:16];
          2:m_data=tx_word[15:8]; default:m_data=tx_word[7:0];
        endcase
    end

    always @(posedge clk) begin
      if(rst) begin
        state<=RECEIVE; rx_count<=0; rx_length_ok<=0;
        tx_active<=0; tx_cancel<=0; tx_index<=0;
        tx_sequence<=0; tx_node<=0; tx_t1_sec<=0; tx_t1_ns<=0;
        tx_t2_sec<=0; tx_t2_ns<=0; tx_t3_sec<=0; tx_t3_ns<=0;
        rx_time_sec<=0; rx_time_ns<=0; sequence_counter<=0;
        pending_sequence<=0; pending_t1_sec<=0; pending_t1_ns<=0;
        outstanding<=0; first_due<=1; have_sample<=0;
        poll_reference<=0; request_reference<=0; sample_reference<=0;
        lock_count<=0; correction_sec<=0; correction_ns<=0;
        synced<=0; sync_pulse<=0; last_offset_ns<=0; last_delay_ns<=0;
        stat_applied<=0; stat_rejected<=0; stat_timeout<=0;
      end else begin
        sync_pulse<=0;
        // Once valid has been exposed, drain the complete TX frame even if
        // enable falls. This preserves stable ready/valid obligations.
        if(tx_active && m_ready) begin
          if(tx_index==0) begin
            if(IS_MASTER) begin tx_t3_sec<=rtc_sec; tx_t3_ns<=rtc_ns; end
            else begin
              tx_t1_sec<=rtc_sec; tx_t1_ns<=rtc_ns;
              if(enable && !tx_cancel) begin
                outstanding<=1; pending_sequence<=tx_sequence;
                pending_t1_sec<=rtc_sec; pending_t1_ns<=rtc_ns;
                request_reference<=tick_us;
              end
            end
          end
          if(tx_index==47) begin tx_active<=0; tx_index<=0; tx_cancel<=0; end
          else tx_index<=tx_index+1'b1;
        end
        if(!enable) begin
          state<=RECEIVE; rx_count<=0; outstanding<=0; first_due<=1;
          synced<=0; lock_count<=0; have_sample<=0;
          if(tx_active && !(m_ready && tx_index==47)) tx_cancel<=1;
        end else begin
          if(!IS_MASTER && have_sample && elapsed_sample>=HOLDOVER_US) begin
            synced<=0; lock_count<=0; have_sample<=0;
          end
          // Timeout wins over a reply completed on the deadline.
          if(!IS_MASTER && outstanding && elapsed_request>=TIMEOUT_US) begin
            outstanding<=0; stat_timeout<=stat_timeout+1'b1;
          end
          if(s_valid && s_ready) begin
            if(rx_count==0) begin rx_time_sec<=rtc_sec; rx_time_ns<=rtc_ns; end
            if(rx_count<48) packet[rx_count]<=s_data;
            if(s_last) begin
              rx_length_ok<=(rx_count==47); rx_count<=0; state<=EVALUATE;
            end else if(rx_count<48) rx_count<=rx_count+1'b1;
          end
          if(state==EVALUATE) begin
            state<=RECEIVE;
            if(!header_ok || !fields_ok) stat_rejected<=stat_rejected+1'b1;
            else if(IS_MASTER) begin
              tx_sequence<=p_sequence; tx_node<=p_node;
              tx_t1_sec<=p_t1_sec; tx_t1_ns<=p_t1_ns;
              tx_t2_sec<=rx_time_sec; tx_t2_ns<=rx_time_ns;
              tx_active<=1; tx_cancel<=0; tx_index<=0;
            end else if(!outstanding || elapsed_request>=TIMEOUT_US
                    || p_sequence!=pending_sequence || p_node!=NODE_ID
                    || p_t1_sec!=pending_t1_sec || p_t1_ns!=pending_t1_ns
                    || d32<0 || d32>MAX_RTT_NS
                    || calculated_delay<0 || calculated_delay>MAX_RTT_NS) begin
              stat_rejected<=stat_rejected+1'b1;
            end else begin
              outstanding<=0;
              last_offset_ns<=calculated_offset; last_delay_ns<=calculated_delay;
              correction_sec<=normalized_sec; correction_ns<=normalized_ns[31:0];
              state<=APPLY;
            end
          end
          if(state==APPLY && !IS_MASTER) begin
            state<=RECEIVE; stat_applied<=stat_applied+1'b1; sync_pulse<=1;
            sample_reference<=tick_us; have_sample<=1;
            if(last_offset_ns<=LOCK_THRESHOLD_NS && last_offset_ns>=-LOCK_THRESHOLD_NS) begin
              if(lock_count<LOCK_SAMPLES) lock_count<=lock_count+1'b1;
              if(lock_count+1>=LOCK_SAMPLES) synced<=1;
            end else begin lock_count<=0; synced<=0; end
          end
          if(!IS_MASTER && state==RECEIVE && rx_count==0 && !s_valid
                && !tx_active && !outstanding && (first_due || elapsed_poll>=POLL_US)) begin
            sequence_counter<=sequence_counter+1'b1;
            tx_sequence<=sequence_counter+1'b1; tx_node<=NODE_ID;
            tx_t1_sec<=0; tx_t1_ns<=0;
            tx_active<=1; tx_cancel<=0; tx_index<=0;
            first_due<=0; poll_reference<=tick_us;
          end
        end
      end
    end
endmodule
`default_nettype wire
