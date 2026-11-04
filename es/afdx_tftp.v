// RFC 1350 octet transport. UDP metadata and payload only; one live session.
module afdx_tftp #(
    parameter MAX_FILE_BYTES=4096, parameter TIMEOUT_US=20000,
    parameter MAX_RETRIES=3, parameter LOCAL_TID_BASE=49160
)(
    input wire clk, input wire rst, input wire enable, input wire [31:0] tick_us,
    input wire [7:0] s_data, input wire s_valid, input wire s_last, output wire s_ready,
    input wire [31:0] s_src_ip, input wire [15:0] s_src_port, input wire [15:0] s_dst_port,
    output wire [7:0] m_data, output wire m_valid, output wire m_last, input wire m_ready,
    output wire [31:0] m_dst_ip, output wire [15:0] m_src_port, output wire [15:0] m_dst_port,
    input wire cmd_valid, output wire cmd_ready, input wire cmd_write,
    input wire [511:0] cmd_name, input wire [6:0] cmd_name_len,
    input wire [31:0] cmd_peer_ip, input wire [15:0] cmd_peer_port,
    output wire open_valid, input wire open_ready, input wire [15:0] open_error,
    input wire [12:0] open_size, output reg file_write, output reg file_is_client,
    output reg [511:0] filename, output reg [6:0] filename_len,
    output wire [12:0] rd_addr, input wire [7:0] rd_data,
    output reg wr_en, output reg [12:0] wr_addr, output reg [7:0] wr_data,
    output reg file_commit, output reg file_done, output reg file_abort,
    output reg [12:0] file_bytes, output wire [31:0] file_peer_ip, output wire busy,
    output reg [31:0] stat_done, output reg [31:0] stat_retries, output reg [31:0] stat_errors
);
localparam IDLE=0, OPEN=1, REQUEST=2, BUILD=3, WAIT=4, WRITE=5;
reg [2:0] state;
reg [7:0] rx_mem[0:515];
reg [9:0] rx_count, rx_len;
reg rx_collect,rx_pending,rx_over;
reg [31:0] rx_ip;
reg [15:0] rx_src,rx_dst;
reg [7:0] tx_mem[0:515];
reg [9:0] tx_len,tx_idx;
reg tx_active,tx_finish,tx_timer;
reg [31:0] tx_ip;
reg [15:0] tx_src,tx_dst;
// Side replies never overwrite the retained retransmission packet.
reg aux_active,aux_ack;
reg [2:0] aux_idx;
reg [15:0] aux_value,aux_src,aux_dst;
reg [31:0] aux_ip;
reg [31:0] peer_ip;
reg [15:0] peer_port,local_port,next_tid,block;
reg peer_pinned,client_push;
reg [12:0] read_size,offset;
reg [9:0] data_len,copy_idx;
reg [31:0] last_send;
reg timer_armed;
reg [15:0] retry_count;
reg cache_valid;
reg [31:0] cache_ip,cache_time;
reg [15:0] cache_src,cache_dst,cache_block;
wire [15:0] rx_opcode={rx_mem[0],rx_mem[1]};
wire [15:0] rx_block={rx_mem[2],rx_mem[3]};
wire [31:0] elapsed=tick_us-last_send;
wire [31:0] cache_elapsed=tick_us-cache_time;
assign busy=(state!=IDLE);
assign file_peer_ip=peer_ip;
assign open_valid=(state==OPEN);
assign cmd_ready=enable && state==IDLE && !rx_collect && !rx_pending && !tx_active && !aux_active && !s_valid;
assign s_ready=enable && !rx_pending && state!=OPEN && state!=REQUEST && state!=BUILD && state!=WRITE;
assign rd_addr=offset+copy_idx;
assign m_valid=aux_active || tx_active;
assign m_data=aux_active ? ((aux_idx==0)?8'd0:(aux_idx==1)?(aux_ack?8'd4:8'd5):(aux_idx==2)?aux_value[15:8]:(aux_idx==3)?aux_value[7:0]:8'd0) : tx_mem[tx_idx];
assign m_last=aux_active ? (aux_idx==(aux_ack?3:4)) : (tx_idx==tx_len-1'b1);
assign m_dst_ip=aux_active?aux_ip:tx_ip;
assign m_src_port=aux_active?aux_src:tx_src;
assign m_dst_port=aux_active?aux_dst:tx_dst;
reg req_ok;
reg [511:0] req_name;
reg [6:0] req_n;
integer q,term;
reg bad_name;
always @* begin
    req_ok=0; req_name=0; req_n=0; term=0; bad_name=0;
    for(q=0;q<64;q=q+1) begin
        if(term==0) begin
            if(rx_mem[q+2]==0) term=q+2;
            else if(q<63) begin
                req_name[511-q*8 -: 8]=rx_mem[q+2]; req_n=q+1;
                if(rx_mem[q+2]<33 || rx_mem[q+2]>126 || rx_mem[q+2]==47 || rx_mem[q+2]==92 || rx_mem[q+2]==58) bad_name=1;
                if(q>0 && rx_mem[q+2]==46 && rx_mem[q+1]==46) bad_name=1;
            end else bad_name=1;
        end
    end
    if(term>=3 && !bad_name && rx_len==term+7 &&
       (rx_mem[term+1]|8'h20)==8'h6f && (rx_mem[term+2]|8'h20)==8'h63 &&
       (rx_mem[term+3]|8'h20)==8'h74 && (rx_mem[term+4]|8'h20)==8'h65 &&
       (rx_mem[term+5]|8'h20)==8'h74 && rx_mem[term+6]==0) req_ok=1;
end
reg cmd_name_ok;
integer c;
integer k;
always @* begin
    cmd_name_ok=(cmd_name_len>0 && cmd_name_len<=63);
    for(c=0;c<63;c=c+1) if(c<cmd_name_len) begin
        if(cmd_name[511-c*8 -: 8]<33 || cmd_name[511-c*8 -: 8]>126 ||
           cmd_name[511-c*8 -: 8]==47 || cmd_name[511-c*8 -: 8]==92 || cmd_name[511-c*8 -: 8]==58) cmd_name_ok=0;
        if(c>0 && cmd_name[511-c*8 -: 8]==46 && cmd_name[519-c*8 -: 8]==46) cmd_name_ok=0;
    end
end
// Tasks only schedule registers in the clocked process.
task side_reply;
input ack; input [15:0] value; input [31:0] ip; input [15:0] src,dst;
begin aux_active<=1;aux_idx<=0;aux_ack<=ack;aux_value<=value;aux_ip<=ip;aux_src<=src;aux_dst<=dst; end
endtask
task send_ack;
input [15:0] number; input finish;
begin
 tx_mem[0]<=0;tx_mem[1]<=4;tx_mem[2]<=number[15:8];tx_mem[3]<=number[7:0];
 tx_len<=4;tx_idx<=0;tx_active<=1;tx_finish<=finish;tx_timer<=!finish;
 tx_ip<=peer_ip;tx_src<=local_port;tx_dst<=peer_port;timer_armed<=0;
end
endtask
task fail_session;
input [15:0] code;
begin
 side_reply(0,code,peer_ip,local_port,peer_port);
 file_abort<=1;stat_errors<=stat_errors+1'b1;state<=IDLE;timer_armed<=0;
end
endtask
task prepare_data;
begin
 if(read_size-offset>=512) data_len<=512; else data_len<=read_size-offset;
 copy_idx<=0;state<=BUILD;timer_armed<=0;
 tx_mem[0]<=0;tx_mem[1]<=3;tx_mem[2]<=block[15:8];tx_mem[3]<=block[7:0];
end
endtask
always @(posedge clk) begin
 if(rst) begin
  state<=IDLE;rx_count<=0;rx_len<=0;rx_collect<=0;rx_pending<=0;rx_over<=0;
  tx_active<=0;tx_idx<=0;tx_len<=0;tx_finish<=0;tx_timer<=0;aux_active<=0;aux_idx<=0;aux_ack<=0;aux_value<=0;aux_ip<=0;aux_src<=0;aux_dst<=0;
  tx_ip<=0;tx_src<=0;tx_dst<=0;peer_ip<=0;peer_port<=0;local_port<=0;
  next_tid<=(LOCAL_TID_BASE==0 || LOCAL_TID_BASE==69)?49160:LOCAL_TID_BASE;
  block<=1;peer_pinned<=0;client_push<=0;read_size<=0;offset<=0;data_len<=0;copy_idx<=0;
  last_send<=0;timer_armed<=0;retry_count<=0;cache_valid<=0;cache_time<=0;cache_ip<=0;cache_src<=0;cache_dst<=0;cache_block<=0;
  file_write<=0;file_is_client<=0;filename<=0;filename_len<=0;file_bytes<=0;
  wr_en<=0;wr_addr<=0;wr_data<=0;file_commit<=0;file_done<=0;file_abort<=0;stat_done<=0;stat_retries<=0;stat_errors<=0;
 end else begin
  wr_en<=0;file_commit<=0;file_done<=0;file_abort<=0;
  if(cache_valid && cache_elapsed>TIMEOUT_US*(MAX_RETRIES+2)) cache_valid<=0;
  if(s_valid && s_ready) begin
   if(!rx_collect) begin
    rx_ip<=s_src_ip;rx_src<=s_src_port;rx_dst<=s_dst_port;rx_over<=0;
    rx_mem[0]<=s_data;rx_count<=1;rx_collect<=!s_last;
    if(s_last) begin rx_len<=1;rx_pending<=1; end
   end else begin
    if(rx_count<516) rx_mem[rx_count]<=s_data;else rx_over<=1;
    if(rx_count<1023) rx_count<=rx_count+1'b1;else rx_over<=1;
    if(s_last) begin rx_collect<=0;rx_len<=rx_count+1'b1;rx_pending<=1; end
   end
  end
  if(aux_active && m_ready) begin
   if(m_last) begin aux_active<=0;aux_idx<=0;end else aux_idx<=aux_idx+1'b1;
  end else if(tx_active && m_ready) begin
   if(m_last) begin
    tx_active<=0;tx_idx<=0;
    if(tx_timer) begin last_send<=tick_us;timer_armed<=1;end
    if(tx_finish) begin file_done<=1;stat_done<=stat_done+1'b1;state<=IDLE;timer_armed<=0; end
   end else tx_idx<=tx_idx+1'b1;
  end
  if(!tx_active && !aux_active) begin
   if(cmd_valid && cmd_ready) begin
    filename<=cmd_name;filename_len<=cmd_name_len;file_is_client<=1;file_write<=!cmd_write;client_push<=cmd_write;
    file_bytes<=0;offset<=0;block<=1;peer_ip<=cmd_peer_ip;peer_port<=(cmd_peer_port==0)?16'd69:cmd_peer_port;
    local_port<=next_tid;next_tid<=(next_tid==65535)?16'd49160:((next_tid==68)?16'd70:next_tid+1'b1);
    peer_pinned<=0;retry_count<=0;timer_armed<=0;
    if(cmd_name_ok) state<=OPEN;else begin file_abort<=1;stat_errors<=stat_errors+1'b1; end
   end else if(state==OPEN && open_ready) begin
    if(open_error!=0 || (!file_write && open_size>MAX_FILE_BYTES)) begin
     if(file_is_client) begin file_abort<=1;stat_errors<=stat_errors+1'b1;state<=IDLE;end
     else fail_session((open_error!=0)?open_error:16'd3);
    end else begin
     read_size<=open_size;
     if(file_is_client) begin copy_idx<=0;state<=REQUEST; end
     else if(file_write) begin send_ack(0,0);state<=WAIT;end
     else begin data_len<=(open_size>=512)?512:open_size;copy_idx<=0;state<=BUILD;
      tx_mem[0]<=0;tx_mem[1]<=3;tx_mem[2]<=0;tx_mem[3]<=1;end
    end
   end else if(state==REQUEST) begin
    tx_mem[0]<=0;tx_mem[1]<=client_push?2:1;
    // A bounded fixed loop copies the command filename and exact octet mode.
    for(k=0;k<63;k=k+1) if(k<filename_len) tx_mem[k+2]<=filename[511-k*8 -: 8];
    tx_mem[filename_len+2]<=0;tx_mem[filename_len+3]<=8'h6f;tx_mem[filename_len+4]<=8'h63;
    tx_mem[filename_len+5]<=8'h74;tx_mem[filename_len+6]<=8'h65;tx_mem[filename_len+7]<=8'h74;tx_mem[filename_len+8]<=0;
    tx_len<=filename_len+9;tx_idx<=0;tx_active<=1;tx_finish<=0;tx_timer<=1;
    tx_ip<=peer_ip;tx_src<=local_port;tx_dst<=peer_port;state<=WAIT;
   end else if(state==BUILD) begin
    if(copy_idx<data_len) begin tx_mem[copy_idx+4]<=rd_data;copy_idx<=copy_idx+1'b1;end
    else begin tx_len<=data_len+4;tx_idx<=0;tx_active<=1;tx_finish<=0;tx_timer<=1;
     tx_ip<=peer_ip;tx_src<=local_port;tx_dst<=peer_port;state<=WAIT;end
   end else if(state==WRITE) begin
    if(copy_idx<data_len) begin
     wr_en<=1;wr_addr<=offset+copy_idx;wr_data<=rx_mem[copy_idx+4];copy_idx<=copy_idx+1'b1;file_bytes<=offset+copy_idx+1'b1;
    end else begin
     offset<=offset+data_len;file_bytes<=offset+data_len;block<=block+1'b1;retry_count<=0;
     if(data_len<512) begin
      file_commit<=1;cache_valid<=1;cache_ip<=peer_ip;cache_src<=peer_port;cache_dst<=local_port;cache_block<=block;cache_time<=tick_us;
     end
     send_ack(block,data_len<512);state<=WAIT;
    end
   end else if(rx_pending) begin
    rx_pending<=0;
    // A recently completed RX session keeps its independent EOF ACK identity.
    if(cache_valid && !rx_over && rx_len>=4 && rx_len<516 && rx_opcode==3 && rx_block==cache_block && rx_ip==cache_ip && rx_src==cache_src && rx_dst==cache_dst) begin
     side_reply(1,cache_block,cache_ip,cache_dst,cache_src);
    end else if(state==IDLE) begin
     if(rx_dst==69) begin
      if(!rx_over && rx_len>=4 && (rx_opcode==1 || rx_opcode==2) && req_ok) begin
       filename<=req_name;filename_len<=req_n;file_is_client<=0;file_write<=(rx_opcode==2);client_push<=0;
       peer_ip<=rx_ip;peer_port<=rx_src;local_port<=next_tid;next_tid<=(next_tid==65535)?16'd49160:((next_tid==68)?16'd70:next_tid+1'b1);
       peer_pinned<=1;block<=1;offset<=0;file_bytes<=0;retry_count<=0;timer_armed<=0;state<=OPEN;
      end else begin side_reply(0,4,rx_ip,69,rx_src);stat_errors<=stat_errors+1'b1;end
     end else if(rx_opcode!=5) side_reply(0,5,rx_ip,rx_dst,rx_src);
    end else if(state==WAIT) begin
     if(rx_dst!=local_port || rx_ip!=peer_ip || (peer_pinned && rx_src!=peer_port)) begin
      if(rx_opcode!=5) side_reply(0,5,rx_ip,rx_dst,rx_src);
     end else if(rx_over || rx_len<4) fail_session(4);
     else if(rx_opcode==5) begin
      file_abort<=1;stat_errors<=stat_errors+1'b1;state<=IDLE;timer_armed<=0;
     end else if(!peer_pinned && !((file_write && rx_opcode==3 && rx_block==1 && rx_len<=516) || (!file_write && rx_opcode==4 && rx_block==0 && rx_len==4))) begin
      side_reply(0,5,rx_ip,local_port,rx_src);
     end else if(file_write && rx_opcode==3 && rx_len<=516) begin
      if(rx_block==block) begin
       if(offset+rx_len-4>MAX_FILE_BYTES) fail_session(3);
       else begin
        if(!peer_pinned) begin peer_port<=rx_src;peer_pinned<=1;end
        data_len<=rx_len-4;copy_idx<=0;state<=WRITE;timer_armed<=0;
       end
      end else if(rx_block==block-1'b1) begin send_ack(rx_block,0);end
      // Other out-of-order DATA are ignored; timeout retains the last ACK.
     end else if(!file_write && rx_opcode==4 && rx_len==4) begin
      if(!peer_pinned && rx_block==0) begin
       peer_port<=rx_src;peer_pinned<=1;retry_count<=0;prepare_data;
      end else if(peer_pinned && rx_block==block) begin
       retry_count<=0;timer_armed<=0;file_bytes<=offset+data_len;
       if(data_len<512) begin file_done<=1;stat_done<=stat_done+1'b1;state<=IDLE;end
       else begin
        offset<=offset+data_len;block<=block+1'b1;copy_idx<=0;state<=BUILD;
        if(read_size-offset-data_len>=512) data_len<=512;else data_len<=read_size-offset-data_len;
        tx_mem[0]<=0;tx_mem[1]<=3;tx_mem[2]<=(block+1'b1)>>8;tx_mem[3]<=block+1'b1;
       end
      end
      // Stale ACK deliberately does not retransmit DATA (RFC 1350 fix).
     end else fail_session(4);
    end
   end else if(state==WAIT && timer_armed && elapsed>=TIMEOUT_US && !rx_collect) begin
    if(retry_count<MAX_RETRIES) begin
     retry_count<=retry_count+1'b1;stat_retries<=stat_retries+1'b1;tx_idx<=0;tx_active<=1;timer_armed<=0;
    end else begin file_abort<=1;stat_errors<=stat_errors+1'b1;state<=IDLE;timer_armed<=0;end
   end
  end
 end
end
endmodule

