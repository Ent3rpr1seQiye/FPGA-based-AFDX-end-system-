`timescale 1ns/1ps
// Bounded ARINC 615A target control files and atomic opaque load-object store.
// See doc/ARINC615A_IMPLEMENTATION_NOTES.md for the supported wire profile.
module afdx_615a_files #(
    parameter integer IMAGE_BYTES=4096,
    parameter integer CONTROL_BYTES=512,
    // Zero disables a policy. Intervals must fit in 31 unsigned bits.
    parameter integer SELECTION_TIMEOUT_US=30000000,
    parameter integer STATUS_INTERVAL_US=1000000
)(
    input wire clk, input wire rst, input wire enable, input wire [31:0] tick_us,
    input wire open_valid, input wire file_write, input wire file_is_client,
    input wire [511:0] filename, input wire [6:0] filename_len,
    input wire [31:0] open_peer_ip,
    output wire open_ready, output reg [15:0] open_error,
    output reg [12:0] open_size,
    input wire [12:0] rd_addr, output reg [7:0] rd_data,
    input wire wr_en, input wire [12:0] wr_addr, input wire [7:0] wr_data,
    input wire file_commit, input wire file_done, input wire file_abort,
    input wire [12:0] file_bytes,
    output reg cmd_valid, input wire cmd_ready,
    output reg cmd_write, output reg [511:0] cmd_name,
    output reg [6:0] cmd_name_len, output reg [31:0] cmd_peer_ip,
    output wire [15:0] cmd_peer_port,
    output reg [3:0] load_state, output reg [15:0] operation_status,
    output reg [7:0] progress, output reg image_valid,
    output reg [12:0] image_size, output reg [31:0] image_crc,
    output reg [31:0] stat_success, output reg [31:0] stat_failure
);
localparam [511:0] LUI={"TARGET.LUI",432'b0}, LUR={"TARGET.LUR",432'b0},
    LUS={"TARGET.LUS",432'b0}, LNO={"TARGET.LNO",432'b0},
    LNL={"TARGET.LNL",432'b0}, LNA={"TARGET.LNA",432'b0}, LNS={"TARGET.LNS",432'b0};
localparam [3:0] K_NONE=0,K_LUI=1,K_LUR=2,K_LUS=3,K_LNO=4,
    K_LNL=5,K_LNA=6,K_LNS=7,K_IMAGE_RX=8,K_IMAGE_TX=9;
localparam [3:0] P_NONE=0,P_U_ACCEPT=1,P_U_PROGRESS=2,P_FETCH=3,
    P_D_ACCEPT=4,P_LIST=5,P_D_PROGRESS=6,P_SEND=7,P_TERMINAL=8,P_PERIODIC=9;
localparam [3:0] S_IDLE=0,S_UPLOAD_WAIT=1,S_UPLOAD_DATA=2,
    S_DOWNLOAD_WAIT=3,S_DOWNLOAD_DATA=4,S_COMPLETE=5,S_FAILED=6;
reg [7:0] bank0 [0:IMAGE_BYTES-1];
reg [7:0] bank1 [0:IMAGE_BYTES-1];
reg [7:0] control [0:CONTROL_BYTES-1];
reg active, bank_select, op_download, rx_bad, commit_seen;
reg [3:0] active_kind, decoded_kind, pending_purpose, active_purpose;
reg [12:0] rx_count, parse_size;
reg [31:0] crc_work, peer_ip;
reg [511:0] object_name, part_number, committed_name, committed_part;
reg [6:0] object_len, part_len, committed_len, committed_part_len;
reg [7:0] version_low;
// Read-only files are snapshots: retransmission is byte identical.
reg [15:0] snap_status, snap_counter, status_counter;
reg [7:0] snap_progress;
reg [511:0] snap_name, snap_part;
reg [6:0] snap_name_len,snap_part_len;
reg [12:0] active_size;
reg [3:0] parse_state;
reg [12:0] parse_pos;
reg [7:0] str_length, str_pos;
reg parse_bad;
// A consumed command remains reserved until its matching client open.
reg command_outstanding, wait_armed;
reg [31:0] tick_last, wait_elapsed, status_elapsed;
integer off, sz, idx;
reg [7:0] value;
wire busy_operation=(load_state==S_UPLOAD_WAIT || load_state==S_UPLOAD_DATA ||
                     load_state==S_DOWNLOAD_WAIT || load_state==S_DOWNLOAD_DATA);
wire open_accepted=open_valid && open_ready && open_error==0;
wire wait_idle=enable && wait_armed &&
              (load_state==S_UPLOAD_WAIT || load_state==S_DOWNLOAD_WAIT) &&
              !active && !cmd_valid && !command_outstanding && parse_state==0 && !open_accepted;
wire [31:0] tick_delta=tick_us-tick_last;
wire [32:0] wait_sum={1'b0,wait_elapsed}+{1'b0,tick_delta};
wire [32:0] status_sum={1'b0,status_elapsed}+{1'b0,tick_delta};
assign open_ready=enable && !active && parse_state==0;
assign cmd_peer_port=16'd69;

function [7:0] name_byte;
 input [511:0] s; input integer n;
 begin name_byte=(n>=0 && n<64) ? s[511-n*8 -: 8] : 8'd0; end
endfunction
function [31:0] crc_byte;
 input [31:0] c; input [7:0] b;
 reg [31:0] t; integer j;
 begin t=c^{24'd0,b}; for(j=0;j<8;j=j+1) t=t[0] ? (t>>1)^32'hedb88320 : t>>1; crc_byte=t; end
endfunction
function reserved_name;
 input [511:0] n;
 begin reserved_name=(n==LUI || n==LUR || n==LUS || n==LNO || n==LNL || n==LNA || n==LNS); end
endfunction

// Queue one client request. The transport serializes client and server files.
task queue_request;
 input [3:0] purpose; input wr; input [511:0] n; input [6:0] len;
 begin
  cmd_valid<=1'b1; cmd_write<=wr; cmd_name<=n; cmd_name_len<=len;
  cmd_peer_ip<=peer_ip; pending_purpose<=purpose;command_outstanding<=1'b1;
 end
endtask
task queue_status;
 input [3:0] purpose;
 begin queue_request(purpose,1'b1,op_download ? LNS:LUS,7'd10); end
endtask
task fail_operation;
 input [15:0] code; input deliver;
 begin
  operation_status<=code; load_state<=S_FAILED; stat_failure<=stat_failure+1'b1;
  wait_armed<=0;
  if(deliver) queue_status(P_TERMINAL);
 end
endtask

always @* begin
 decoded_kind=K_NONE; open_error=16'd0; open_size=13'd0;
 if(filename_len==10 && filename==LUI && !file_write && !file_is_client) decoded_kind=K_LUI;
 else if(filename_len==10 && filename==LNO && !file_write && !file_is_client) decoded_kind=K_LNO;
 else if(filename_len==10 && filename==LUR && file_write && !file_is_client) decoded_kind=K_LUR;
 else if(filename_len==10 && filename==LNA && file_write && !file_is_client) decoded_kind=K_LNA;
 else if(filename_len==10 && filename==LUS && !file_write) decoded_kind=K_LUS;
 else if(filename_len==10 && filename==LNS && !file_write) decoded_kind=K_LNS;
 else if(filename_len==10 && filename==LNL && !file_write) decoded_kind=K_LNL;
 // Client WRQ sends local data, therefore file_write is zero on the file API.
 else if(file_is_client && file_write && pending_purpose==P_FETCH && filename==object_name && filename_len==object_len) decoded_kind=K_IMAGE_RX;
 else if(!file_write && image_valid && filename==committed_name && filename_len==committed_len) decoded_kind=K_IMAGE_TX;
 if(decoded_kind==K_NONE) open_error=file_write ? 16'd2:16'd1;
 if((decoded_kind==K_LUI || decoded_kind==K_LNO) && (busy_operation || cmd_valid || command_outstanding)) open_error=16'd2;
 if(decoded_kind==K_LUR && (load_state!=S_UPLOAD_WAIT || op_download || !wait_armed || cmd_valid || command_outstanding)) open_error=16'd2;
 if(decoded_kind==K_LNA && (load_state!=S_DOWNLOAD_WAIT || !op_download || !wait_armed || cmd_valid || command_outstanding)) open_error=16'd2;
 if((decoded_kind==K_LUR || decoded_kind==K_LNA) && open_peer_ip!=peer_ip) open_error=16'd2;
 if(file_is_client && (!command_outstanding || filename!=cmd_name || filename_len!=cmd_name_len)) open_error=16'd2;
 case(decoded_kind)
 K_LUI,K_LNO:open_size=13'd10;
 K_LUS:open_size=21+(object_len!=0 ? object_len+part_len+11:0);
 K_LNS:open_size=21+(committed_len!=0 ? committed_len+6:0);
 K_LNL:open_size=8+(image_valid ? committed_len+4:0);
 K_IMAGE_TX:open_size=image_size;
 default:open_size=0;
 endcase
end

// All control-file integers are big endian. Strings include their trailing NUL.
always @* begin
 rd_data=8'd0; off=0; sz=active_size; idx=rd_addr; value=0;
 if(active_kind==K_IMAGE_TX) begin
  if(rd_addr<image_size) rd_data=bank_select ? bank1[rd_addr]:bank0[rd_addr];
 end else if(rd_addr<active_size) begin
  if(idx<4) rd_data=(sz >> ((3-idx)*8));
  else if(idx==4) rd_data="A";
  else if(idx==5) rd_data=version_low;
  else if(active_kind==K_LUI || active_kind==K_LNO) begin
   case(idx) 6:rd_data=snap_status[15:8];7:rd_data=snap_status[7:0];8:rd_data=1;default:rd_data=0;endcase
  end else if(active_kind==K_LNL) begin
   if(idx==7) rd_data=image_valid ? 1:0;
   else if(idx==8) rd_data=snap_name_len+1'b1;
   else if(idx>=9 && idx<9+snap_name_len) rd_data=name_byte(snap_name,idx-9);
   else if(idx==10+snap_name_len) rd_data=1;
  end else begin
   case(idx)
    6:rd_data=snap_status[15:8];7:rd_data=snap_status[7:0];
    8:rd_data=1;9:rd_data=0;10:rd_data=snap_counter[15:8];11:rd_data=snap_counter[7:0];
    12,13,14,15:rd_data=0;
    16:rd_data=0;
    17:rd_data=0;
    18:rd_data=snap_progress;
    19:rd_data=0;20:rd_data=(snap_name_len!=0);
    default: begin
     if(idx==21) rd_data=snap_name_len+1'b1;
     else if(idx>=22 && idx<22+snap_name_len) rd_data=name_byte(snap_name,idx-22);
     else if(active_kind==K_LUS) begin
      off=23+snap_name_len;
      if(idx==off) rd_data=snap_part_len+1'b1;
      else if(idx>off && idx<=off+snap_part_len) rd_data=name_byte(snap_part,idx-off-1);
      else begin
       off=off+snap_part_len+2;
       if(idx==off) rd_data=0;
       else if(idx==off+1) rd_data=0;
       else if(idx==off+2) rd_data=snap_progress;
       else if(idx==off+3) rd_data=snap_status[15:8];
       else if(idx==off+4) rd_data=snap_status[7:0];
       else if(idx==off+5) rd_data=1;
      end
     end else begin
      off=23+snap_name_len;
      if(idx==off) rd_data=snap_status[15:8];
      else if(idx==off+1) rd_data=snap_status[7:0];
      else if(idx==off+2) rd_data=1;
     end
    end
   endcase
  end
 end
end

always @(posedge clk) begin
 if(rst) begin
  active<=0;active_kind<=0;active_purpose<=0;pending_purpose<=0;cmd_valid<=0;
  cmd_write<=0;cmd_name<=0;cmd_name_len<=0;cmd_peer_ip<=0;peer_ip<=0;
  bank_select<=0;op_download<=0;rx_bad<=0;commit_seen<=0;rx_count<=0;crc_work<=32'hffffffff;
  object_name<=0;object_len<=0;part_number<=0;part_len<=0;
  committed_name<=0;committed_len<=0;committed_part<=0;committed_part_len<=0;
  version_low<="4";snap_status<=0;snap_counter<=0;status_counter<=0;snap_progress<=0;
  snap_name<=0;snap_part<=0;snap_name_len<=0;snap_part_len<=0;active_size<=0;
  parse_state<=0;parse_pos<=0;parse_size<=0;parse_bad<=0;str_length<=0;str_pos<=0;
  load_state<=S_IDLE;operation_status<=0;progress<=0;image_valid<=0;image_size<=0;image_crc<=0;
  stat_success<=0;stat_failure<=0;
  command_outstanding<=0;wait_armed<=0;tick_last<=tick_us;wait_elapsed<=0;status_elapsed<=0;
 end else begin
  tick_last<=tick_us;
  // Modular deltas handle tick wrap. Count only idle selection waiting, not
  // TFTP service, command backpressure, command-to-open latency or parsing.
  if(wait_idle) begin
   wait_elapsed<=wait_sum[32] ? 32'hffffffff:wait_sum[31:0];
   status_elapsed<=status_sum[32] ? 32'hffffffff:status_sum[31:0];
   if(SELECTION_TIMEOUT_US!=0 && wait_sum>=SELECTION_TIMEOUT_US)
    fail_operation(16'h1003,1'b1);
   else if(STATUS_INTERVAL_US!=0 && status_sum>=STATUS_INTERVAL_US) begin
    queue_status(P_PERIODIC);status_elapsed<=0;
   end
  end
  if(cmd_valid && cmd_ready) cmd_valid<=0;
  if(open_accepted) begin
   active<=1;active_kind<=decoded_kind;active_size<=open_size;
   if(file_is_client) command_outstanding<=0;
   if(decoded_kind==K_LUR || decoded_kind==K_LNA) wait_armed<=0;
   active_purpose<=file_is_client ? pending_purpose:P_NONE;
   rx_count<=0;rx_bad<=0;commit_seen<=0;crc_work<=32'hffffffff;
   snap_status<=operation_status;snap_progress<=progress;snap_counter<=status_counter;
   if(decoded_kind==K_LUS) begin
    snap_name<=object_name;snap_name_len<=object_len;snap_part<=part_number;snap_part_len<=part_len;
   end else begin
    snap_name<=committed_name;snap_name_len<=committed_len;
    snap_part<=committed_part;snap_part_len<=committed_part_len;
   end
   if(decoded_kind==K_LUI || decoded_kind==K_LNO) begin
    peer_ip<=open_peer_ip;op_download<=(decoded_kind==K_LNO);
    operation_status<=decoded_kind==K_LNO && !image_valid ? 16'h1000:16'h0001;
    snap_status<=decoded_kind==K_LNO && !image_valid ? 16'h1000:16'h0001;
    progress<=0;status_counter<=0;
    wait_armed<=0;wait_elapsed<=0;status_elapsed<=0;
    load_state<=decoded_kind==K_LUI ? S_UPLOAD_WAIT:(image_valid ? S_DOWNLOAD_WAIT:S_FAILED);
    if(decoded_kind==K_LUI) begin object_name<=0;object_len<=0;part_number<=0;part_len<=0;end
   end
  end
  if(active && file_commit) commit_seen<=1;
  if(active && wr_en) begin
   if(wr_addr!=rx_count) rx_bad<=1;
   if(active_kind==K_IMAGE_RX) begin
    if(wr_addr<IMAGE_BYTES) begin
     if(bank_select) bank0[wr_addr]<=wr_data;else bank1[wr_addr]<=wr_data;
     crc_work<=crc_byte(crc_work,wr_data);
     progress<=((wr_addr+1)*99)/IMAGE_BYTES;
    end else rx_bad<=1;
   end else if(active_kind==K_LUR || active_kind==K_LNA) begin
    if(wr_addr<CONTROL_BYTES) control[wr_addr]<=wr_data;else rx_bad<=1;
   end else rx_bad<=1;
   if(rx_count<8191) rx_count<=rx_count+1'b1;else rx_bad<=1;
  end
  if(active && file_abort) begin
   active<=0;
   if(!(active_purpose==P_TERMINAL && load_state==S_FAILED) &&
      (active_purpose!=P_NONE || active_kind==K_LUI || active_kind==K_LNO || active_kind==K_LUR || active_kind==K_LNA))
    fail_operation(16'h1003,active_kind!=K_LUS && active_kind!=K_LNS);
  end else if(active && file_done) begin
   active<=0;
   case(active_kind)
    K_LUI:queue_request(P_U_ACCEPT,1'b1,LUS,7'd10);
    K_LNO:if(image_valid) queue_request(P_D_ACCEPT,1'b1,LNS,7'd10);
    K_LUR,K_LNA:begin
     if(rx_bad || !(commit_seen || file_commit) || file_bytes!=rx_count || file_bytes>CONTROL_BYTES || file_bytes<10)
      fail_operation(16'h1000,1'b1);
     else begin parse_state<=1;parse_size<=file_bytes;parse_bad<=0;end
    end
    K_IMAGE_RX:begin
     if(rx_bad || !(commit_seen || file_commit) || file_bytes!=rx_count || file_bytes>IMAGE_BYTES)
      fail_operation(16'h1003,1'b1);
     else begin
      bank_select<=!bank_select;image_valid<=1;image_size<=file_bytes;image_crc<=~crc_work;
      committed_name<=object_name;committed_len<=object_len;
      committed_part<=part_number;committed_part_len<=part_len;
      progress<=100;operation_status<=3;load_state<=S_COMPLETE;stat_success<=stat_success+1'b1;
      queue_status(P_TERMINAL);
     end
    end
    K_IMAGE_TX:if(active_purpose==P_SEND) begin
     progress<=100;operation_status<=3;load_state<=S_COMPLETE;stat_success<=stat_success+1'b1;queue_status(P_TERMINAL);
    end
    K_LNL:if(active_purpose==P_LIST) begin
     load_state<=S_DOWNLOAD_WAIT;wait_armed<=1;wait_elapsed<=0;status_elapsed<=0;
    end
    K_LUS,K_LNS:begin
     status_counter<=status_counter+1'b1;
     case(active_purpose)
      P_U_ACCEPT:begin wait_armed<=1;wait_elapsed<=0;status_elapsed<=0;end
      P_U_PROGRESS:begin load_state<=S_UPLOAD_DATA;queue_request(P_FETCH,1'b0,object_name,object_len);end
      P_D_ACCEPT:queue_request(P_LIST,1'b1,LNL,7'd10);
      P_D_PROGRESS:begin load_state<=S_DOWNLOAD_DATA;queue_request(P_SEND,1'b1,committed_name,committed_len);end
      default:begin end
     endcase
    end
    default:begin end
   endcase
  end
  // One byte per cycle parser: bounded strings, exact length/count, no paths.
  case(parse_state)
   1:begin
    if({control[0],control[1],control[2],control[3]}!={19'd0,parse_size} ||
       control[4]!="A" || (control[5]!="3" && control[5]!="4") || control[6]!=0 || control[7]!=1)
     begin parse_state<=0;fail_operation(16'h1000,1'b1);end
    else begin version_low<=control[5];str_length<=control[8];str_pos<=0;parse_pos<=9;
     object_name<=0;object_len<=0;parse_state<=2;
     if(control[8]<2 || control[8]>64 || 9+control[8]>parse_size) parse_bad<=1;
    end
   end
   2:begin
    if(parse_bad) begin parse_state<=0;fail_operation(16'h1000,1'b1);end
    else if(str_pos+1==str_length) begin
     if(control[parse_pos]!=0) parse_bad<=1;
     object_len<=str_length-1;parse_pos<=parse_pos+1'b1;parse_state<=3;
    end else begin
     if(control[parse_pos]<33 || control[parse_pos]>126 || control[parse_pos]=="/" || control[parse_pos]==8'h5c || control[parse_pos]==":") parse_bad<=1;
     object_name[511-str_pos*8 -:8]<=control[parse_pos];str_pos<=str_pos+1'b1;parse_pos<=parse_pos+1'b1;
    end
   end
   3:begin
    if(parse_bad || reserved_name(object_name) || (op_download && (object_name!=committed_name || object_len!=committed_len))) begin
     parse_state<=0;fail_operation(16'h1000,1'b1);
    end else if(op_download) begin
     parse_state<=0;
     if(parse_pos!=parse_size) fail_operation(16'h1000,1'b1);
     else begin operation_status<=2;queue_status(P_D_PROGRESS);end
    end else begin
     str_length<=control[parse_pos];str_pos<=0;part_number<=0;part_len<=0;
     if(parse_pos>=parse_size || control[parse_pos]<2 || control[parse_pos]>64 || parse_pos+1+control[parse_pos]!=parse_size) parse_bad<=1;
     parse_pos<=parse_pos+1'b1;parse_state<=4;
    end
   end
   4:begin
    if(parse_bad) begin parse_state<=0;fail_operation(16'h1000,1'b1);end
    else if(str_pos+1==str_length) begin
     part_len<=str_length-1;parse_state<=0;
     if(control[parse_pos]!=0) fail_operation(16'h1000,1'b1);
     else begin operation_status<=2;queue_status(P_U_PROGRESS);end
    end else begin
     if(control[parse_pos]<32 || control[parse_pos]>126) parse_bad<=1;
     part_number[511-str_pos*8 -:8]<=control[parse_pos];str_pos<=str_pos+1'b1;parse_pos<=parse_pos+1'b1;
    end
   end
   default:begin end
  endcase
 end
end
endmodule

