`timescale 1ns/1ps
`default_nettype none
// 615A control-file state machine above the RFC1350 transport.
module afdx_loader #(
    parameter IMAGE_BYTES=4096, TIMEOUT_US=20000, MAX_RETRIES=3
)(
    input wire clk,rst,enable,input wire [31:0] tick_us,
    input wire [7:0] s_data,input wire s_valid,s_last,output wire s_ready,
    input wire [31:0] s_src_ip,input wire [15:0] s_src_port,s_dst_port,
    output wire [7:0] m_data,output wire m_valid,m_last,input wire m_ready,
    output wire [31:0] m_dst_ip,output wire [15:0] m_src_port,m_dst_port,
    output wire [3:0] load_state,output wire [15:0] operation_status,
    output wire [7:0] progress,output wire image_valid,
    output wire [12:0] image_size,output wire [31:0] image_crc,
    output wire [31:0] stat_success,stat_failure,stat_retries,stat_errors
);
wire cmd_valid,cmd_ready,cmd_write,open_valid,open_ready,file_write,file_is_client;
wire [511:0] cmd_name,filename;
wire [6:0] cmd_name_len,filename_len;
wire [31:0] cmd_peer_ip,file_peer_ip;
wire [15:0] cmd_peer_port,open_error;
wire [12:0] open_size,rd_addr,wr_addr,file_bytes;
wire [7:0] rd_data,wr_data;
wire wr_en,file_commit,file_done,file_abort,busy;
wire [31:0] stat_done;
afdx_tftp #(.MAX_FILE_BYTES(IMAGE_BYTES),.TIMEOUT_US(TIMEOUT_US),.MAX_RETRIES(MAX_RETRIES)) u_tftp (
    .clk(clk),.rst(rst),.enable(enable),.tick_us(tick_us),
    .s_data(s_data),.s_valid(s_valid),.s_last(s_last),.s_ready(s_ready),
    .s_src_ip(s_src_ip),.s_src_port(s_src_port),.s_dst_port(s_dst_port),
    .m_data(m_data),.m_valid(m_valid),.m_last(m_last),.m_ready(m_ready),
    .m_dst_ip(m_dst_ip),.m_src_port(m_src_port),.m_dst_port(m_dst_port),
    .cmd_valid(cmd_valid),.cmd_ready(cmd_ready),.cmd_write(cmd_write),
    .cmd_name(cmd_name),.cmd_name_len(cmd_name_len),.cmd_peer_ip(cmd_peer_ip),.cmd_peer_port(cmd_peer_port),
    .open_valid(open_valid),.open_ready(open_ready),.open_error(open_error),.open_size(open_size),
    .file_write(file_write),.file_is_client(file_is_client),.filename(filename),.filename_len(filename_len),
    .rd_addr(rd_addr),.rd_data(rd_data),.wr_en(wr_en),.wr_addr(wr_addr),.wr_data(wr_data),
    .file_commit(file_commit),.file_done(file_done),.file_abort(file_abort),.file_bytes(file_bytes),
    .file_peer_ip(file_peer_ip),.busy(busy),.stat_done(stat_done),.stat_retries(stat_retries),.stat_errors(stat_errors));
afdx_615a_files #(.IMAGE_BYTES(IMAGE_BYTES)) u_files (
    .clk(clk),.rst(rst),.enable(enable),.tick_us(tick_us),
    .open_valid(open_valid),.open_ready(open_ready),.open_error(open_error),.open_size(open_size),
    .file_write(file_write),.file_is_client(file_is_client),.filename(filename),.filename_len(filename_len),
    .open_peer_ip(file_peer_ip),.rd_addr(rd_addr),.rd_data(rd_data),
    .wr_en(wr_en),.wr_addr(wr_addr),.wr_data(wr_data),.file_commit(file_commit),
    .file_done(file_done),.file_abort(file_abort),.file_bytes(file_bytes),
    .cmd_valid(cmd_valid),.cmd_ready(cmd_ready),.cmd_write(cmd_write),.cmd_name(cmd_name),
    .cmd_name_len(cmd_name_len),.cmd_peer_ip(cmd_peer_ip),.cmd_peer_port(cmd_peer_port),
    .load_state(load_state),.operation_status(operation_status),.progress(progress),
    .image_valid(image_valid),.image_size(image_size),.image_crc(image_crc),
    .stat_success(stat_success),.stat_failure(stat_failure));
endmodule
`default_nettype wire
