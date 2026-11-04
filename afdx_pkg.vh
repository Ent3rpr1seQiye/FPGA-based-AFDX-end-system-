//-----------------------------------------------------------------------------
// afdx_pkg.vh - ARINC 664 Part 7 (AFDX) common constants
//-----------------------------------------------------------------------------

// AFDX destination MAC: constant 32-bit field followed by 16-bit VLID
// dst_mac = {32'h0300_0000, vlid[15:0]}  -> bytes on wire: 03 00 00 00 VLH VLL
`define AFDX_DST_MAC_CONST   32'h0300_0000
`define AFDX_ETHTYPE_IPV4    16'h0800
`define AFDX_IP_PROTO_UDP    8'd17
`define AFDX_IP_VERSION_IHL  8'h45
`define AFDX_UDP_CHECKSUM    16'h0000        // UDP checksum disabled per A664p7

// Payload / frame limits (ARINC 664 P7: Lmax up to 1471 B payload)
`define AFDX_MAX_PAYLOAD     1471
`define AFDX_MAX_FRAME       1518

// BAG codes: BAG = (1 << code) ms, code 0..7 -> 1,2,4,8,16,32,64,128 ms
`define AFDX_BAG_1MS         3'd0
`define AFDX_BAG_2MS         3'd1
`define AFDX_BAG_4MS         3'd2
`define AFDX_BAG_8MS         3'd3
`define AFDX_BAG_16MS        3'd4
`define AFDX_BAG_32MS        3'd5
`define AFDX_BAG_64MS        3'd6
`define AFDX_BAG_128MS       3'd7

// RX port types
`define AFDX_PORT_SAMPLING   1'b0
`define AFDX_PORT_QUEUING    1'b1

// Config bus address map (word addressed)
//  0x00000-0x000FF : global registers
//  0x01000-0x01FFF : TX VL table  (entry i at 0x1000 + i*4, 3 words used)
//  0x10000-0x1FFFF : RX VL table  (entry vlid at 0x10000 + vlid, 1 word)
`define CFG_GLOBAL_BASE      20'h00000
`define CFG_TXVL_BASE        20'h01000
`define CFG_RXVL_BASE        20'h10000
