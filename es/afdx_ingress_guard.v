`timescale 1ns/1ps
`default_nettype none
// Packet token bucket in clock ticks. A rejected GMII frame is marked RX_ER
// throughout its DV interval so the normal MAC discards the complete frame.
module afdx_ingress_guard #(
 parameter integer TICK_NS=8, GAP_US=64, BURST=2
)(
 input wire clk,rst,enable,
 input wire rx_dv,
 output wire reject_error,
 output reg [31:0] stat_admitted,stat_rejected
);
localparam integer COST=(GAP_US*1000+TICK_NS-1)/TICK_NS;
localparam integer CAPACITY=BURST*COST;
reg [31:0] credit;
reg active,rejected;
wire start=rx_dv&&!active;
wire [31:0] replenished=credit<CAPACITY ? credit+1'b1:CAPACITY;
wire admit=replenished>=COST;
assign reject_error=enable&&rx_dv&&(active?rejected:!admit);
always @(posedge clk)begin
 if(rst)begin credit<=CAPACITY;active<=0;rejected<=0;stat_admitted<=0;stat_rejected<=0;end
 else begin
  active<=rx_dv;
  credit<=replenished;
  if(start)begin
   rejected<=enable&&!admit;
   if(!enable||admit)begin
    stat_admitted<=stat_admitted+1'b1;
    if(enable)credit<=replenished-COST;
   end else stat_rejected<=stat_rejected+1'b1;
  end
 end
end
endmodule
`default_nettype wire
