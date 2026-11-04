`timescale 1ns / 1ps
`default_nettype none
// Wall clock and independent monotonic microsecond time base. Configuration
// and synchronization do not change tick_us or its fractional phase.
module afdx_rtc #(
    parameter TICK_NS = 80,
    // Wall-clock rate only; supported when abs(TICK_NS * RATE_PPB) < 1e9.
    // Positive values make the wall clock run fast. The monotonic base stays
    // nominal. Use a signed override for negative drift (e.g. -100000).
    parameter integer RATE_PPB = 0
) (
    input wire clk,
    input wire rst,
    input wire cfg_wen,
    input wire [1:0] cfg_op,       // 0: seconds, 1: normalized nanoseconds
    input wire [31:0] cfg_wdata,
    input wire adj_valid,
    input wire adj_sign,           // 0: add, 1: subtract
    input wire [31:0] adj_ns,
    input wire set_valid,
    input wire [31:0] set_sec,
    input wire [31:0] set_ns,
    output reg [31:0] rtc_sec,
    output reg [31:0] rtc_ns,
    output reg [31:0] tick_us,
    output reg pps
);
localparam integer WHOLE_US = TICK_NS / 1000;
localparam integer FRACTION_NS = TICK_NS % 1000;
// Evaluate the product at wide precision before narrowing the supported
// sub-nanosecond increment. No runtime multiplication or division is needed.
localparam signed [63:0] DRIFT_PRODUCT = 64'sd1 * TICK_NS * RATE_PPB;
localparam signed [31:0] DRIFT_PER_TICK = DRIFT_PRODUCT[31:0];
reg [9:0] ns_acc;
reg [10:0] mono_sum;
reg signed [31:0] drift_acc;
reg signed [32:0] drift_sum;
reg signed [31:0] drift_next;
reg signed [1:0] drift_ns;
// A normalized ns field, one clock period, and a full 32-bit adjustment
// fit in 35 signed bits. Explicit constant subtraction avoids a divider.
reg signed [34:0] wall_ns;
reg signed [4:0] sec_delta;
reg [31:0] wall_sec;
reg natural_carry;

always @(*) begin
    mono_sum = {1'b0, ns_acc} + FRACTION_NS;
    drift_sum = {drift_acc[31], drift_acc} +
                {DRIFT_PER_TICK[31], DRIFT_PER_TICK};
    drift_ns = 2'sd0;
    if (drift_sum >= 33'sd1000000000) begin
        drift_sum = drift_sum - 33'sd1000000000;
        drift_ns = 2'sd1;
    end else if (drift_sum <= -33'sd1000000000) begin
        drift_sum = drift_sum + 33'sd1000000000;
        drift_ns = -2'sd1;
    end
    drift_next = drift_sum[31:0];
    wall_sec = rtc_sec;
    wall_ns = $signed({3'd0, rtc_ns}) + TICK_NS + drift_ns;
    natural_carry = (wall_ns >= 35'sd1000000000);
    // A seconds write replaces the second field on this edge. An ns write
    // replaces the subsecond field, carrying whole seconds into it.
    if (cfg_wen && cfg_op == 2'd0) wall_sec = cfg_wdata;
    if (cfg_wen && cfg_op == 2'd1)
        wall_ns = $signed({3'd0, cfg_wdata});
    if (adj_valid) begin
        if (adj_sign) wall_ns = wall_ns - $signed({3'd0, adj_ns});
        else          wall_ns = wall_ns + $signed({3'd0, adj_ns});
    end
    // Network synchronization is atomic and wins over host writes and steps.
    // Load exactly the supplied epoch: this edge adds no nominal wall tick.
    if (set_valid) begin
        wall_sec = set_sec;
        wall_ns = $signed({3'd0, set_ns});
    end
    // Normalize arbitrary 32-bit ns writes and signed adjustments with
    // bounded add/subtract stages, keeping hardware cost predictable.
    sec_delta = 5'sd0;
    if (wall_ns < 0) begin
        wall_ns = wall_ns + 35'sd8000000000;
        sec_delta = -5'sd8;
    end
    if (wall_ns >= 35'sd8000000000) begin
        wall_ns = wall_ns - 35'sd8000000000;
        sec_delta = sec_delta + 5'sd8;
    end
    if (wall_ns >= 35'sd4000000000) begin
        wall_ns = wall_ns - 35'sd4000000000;
        sec_delta = sec_delta + 5'sd4;
    end
    if (wall_ns >= 35'sd2000000000) begin
        wall_ns = wall_ns - 35'sd2000000000;
        sec_delta = sec_delta + 5'sd2;
    end
    if (wall_ns >= 35'sd1000000000) begin
        wall_ns = wall_ns - 35'sd1000000000;
        sec_delta = sec_delta + 5'sd1;
    end
end

always @(posedge clk) begin
    if (rst) begin
        rtc_sec <= 32'd0;
        rtc_ns <= 32'd0;
        tick_us <= 32'd0;
        ns_acc <= 10'd0;
        drift_acc <= 32'sd0;
        pps <= 1'b0;
    end else begin
        ns_acc <= (mono_sum >= 1000) ? mono_sum - 11'd1000 : mono_sum;
        // Phase advances even during a set/write/adjustment; only reset clears it.
        drift_acc <= drift_next;
        tick_us <= tick_us + WHOLE_US + (mono_sum >= 1000);
        rtc_sec <= wall_sec + {{27{sec_delta[4]}}, sec_delta};
        rtc_ns <= wall_ns[31:0];
        // Host writes and time steps do not synthesize PPS edges.
        pps <= natural_carry && !cfg_wen && !adj_valid && !set_valid;
    end
end
endmodule
`default_nettype wire
