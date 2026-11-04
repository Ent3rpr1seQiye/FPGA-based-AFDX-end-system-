// Bounded SNMPv2c UDP-payload agent. One datagram outstanding.
module afdx_snmp_agent #(
    parameter MAX_PACKET=1471, parameter TICK_NS=8,
    parameter N_TX_VL=128, parameter N_RX_VL=4096
)(
    input wire clk, input wire rst,
    input wire [7:0] s_data, input wire s_valid, output wire s_ready, input wire s_last,
    output reg [7:0] m_data, output wire m_valid, input wire m_ready, output wire m_last,
    output wire busy, output reg [19:0] stats_addr, input wire [31:0] stats_data
);
    localparam RX=0, HEADER=1, VERSION=2, COMMUNITY=3, PDU=4,
      RID=5, ERR=6, IDX=7, LIST=8, VB=9, OID=10, OIDCOPY=11,
      VALUE=12, SEARCH=13, FILL=14, COPYVALUE=15, NEXTVB=16,
      FINALIZE=17, SEND=18, DISCARD=19;
    reg [4:0] state;
    reg [7:0] packet[0:MAX_PACKET-1];
    integer rx_count, packet_len, p, seq_end, pdu_end, list_end, vb_end;
    integer tlv_start, tlv_len, tlv_end;
    reg parse_ok;
    integer comm_start, comm_len, rid_start, rid_len;
    reg private_comm;
    reg [7:0] pdu_tag;
    integer nvb, vi, copy_pos, oid_start, oid_len, val_start, val_len;
    reg [7:0] val_tag;
    reg [31:0] arcs[0:31];
    integer arc_count, oid_group_bytes;
    reg [32:0] arc_acc, arc_next;
    reg oid_first;
    integer candidate, selected, compare_result, prefix_result;
    reg known_object;
    reg [7:0] roid[0:255], rval[0:255];
    integer olen[0:7], vlen[0:7], blen[0:7];
    reg [7:0] vtag[0:7];
    reg [7:0] contact[0:31], sysname[0:31], location[0:31];
    reg [7:0] stage_contact[0:31], stage_name[0:31], stage_location[0:31];
    integer contact_len, name_len, location_len, stage_contact_len, stage_name_len, stage_location_len;
    reg [7:0] error_status, error_index;
    integer raw_list_start, raw_list_len;
    integer list_length, pdu_length, msg_length, total_length;
    integer phase, pos, out_vb, tx_count;
    reg [63:0] tick_fraction;
    reg [31:0] uptime;
    reg [31:0] number_value;
    integer integer_length, a, b, c, k;
    reg [7:0] cb;
    reg malformed;

    assign s_ready=(state==RX || state==DISCARD);
    assign busy=(state!=RX || rx_count!=0);
    assign m_valid=(state==SEND);
    assign m_last=(state==SEND && tx_count==total_length-1);

    // Only definite BER lengths of 0..65535, with complete enclosing bounds.
    task read_tlv;
      input integer at;
      input integer bound;
      input [7:0] tag;
      integer ll;
      begin
        parse_ok=0; tlv_start=0; tlv_len=0; tlv_end=0; ll=0;
        if(at>=0 && at+2<=bound && bound<=packet_len) begin
          if(tag==0 || packet[at]==tag) begin
            if(packet[at+1]<128) begin ll=packet[at+1]; tlv_start=at+2; end
            else if(packet[at+1]==8'h81 && at+3<=bound) begin ll=packet[at+2]; tlv_start=at+3; end
            else if(packet[at+1]==8'h82 && at+4<=bound) begin ll={packet[at+2],packet[at+3]}; tlv_start=at+4; end
            if(tlv_start!=0 && ll<=bound-tlv_start) begin
              tlv_len=ll; tlv_end=tlv_start+ll; parse_ok=1;
            end
          end
        end
      end
    endtask
    function integer length_octets;
      input integer n;
      begin if(n<128) length_octets=1; else if(n<256) length_octets=2; else length_octets=3; end
    endfunction
    function [7:0] length_byte;
      input integer n; input integer offset;
      begin
        if(n<128) length_byte=n;
        else if(n<256) begin if(offset==0) length_byte=8'h81; else length_byte=n; end
        else case(offset) 0:length_byte=8'h82; 1:length_byte=n>>8; default:length_byte=n; endcase
      end
    endfunction
    function integer object_arc;
      input integer obj; input integer idx;
      begin
        case(idx)
          0:object_arc=1; 1:object_arc=3; 2:object_arc=6; 3:object_arc=1;
          4:if(obj<=7) object_arc=2; else object_arc=3;
          5:if(obj<=7) object_arc=1; else object_arc=999;
          6:object_arc=1;
          7:if(obj<=7) object_arc=obj; else object_arc=obj-7;
          default:object_arc=0;
        endcase
      end
    endfunction
    function [7:0] object_byte;
      input integer obj; input integer idx;
      begin
        if(obj<=7) case(idx)
          0:object_byte=43; 1:object_byte=6; 2:object_byte=1;
          3:object_byte=2; 4:object_byte=1; 5:object_byte=1;
          6:object_byte=obj; default:object_byte=0;
        endcase
        else case(idx)
          0:object_byte=43; 1:object_byte=6; 2:object_byte=1;
          3:object_byte=3; 4:object_byte=8'h87; 5:object_byte=8'h67;
          6:object_byte=1; 7:object_byte=obj-7; default:object_byte=0;
        endcase
      end
    endfunction
    function [7:0] descr_byte;
      input integer idx;
      reg [183:0] str;
      begin str="AFDX FPGA SNMPv2c agent"; descr_byte=str[(22-idx)*8+:8]; end
    endfunction
    function integer uint_length;
      input [31:0] n;
      begin
        if(n<128) uint_length=1; else if(n<32768) uint_length=2;
        else if(n<8388608) uint_length=3; else if(n<2147483648) uint_length=4; else uint_length=5;
      end
    endfunction

    always @* begin
      stats_addr=20'h00020;
      if(selected>=10 && selected<=16) stats_addr=20'h00020+selected-10;
      m_data=0;
      case(phase)
        0:m_data=8'h30;
        1:m_data=length_byte(msg_length,pos);
        2:case(pos) 0:m_data=2; 1:m_data=1; default:m_data=1; endcase
        3:m_data=4;
        4:m_data=comm_len;
        5:if(comm_start+pos<MAX_PACKET) m_data=packet[comm_start+pos];
        6:m_data=8'ha2;
        7:m_data=length_byte(pdu_length,pos);
        8:m_data=2;
        9:m_data=rid_len;
        10:if(rid_start+pos<MAX_PACKET) m_data=packet[rid_start+pos];
        11:case(pos) 0:m_data=2; 1:m_data=1; default:m_data=error_status; endcase
        12:case(pos) 0:m_data=2; 1:m_data=1; default:m_data=error_index; endcase
        13:m_data=8'h30;
        14:m_data=length_byte(list_length,pos);
        15:if(raw_list_start+pos<MAX_PACKET) m_data=packet[raw_list_start+pos];
        16:m_data=8'h30;
        17:m_data=length_byte(blen[out_vb],pos);
        18:m_data=6;
        19:m_data=olen[out_vb];
        20:m_data=roid[out_vb*32+pos];
        21:m_data=vtag[out_vb];
        22:m_data=vlen[out_vb];
        23:m_data=rval[out_vb*32+pos];
        default:m_data=0;
      endcase
    end

    always @(posedge clk) begin
      if(rst) begin
        state<=RX; rx_count<=0; packet_len<=0; tick_fraction<=0; uptime<=0;
        contact_len<=0; name_len<=9; location_len<=0;
        phase<=0; pos<=0; selected<=0; tx_count<=0;
        // Unused string bytes need no reset; their lengths gate all accesses.
        sysname[0]<= "a"; sysname[1]<= "f"; sysname[2]<= "d";
        sysname[3]<= "x"; sysname[4]<= "-"; sysname[5]<= "f";
        sysname[6]<= "p"; sysname[7]<= "g"; sysname[8]<= "a";
      end else begin
        if(tick_fraction+TICK_NS>=10000000) begin
          tick_fraction<=tick_fraction+TICK_NS-10000000; uptime<=uptime+1'b1;
        end else tick_fraction<=tick_fraction+TICK_NS;
        case(state)
          RX:if(s_valid) begin
            if(rx_count<MAX_PACKET) packet[rx_count]<=s_data;
            if(s_last) begin
              packet_len<=rx_count+1; rx_count<=0; state<=HEADER;
            end else if(rx_count==MAX_PACKET-1) begin rx_count<=0; state<=DISCARD; end
            else rx_count<=rx_count+1;
          end
          DISCARD:if(s_valid && s_last) begin state<=RX; rx_count<=0; end
          HEADER:begin
            error_status<=0; error_index<=0; nvb<=0; vi<=0; selected<=0;
            stage_contact_len<=contact_len; stage_name_len<=name_len; stage_location_len<=location_len;
            for(k=0;k<32;k=k+1) begin stage_contact[k]<=contact[k]; stage_name[k]<=sysname[k]; stage_location[k]<=location[k]; end
            read_tlv(0,packet_len,8'h30);
            if(parse_ok && tlv_end==packet_len) begin p<=tlv_start; seq_end<=tlv_end; state<=VERSION; end
            else state<=RX;
          end
          VERSION:begin
            read_tlv(p,seq_end,2);
            if(parse_ok && tlv_len==1 && packet[tlv_start]==1) begin p<=tlv_end; state<=COMMUNITY; end else state<=RX;
          end
          COMMUNITY:begin
            read_tlv(p,seq_end,4);
            if(parse_ok && ((tlv_len==6 && packet[tlv_start]=="p" && packet[tlv_start+1]=="u" && packet[tlv_start+2]=="b" && packet[tlv_start+3]=="l" && packet[tlv_start+4]=="i" && packet[tlv_start+5]=="c") ||
              (tlv_len==7 && packet[tlv_start]=="p" && packet[tlv_start+1]=="r" && packet[tlv_start+2]=="i" && packet[tlv_start+3]=="v" && packet[tlv_start+4]=="a" && packet[tlv_start+5]=="t" && packet[tlv_start+6]=="e"))) begin
              private_comm<=tlv_len==7; comm_start<=tlv_start; comm_len<=tlv_len; p<=tlv_end; state<=PDU;
            end else state<=RX;
          end
          PDU:begin
            read_tlv(p,seq_end,0);
            if(parse_ok && tlv_end==seq_end && (packet[p]==8'ha0 || packet[p]==8'ha1 || packet[p]==8'ha3)) begin
              pdu_tag<=packet[p]; p<=tlv_start; pdu_end<=tlv_end; state<=RID;
            end else state<=RX;
          end
          RID:begin
            read_tlv(p,pdu_end,2);
            if(parse_ok && tlv_len>=1 && tlv_len<=4) begin rid_start<=tlv_start; rid_len<=tlv_len; p<=tlv_end; state<=ERR; end else state<=RX;
          end
          ERR,IDX:begin
            read_tlv(p,pdu_end,2);
            malformed=0;
            for(k=0;k<4;k=k+1) if(k<tlv_len && packet[tlv_start+k]!=0) malformed=1;
            if(parse_ok && tlv_len>=1 && tlv_len<=4 && !malformed) begin p<=tlv_end; if(state==ERR) state<=IDX; else state<=LIST; end else state<=RX;
          end
          LIST:begin
            read_tlv(p,pdu_end,8'h30);
            if(parse_ok && tlv_end==pdu_end) begin
              p<=tlv_start; raw_list_start<=tlv_start; raw_list_len<=tlv_len; list_end<=tlv_end;
              if(tlv_len==0) state<=FINALIZE; else state<=VB;
            end else state<=RX;
          end
          VB:begin
            read_tlv(p,list_end,8'h30);
            if(parse_ok && vi<8) begin vb_end<=tlv_end; p<=tlv_start; state<=OID; end else state<=RX;
          end
          OID:begin
            read_tlv(p,vb_end,6);
            if(parse_ok && tlv_len>=1 && tlv_len<=32) begin
              oid_start<=tlv_start; oid_len<=tlv_len; olen[vi]<=tlv_len;
              p<=tlv_end; copy_pos<=0; arc_count<=0; arc_acc<=0; oid_first<=1; oid_group_bytes<=0; state<=OIDCOPY;
            end else state<=RX;
          end
          OIDCOPY:begin
            cb=packet[oid_start+copy_pos];
            roid[vi*32+copy_pos]<=cb;
            // OID subidentifiers fit the RFC2578 unsigned 32-bit arc limit.
            arc_next=(arc_acc<<7)|(cb&127);
            if((oid_group_bytes==0 && cb==8'h80) || oid_group_bytes>=5 || arc_acc>33'h03ffffff || arc_count>31 ||
               (oid_first && arc_next>33'h10000004f) || (!oid_first && arc_next>33'h0ffffffff)) state<=RX;
            else begin
              arc_acc<=arc_next;
              if(!cb[7]) begin
                if(oid_first) begin
                  if(arc_next<40) begin arcs[0]<=0; arcs[1]<=arc_next; end
                  else if(arc_next<80) begin arcs[0]<=1; arcs[1]<=arc_next-40; end
                  else begin arcs[0]<=2; arcs[1]<=arc_next-80; end
                  arc_count<=2; oid_first<=0;
                end else begin arcs[arc_count]<=arc_next; arc_count<=arc_count+1; end
                arc_acc<=0; oid_group_bytes<=0;
              end else oid_group_bytes<=oid_group_bytes+1;
              if(copy_pos==oid_len-1) begin if(cb[7]) state<=RX; else state<=VALUE; end
              else copy_pos<=copy_pos+1;
            end
          end
          VALUE:begin
            read_tlv(p,vb_end,0);
            if(parse_ok && tlv_end==vb_end) begin
              val_start<=tlv_start; val_len<=tlv_len; val_tag<=packet[p];
              candidate<=1; known_object<=0; state<=SEARCH;
            end else state<=RX;
          end
          SEARCH:begin
            compare_result=0; prefix_result=1;
            for(k=0;k<32;k=k+1) begin
              if(k<8 && (k>=arc_count || arcs[k]!=object_arc(candidate,k))) prefix_result=0;
              if(k<9 && compare_result==0) begin
                if(k>=arc_count) compare_result=1;
                else if(object_arc(candidate,k)>arcs[k]) compare_result=1;
                else if(object_arc(candidate,k)<arcs[k]) compare_result=-1;
              end
            end
            if(compare_result==0 && arc_count>9) compare_result=-1;
            if(prefix_result) known_object<=1;
            if((pdu_tag==8'ha1 && compare_result>0) || (pdu_tag!=8'ha1 && compare_result==0)) begin selected<=candidate; state<=FILL; end
            else if(candidate==16) begin selected<=0; state<=FILL; end
            else candidate<=candidate+1;
          end
          FILL:begin
            copy_pos<=0;
            if(pdu_tag==8'ha3) begin
              // First error wins. No state is committed until all varbinds pass.
              a=0;
              if(!private_comm) a=6;
              else if(selected==0) a=11;
              else if(selected!=4 && selected!=5 && selected!=6) a=17;
              else if(val_tag!=4) a=7;
              else if(val_len>32) a=8;
              if(error_status==0 && a!=0) begin error_status<=a; error_index<=vi+1; end
              vtag[vi]<=val_tag; vlen[vi]<=val_len;
              state<=COPYVALUE;
            end else if(selected==0) begin
              if(pdu_tag==8'ha1) vtag[vi]<=8'h82;
              else if(known_object) vtag[vi]<=8'h81; else vtag[vi]<=8'h80;
              vlen[vi]<=0; state<=NEXTVB;
            end else begin
              if(pdu_tag==8'ha1) begin
                if(selected<=7) olen[vi]<=8; else olen[vi]<=9;
                for(k=0;k<9;k=k+1) roid[vi*32+k]<=object_byte(selected,k);
              end
              if(selected==1) begin vtag[vi]<=4; vlen[vi]<=23; state<=COPYVALUE; end
              else if(selected==2) begin
                vtag[vi]<=6; vlen[vi]<=7;
                for(k=0;k<7;k=k+1) rval[vi*32+k]<=object_byte(8,k);
                state<=NEXTVB;
              end else if(selected==4 || selected==5 || selected==6) begin
                vtag[vi]<=4;
                if(selected==4) vlen[vi]<=contact_len; else if(selected==5) vlen[vi]<=name_len; else vlen[vi]<=location_len;
                state<=COPYVALUE;
              end else begin
                if(selected==3) begin number_value=uptime; vtag[vi]<=8'h43; end
                else if(selected==7) begin number_value=72; vtag[vi]<=2; end
                else if(selected==8) begin number_value=N_TX_VL; vtag[vi]<=2; end
                else if(selected==9) begin number_value=N_RX_VL; vtag[vi]<=2; end
                else begin number_value=stats_data; vtag[vi]<=8'h41; end
                integer_length=uint_length(number_value); vlen[vi]<=integer_length;
                for(k=0;k<5;k=k+1) if(k<integer_length) begin
                  if(integer_length==5 && k==0) rval[vi*32+k]<=0;
                  else rval[vi*32+k]<=number_value>>((integer_length-1-k)*8);
                end
                state<=NEXTVB;
              end
            end
          end
          COPYVALUE:begin
            if(pdu_tag==8'ha3) begin
              if(copy_pos<val_len && copy_pos<32) begin
                cb=packet[val_start+copy_pos]; rval[vi*32+copy_pos]<=cb;
                if(private_comm && val_tag==4 && val_len<=32 && (selected==4 || selected==5 || selected==6)) begin
                  if(cb<32 || cb>126) begin if(error_status==0) begin error_status<=10; error_index<=vi+1; end end
                  if(selected==4) stage_contact[copy_pos]<=cb;
                  else if(selected==5) stage_name[copy_pos]<=cb;
                  else stage_location[copy_pos]<=cb;
                end
              end
              if(copy_pos>=val_len || copy_pos>=31) begin
                if(selected==4) stage_contact_len<=val_len;
                else if(selected==5) stage_name_len<=val_len;
                else if(selected==6) stage_location_len<=val_len;
                state<=NEXTVB;
              end else copy_pos<=copy_pos+1;
            end else begin
              if(copy_pos<vlen[vi]) begin
                if(selected==1) rval[vi*32+copy_pos]<=descr_byte(copy_pos);
                else if(selected==4) rval[vi*32+copy_pos]<=contact[copy_pos];
                else if(selected==5) rval[vi*32+copy_pos]<=sysname[copy_pos];
                else rval[vi*32+copy_pos]<=location[copy_pos];
              end
              if(copy_pos+1>=vlen[vi]) state<=NEXTVB; else copy_pos<=copy_pos+1;
            end
          end
          NEXTVB:begin
            nvb<=vi+1; p<=vb_end;
            if(vb_end==list_end) state<=FINALIZE;
            else if(vi==7) state<=RX;
            else begin vi<=vi+1; state<=VB; end
          end
          FINALIZE:begin
            a=0;
            for(k=0;k<8;k=k+1) if(k<nvb) begin
              b=2+olen[k]+2+vlen[k]; blen[k]<=b; a=a+1+length_octets(b)+b;
            end
            if(error_status!=0) a=raw_list_len;
            b=2+rid_len+6+1+length_octets(a)+a;
            c=3+2+comm_len+1+length_octets(b)+b;
            if(1+length_octets(c)+c>MAX_PACKET) begin
              // tooBig response has an empty variable-bindings list (RFC3416).
              error_status<=1; error_index<=0; a=0;
              b=2+rid_len+6+2; c=3+2+comm_len+1+length_octets(b)+b;
            end else if(pdu_tag==8'ha3 && error_status==0) begin
              contact_len<=stage_contact_len; name_len<=stage_name_len; location_len<=stage_location_len;
              for(k=0;k<32;k=k+1) begin contact[k]<=stage_contact[k]; sysname[k]<=stage_name[k]; location[k]<=stage_location[k]; end
            end
            list_length<=a; pdu_length<=b; msg_length<=c; total_length<=1+length_octets(c)+c;
            phase<=0; pos<=0; out_vb<=0; tx_count<=0;
            if(1+length_octets(c)+c<=MAX_PACKET) state<=SEND; else state<=RX;
          end
          SEND:if(m_ready) begin
            tx_count<=tx_count+1; pos<=pos+1;
            if(tx_count==total_length-1) begin state<=RX; rx_count<=0; end
            else case(phase)
              0:begin phase<=1; pos<=0; end
              1:if(pos+1==length_octets(msg_length)) begin phase<=2; pos<=0; end
              2:if(pos==2) begin phase<=3; pos<=0; end
              3:begin phase<=4; pos<=0; end
              4:begin phase<=5; pos<=0; end
              5:if(pos+1==comm_len) begin phase<=6; pos<=0; end
              6:begin phase<=7; pos<=0; end
              7:if(pos+1==length_octets(pdu_length)) begin phase<=8; pos<=0; end
              8:begin phase<=9; pos<=0; end
              9:begin phase<=10; pos<=0; end
              10:if(pos+1==rid_len) begin phase<=11; pos<=0; end
              11:if(pos==2) begin phase<=12; pos<=0; end
              12:if(pos==2) begin phase<=13; pos<=0; end
              13:begin phase<=14; pos<=0; end
              14:if(pos+1==length_octets(list_length)) begin
                pos<=0; if(error_status!=0) phase<=15; else phase<=16;
              end
              16:begin phase<=17; pos<=0; end
              17:if(pos+1==length_octets(blen[out_vb])) begin phase<=18; pos<=0; end
              18:begin phase<=19; pos<=0; end
              19:begin phase<=20; pos<=0; end
              20:if(pos+1==olen[out_vb]) begin phase<=21; pos<=0; end
              21:begin phase<=22; pos<=0; end
              22:begin pos<=0; if(vlen[out_vb]!=0) phase<=23;
                 else begin out_vb<=out_vb+1; phase<=16; end end
              23:if(pos+1==vlen[out_vb]) begin out_vb<=out_vb+1; phase<=16; pos<=0; end
              default:begin end
            endcase
          end
          default:state<=RX;
        endcase
      end
    end
endmodule



