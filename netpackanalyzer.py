#!usr/bin/env python
import socket
import struct
import textwrap

#to represt information in tabs and more redable
tab1='\t - '
tab2='\t\t - '
tab3='\t\t\t - '
tab4='\t\t\t\t - '

dat_tab1='\t '
dat_tab2='\t\t '
dat_tab3='\t\t\t '
dat_tab4='\t\t\t\t '

def main():
    conn=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while true:
        rdata, adr=conn.recvfrom(65536)
        dm,sm,pt,data=ethernetpacket(rdata)

        if pt=8:
            ver, headlen, ttl, prot, src, dest, data=ipv4extract(data)
            print(tab1+"IPv4 packet")
            print(tab2+'VERSION: {}, HEADER: {}, TIME TO LIVE: {}, PROTOCOL: {}, SOURCE IP: {}, DESTINATION IP:{}'.format(ver, headlen, ttl, prot, src, dest)) # header displayed

            if prot==1:  #ICMP
                type, code, csum = icmp_unpack(data)
                print(tab1+ "ICMP packet")
                print(tab2+ 'TYPE: {}, CODE: {}, CHECKSUM: {}'.format(type, code, csum))
                print(tab3+ "DATA EXTRACTED")
                print(multi_line(dat_tab3, data))

            elif prot==6: # tcp
                s_port, d_port, seq, ack, fl_urg, fl_ack, fl_psh, fl_rst, fl_syn, fl_fin=tcp_unpack(data)
                print(tab1+ "TCP packet")
                print(tab2+ "S_PORT: {}, D_PORT, SEQUENCE: {}, ACKNOWLEDGE: {}". format(s_port, d_port, seq, ack))
                print(tab3+ "FLAGS")
                print(tab3+ "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(fl_urg, fl_ack, fl_psh, fl_rst, fl_syn, fl_fin))
                print(tab1+ "DATA")
                print(tab2+multi_line(dat_tab3, data))

            elif prot==17:
                s_port, d_port, size=udp(data)
                print(tab1+ "UDP PACKET")
                print(tab2+ "SOURCE_PORT: {}, DEST_PORT: {}, SIZE: {}".format(s_port, d_port, size))
                print(tab3+ "DATA")
                print(tab3+multi_line(dat_tab3, data))

            else:
                print(tab1+"OTHER DATA")
                print(tab2+ multi_line(dat_tab3, data))


#unpacking ethernet packet
def ethernetpacket(data):
    dmac,smac,ver=struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dmac), get_mac_addr(smac), socket.htons(ver), data[14:]

#display mac address
def get_mac_addr(data_mac):
    pr_mac= map('{02x}'.format, data_mac)
    return ":".join(pr_mac).upper()

def ipv4extract(data):
    verhl=data[0]
    ver=verhl>>4
    headlen=(verhl&15)*4
    ttl,prot,src,dest=struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ver, headlen, ttl, prot, ipv4(src), ipv4(dest), data[headlen:]

def ipv4(address):
    return '.'.join(str,address)

#unpack icmp
def icmp_unpack(data):
    type, code, csum=struct.unpack('! B B H', data[:4])
    return type, code, csum, data[4:]

#unpack tcp
def tcp_unpack(data):
    s_port, d_port, seq, ack, off_flag=struct.unpack('! H H L L H', data[:12])
    off=(off_flag >> 12)*4
    fl_urg=(off_flag & 32) >> 5
    fl_ack=(off_flag & 16) >> 4
    fl_psh=(off_flag & 8) >> 3
    fl_rst=(off_flag & 4) >> 2
    fl_syn=(off_flag & 2) >> 1
    fl_fin=off_flag & 1
    return s_port, d_port, seq, ack, fl_urg, fl_ack, fl_psh, fl_rst, fl_syn, fl_fin, data[off:]

#unpack udp
def udp(data):
    s_port, d_port, size=struct.unpack('! H H 2x H', data[:8])
    return s_port, d_port, size, data[8:]

#multi line data formatting
def multi_line(prefix, str, size=80):
    size-=len(prefix)
    if isinstance(str, bytes):
        str=''.join(r'\x{:02x}'.format(byte) for byte in str)
        if size%2:
            size-=1
    return '\n'.join ([prefix + line for in textwrap.wrap(str, size)])
main()
