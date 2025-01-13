import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, conf
import threading

global stop_sniffing
stop_sniffing = False

def packet_handler(packet):
    if stop_sniffing:
        return
    packet_summary = packet.summary()
    text_area.insert(tk.END, packet_summary + "\n")
    text_area.yview(tk.END)  # Auto-scroll to the latest packet

# Function to start sniffing in a thread
def start_sniffing():
    global stop_sniffing
    stop_sniffing = False
    global sniff_thread
    sniff_thread = threading.Thread(target=lambda: sniff(iface=conf.iface, prn=packet_handler, store=False), daemon=True)
    sniff_thread.start()

# Function to stop sniffing
def stop_sniffing_func():
    global stop_sniffing
    stop_sniffing = True

# Create GUI
root = tk.Tk()
root.title("Network Sniffer")
root.geometry("600x400")

label = tk.Label(root, text="Captured Packets:")
label.pack()

text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=20)
text_area.pack()

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack()

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing_func)
stop_button.pack()

root.mainloop()
