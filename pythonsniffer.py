import socket
import os

HOST = '192.168.100.2'

def main():
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    # Create raw socket
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))


    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        print("Sniffer started... Press CTRL+C to stop.\n")
        while True:
            raw_data, addr = sniffer.recvfrom(65565)
            print(f"Packet from {addr}: {raw_data[:50]}...")
    except KeyboardInterrupt:
        print("\nStopping sniffer...")

    finally:
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sniffer.close()

if __name__ == '__main__':
    main()
