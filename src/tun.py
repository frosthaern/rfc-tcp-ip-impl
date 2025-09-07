import os
import fcntl
import struct
import subprocess
from typing import Optional, Callable
import threading
import select


class Tun:
    TUNSETIFF = 0x400454CA
    TUNSETOWNER = 0x400454CC
    TUNSETGROUP = 0x400454CE
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

    def __init__(self, name: str = "tun0", mtu: int = 1500):
        self.name = name
        self.mtu = mtu
        self.fd: int = -1
        self.is_open = False
        self.packet_handler: Optional[Callable[[bytes], None]] = None
        self.running = False
        self.read_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def create(self, ip_addr: str, netmask: str = "255.255.255.0") -> bool:
        with self._lock:
            if self.is_open:
                return True
            try:
                self.fd = os.open("/dev/net/tun", os.O_RDWR)
                ifr = struct.pack(
                    "16sH", self.name.encode(), self.IFF_TUN | self.IFF_NO_PI
                )
                ifr = fcntl.ioctl(self.fd, self.TUNSETIFF, ifr)
                self.name = ifr[:16].strip(b"\x00").decode()
                fcntl.ioctl(self.fd, self.TUNSETOWNER, os.getuid())
                self.is_open = True
                self._configure_interface(ip_addr, netmask)
                print(f"TUN device '{self.name}' created successfully")
                print(f"IP: {ip_addr}, Netmask: {netmask}, MTU: {self.mtu}")
                return True
            except Exception as e:
                print(f"Error creating a TUN device: {e}")
                self._cleanup_resources()
                return False
    
    def _cleanup_resources(self):
        if self.fd != -1:
            try:
                os.close(self.fd)
            except OSError as e:
                print(f"Error closing TUN device: {e}")
            finally:
                self.fd = -1
        self.is_open = False
        self.running = False

    def _configure_interface(self, ip_addr: str, netmask: str):
        try:
            subprocess.run(
                ["ip", "addr", "add", f"{ip_addr}/24", "dev", self.name],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["ip", "link", "set", "dev", self.name, "up"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["ip", "link", "set", "dev", self.name, "mtu", str(self.mtu)],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"Error configuring interface: {e}")
            raise e

    def set_packet_handler(self, handler: Callable[[bytes], None]):
        self.packet_handler = handler

    def start_packet_loop(self, blocking: bool = True):
        if not self.is_open:
            raise RuntimeError("TUN device not open")
        self.running = True
        if blocking:
            self._packet_loop()
        else:
            self.read_thread = threading.Thread(target=self._packet_loop, daemon=True)
            self.read_thread.start()

    def _packet_loop(self):
        print(f"Starting packet loop for {self.name}")
        while self.running:
            try:
                ready, _, _ = select.select([self.fd], [], [], 1.0)
                if ready:
                    packet = os.read(self.fd, self.mtu + 100)

                    if packet and self.packet_handler:
                        self.packet_handler(packet)
            except OSError as e:
                if self.running:
                    print(f"Error reading from TUN Device: {e}")
                    raise e
                break
            except KeyboardInterrupt:
                break
            # idk if i need to set self.running to False or not
            # becaue anyways the program will terminate if Exception happens
            # else it will be in infinite loop but idk what happens in case
            # it's not the main thread
        print("Packet loop stopped")

    def send_packet(self, packet: bytes) -> bool:
        if not self.is_open:
            return False
        try:
            bytes_written = os.write(self.fd, packet)
            return bytes_written == len(packet)
        except OSError as e:
            print(f"Error sending packet: {e}")
            return False

    def get_stats(self) -> dict:
        rx_bytes, tx_bytes, rx_packets, tx_packets = 0, 0, 0, 0
        try:
            with open(f"/sys/class/net/{self.name}/statistics/rx_bytes") as f:
                rx_bytes = int(f.read().strip())
            with open(f"/sys/class/net/{self.name}/statistics/tx_bytes") as f:
                tx_bytes = int(f.read().strip())
            with open(f"/sys/class/net/{self.name}/statistics/rx_packets") as f:
                rx_packets = int(f.read().strip())
            with open(f"/sys/class/net/{self.name}/statistics/tx_packets") as f:
                tx_packets = int(f.read().strip())

            return {
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_packets": rx_packets,
                "tx_packets": tx_packets,
            }
        except Exception as e:
            print(f"Error: {e} occurred while reading statistics")
            return {}

    def stop(self):
        self.running = False
        if self.read_thread and self.read_thread.is_alive():
            self.read_thread.join(timeout=2.0)

    def close(self):
        self.stop()

        if self.is_open and self.fd:
            try:
                subprocess.run(
                    ["ip", "link", "set", "dev", self.name, "down"],
                    check=False,
                    capture_output=True,
                )
                os.close(self.fd)
                print(f"TUN device '{self.name}' closed")
            except Exception as e:
                print(f"Error closing TUN device: {e}")
            finally:
                self.fd = -1
                self.is_open = False

    def __enter__(self):
        return self
