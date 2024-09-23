import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
import threading
import time
from queue import Queue
import logging
from collections import defaultdict
from datetime import datetime

class TrafficCapture:
    def __init__(self):
        self.captured_queue = Queue()
        self.stop_sniffing = threading.Event()

    def packet_callback(self, packet):
        """Función de callback para procesar cada paquete capturado"""
        if IP in packet:
            ip_origen = packet[IP].src
            ip_destino = packet[IP].dst
            protocolo = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Otro'
            tamaño_paquete = len(packet)
            timestamp = datetime.now()

            # Extraer puertos y flags de TCP/UDP
            if protocolo == 'TCP':
                puerto_origen = packet[TCP].sport
                puerto_destino = packet[TCP].dport
                flag_TCP = str(packet[TCP].flags)  # Convertir a string
            elif protocolo == 'UDP':
                puerto_origen = packet[UDP].sport
                puerto_destino = packet[UDP].dport
                flag_TCP = 'None'
            else:
                puerto_origen = None
                puerto_destino = None
                flag_TCP = 'None'

            # Añadir los datos capturados a la cola
            self.captured_queue.put({
                'ip_origen': ip_origen,
                'ip_destino': ip_destino,
                'puerto_origen': puerto_origen,
                'puerto_destino': puerto_destino,
                'protocolo': protocolo,
                'tamaño_paquete': tamaño_paquete,
                'flag_TCP': flag_TCP,
                'timestamp': timestamp
            })

    def start_sniffing(self, interface=None):
        """Inicia la captura de paquetes"""
        logging.info("Iniciando captura de paquetes...")
        sniff(prn=self.packet_callback, store=False, stop_filter=self.should_stop, iface=interface)

    def should_stop(self, packet):
        """Determina cuándo detener la captura"""
        return self.stop_sniffing.is_set()

    def stop(self):
        """Detiene la captura de paquetes"""
        self.stop_sniffing.set()
