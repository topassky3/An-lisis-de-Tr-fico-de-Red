import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
import threading
import time
from queue import Queue
import logging
from collections import defaultdict
from datetime import datetime
from trafficcapture import TrafficCapture
from trafficprocessor import TrafficProcessor

# Configuración del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    # Inicializar capturador y procesador de tráfico
    traffic_capture = TrafficCapture()
    traffic_processor = TrafficProcessor()

    # Iniciar captura de paquetes en un hilo separado
    sniff_thread = threading.Thread(target=traffic_capture.start_sniffing, daemon=True)
    sniff_thread.start()

    # Esperar a que se capturen suficientes datos para ajustar los encoders
    initial_data = []
    initial_sample_size = 500  # Número de paquetes para ajustar los encoders
    logging.info(f"Esperando a capturar {initial_sample_size} paquetes para inicializar los transformadores...")

    while len(initial_data) < initial_sample_size:
        try:
            packet = traffic_capture.captured_queue.get(timeout=10)
            initial_data.append(packet)
        except:
            logging.warning("Esperando más paquetes...")
            continue

    df_initial = pd.DataFrame(initial_data)
    traffic_processor.fit_encoders(df_initial)

    # Procesamiento continuo de paquetes capturados
    try:
        while True:
            batch_size = 100  # Número de paquetes por lote
            batch_data = []
            for _ in range(batch_size):
                try:
                    packet = traffic_capture.captured_queue.get(timeout=10)
                    batch_data.append(packet)
                except:
                    break  # Salir si no hay más paquetes en este intervalo

            if batch_data:
                df_batch = pd.DataFrame(batch_data)
                vectorized, df_with_time = traffic_processor.vectorize(df_batch)

                if vectorized is not None:
                    # Extracción de características dinámicas
                    dynamic_features = traffic_processor.extract_dynamic_features(df_with_time)

                    # Replicar las características dinámicas para cada fila en vectorized
                    # Utilizamos pd.DataFrame constructor para crear un DataFrame con las mismas filas
                    dynamic_features_df = pd.DataFrame([dynamic_features] * len(vectorized)).reset_index(drop=True)
                    
                    # Asegurarse de que vectorized también tenga el mismo índice
                    vectorized = vectorized.reset_index(drop=True)

                    # Concatenar características estáticas y dinámicas
                    final_features = pd.concat([vectorized, dynamic_features_df], axis=1)

                    # Aquí puedes integrar tu modelo de IA para clasificar o detectar anomalías
                    # Por ejemplo: predictions = modelo.predict(final_features)
                    logging.info(f"Vectorizado de {len(df_batch)} paquetes con características dinámicas:\n{final_features.head()}")

            # Esperar un intervalo antes de procesar el siguiente lote
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("Deteniendo la captura de paquetes...")
        traffic_capture.stop()
        sniff_thread.join()
        logging.info("Captura de paquetes detenida.")

if __name__ == "__main__":
    main()
