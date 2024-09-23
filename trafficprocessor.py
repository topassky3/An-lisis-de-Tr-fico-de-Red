import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
import threading
import time
from queue import Queue
import logging
from collections import defaultdict
from datetime import datetime

class TrafficProcessor:
    def __init__(self):
        self.onehot_encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        self.scaler = MinMaxScaler()
        self.encoders_fitted = False
        self.scaler_fitted = False
        self.sessions = defaultdict(dict)  # Para gestionar las sesiones
        self.session_timeout = 60  # Tiempo en segundos para considerar una sesión terminada

    def fit_encoders(self, df):
        """Ajusta los encoders y scalers con los datos iniciales"""
        categorical_columns = ['protocolo', 'flag_TCP']
        numerical_columns = ['puerto_origen', 'puerto_destino', 'tamaño_paquete']

        # Asegurarse de que las columnas categóricas sean de tipo string
        df[categorical_columns] = df[categorical_columns].astype(str)

        # Ajustar OneHotEncoder
        self.onehot_encoder.fit(df[categorical_columns])
        self.encoders_fitted = True
        logging.info("OneHotEncoder ajustado.")

        # Ajustar MinMaxScaler
        self.scaler.fit(df[numerical_columns])
        self.scaler_fitted = True
        logging.info("MinMaxScaler ajustado.")

    def vectorize(self, df):
        """Vectoriza los datos capturados"""
        if df.empty:
            logging.warning("No hay datos capturados para vectorizar.")
            return None, None

        # Rellenar los valores nulos si hay puertos o flags faltantes
        df.fillna({'puerto_origen': 0, 'puerto_destino': 0, 'flag_TCP': 'None'}, inplace=True)

        categorical_columns = ['protocolo', 'flag_TCP']
        numerical_columns = ['puerto_origen', 'puerto_destino', 'tamaño_paquete']

        # Asegurarse de que las columnas categóricas sean de tipo string
        df[categorical_columns] = df[categorical_columns].astype(str)

        # Codificación de características categóricas
        categorical_encoded = self.onehot_encoder.transform(df[categorical_columns])

        # Normalización de las características numéricas
        numerical_scaled = self.scaler.transform(df[numerical_columns])

        # Concatenar las características codificadas y normalizadas
        vectorized_data = pd.concat([
            pd.DataFrame(numerical_scaled, columns=[f"{col}_normalizado" for col in numerical_columns]),
            pd.DataFrame(categorical_encoded, columns=self.onehot_encoder.get_feature_names_out(categorical_columns))
        ], axis=1)

        return vectorized_data, df

    def extract_dynamic_features(self, df):
        """Extrae características dinámicas a partir de los datos capturados"""
        dynamic_features = {
            'frecuencia_conexiones': 0,
            'duracion_sesion_media': 0,
            'variacion_trafico': 0
        }

        # Definir un identificador de sesión único
        for _, row in df.iterrows():
            session_id = (row['ip_origen'], row['ip_destino'], row['puerto_origen'], row['puerto_destino'], row['protocolo'])
            current_time = row['timestamp']

            # Actualizar información de la sesión
            session = self.sessions[session_id]
            if 'last_seen' in session:
                time_diff = (current_time - session['last_seen']).total_seconds()
                if time_diff > self.session_timeout:
                    # Sesión considerada terminada
                    session['end_time'] = session['last_seen']
                    session['duration'] = (session['end_time'] - session['start_time']).total_seconds()
                    dynamic_features['duracion_sesion_media'] += session['duration']
                    dynamic_features['frecuencia_conexiones'] += 1
                    dynamic_features['variacion_trafico'] += session['tamaño_total'] - session.get('previous_tamaño', 0)
                    # Reiniciar la sesión
                    session['start_time'] = current_time
                    session['last_seen'] = current_time
                    session['tamaño_total'] = row['tamaño_paquete']
                    session['previous_tamaño'] = row['tamaño_paquete']
                else:
                    # Actualizar sesión existente
                    session['last_seen'] = current_time
                    session['tamaño_total'] += row['tamaño_paquete']
                    dynamic_features['variacion_trafico'] += abs(row['tamaño_paquete'] - session.get('previous_tamaño', row['tamaño_paquete']))
                    session['previous_tamaño'] = row['tamaño_paquete']
            else:
                # Nueva sesión
                session['start_time'] = current_time
                session['last_seen'] = current_time
                session['tamaño_total'] = row['tamaño_paquete']
                session['previous_tamaño'] = row['tamaño_paquete']

        # Calcular medias y normalizar
        total_sessions = dynamic_features['frecuencia_conexiones'] if dynamic_features['frecuencia_conexiones'] > 0 else 1
        dynamic_features['duracion_sesion_media'] /= total_sessions
        dynamic_features['variacion_trafico'] /= total_sessions

        # Normalizar características dinámicas (ejemplo usando MinMaxScaler)
        # Puedes ajustar esto según tus necesidades
        dynamic_features_scaled = {
            'frecuencia_conexiones_normalizado': dynamic_features['frecuencia_conexiones'] / 1000,  # Ejemplo de normalización
            'duracion_sesion_media_normalizado': dynamic_features['duracion_sesion_media'] / 300,   # Ejemplo de normalización
            'variacion_trafico_normalizado': dynamic_features['variacion_trafico'] / 1000          # Ejemplo de normalización
        }

        return pd.Series(dynamic_features_scaled)