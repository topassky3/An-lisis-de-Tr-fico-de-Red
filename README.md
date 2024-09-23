# Network Traffic Feature Detection

## Descripción

Este proyecto utiliza técnicas de captura y análisis de tráfico de red para detectar características estáticas y dinámicas, con el objetivo de identificar patrones de tráfico normal y anómalo. El sistema está diseñado para ejecutarse en tiempo real y es capaz de integrarse con modelos de aprendizaje automático para clasificar el tráfico de red o detectar anomalías.

## Características

- **Captura en Tiempo Real**: Utiliza Scapy para capturar paquetes de red en tiempo real.
- **Extracción de Características Estáticas y Dinámicas**: Analiza y vectoriza características tanto estáticas como dinámicas de los paquetes capturados.
- **Gestión de Sesiones**: Agrupa paquetes por flujos únicos para calcular métricas como la duración de sesiones y la variación del tráfico.
- **Integración con Modelos de IA**: Permite la integración con modelos preentrenados de aprendizaje automático para la clasificación y detección de anomalías.
- **Optimización del Procesamiento**: Implementa técnicas de normalización y codificación eficiente para preparar los datos para el análisis.

## Requisitos

Este proyecto está desarrollado en Python y requiere las siguientes librerías:

- Python 3.7 o superior
- Scapy
- Pandas
- NumPy
- Scikit-learn

## Instalación

1. **Clonar el Repositorio**

   ```bash
   git clone https://github.com/tu-usuario/network-traffic-feature-detection.git
   cd network-traffic-feature-detection

2. **Crear un Entorno Virtual (Opcional pero Recomendado)**
```bash
    python3 -m venv env
    source env/bin/activate
```

3. **Instalar las Dependencias**
```bash
    pip install -r requirements.txt
```

## Uso

Para iniciar la captura y análisis de tráfico, ejecuta el script principal desde la línea de comandos con privilegios de superusuario:

```bash
    sudo $(which python3) main.py
```

## Estructura del Código

1. main.py: Script principal que inicia la captura y procesamiento de paquetes.
2. TrafficCapture (Clase): Encapsula la lógica de captura de paquetes utilizando Scapy.
3. TrafficProcessor (Clase): Maneja la vectorización de datos y la extracción de características dinámicas.
4. requirements.txt: Archivo que lista las dependencias necesarias (si aplica).




