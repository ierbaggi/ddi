# Usa una imagen ligera de Python
FROM python:3.10-slim

# No buffer en stdout/stderr
ENV PYTHONUNBUFFERED=1

# Crea y sitúa el directorio de la app
WORKDIR /app

# Copia y instala dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo el código
COPY . .

# Expone el puerto 5000
EXPOSE 5000

# Asegura que Flask escuche en 0.0.0.0 y use el PORT de Railway
CMD ["python", "app.py"]
