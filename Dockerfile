FROM python:3.9-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && \
    apt-get install -y default-libmysqlclient-dev gcc pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Copiar requirements primero para cachear
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copiar todo el proyecto
COPY . .

# Cambiar el comando para apuntar a src
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "src.app:app"]
