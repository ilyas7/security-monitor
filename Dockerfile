FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads exports

EXPOSE 8501

CMD ["streamlit", "run", "src/security_monitor.py", "--server.port=8501", "--server.address=0.0.0.0"]