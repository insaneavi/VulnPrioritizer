FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 INTEL_ROOT=/app/intel
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/intel/epss /app/intel/cisa /app/intel/metadata
EXPOSE 8085
CMD ["gunicorn","--bind","0.0.0.0:8085","--workers","2","--threads","4","--timeout","180","app:app"]
