FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git=1:2.34.1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install requests==2.31.0 flask>=2.0.0

RUN npm install -g pnpm@8.6.0

COPY . .

CMD ["python", "main.py"]
