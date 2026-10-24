# AI-SAST (aisast) Dockerfile
# Güvenlik ve Uyumluluk: Minimal Debian Slim imajı, Git bağımlılığı ve izole çalışma ortamı

FROM python:3.11-slim

LABEL maintainer="Yiğit Ali Çolakoğlu <yigitalicolakoglu22@gmail.com>"
LABEL description="AI Destekli Kod Güvenliği & Sır Tarayıcı CLI (AI-Powered SAST & Secret Scanner)"

# Git desteği ekle (Diff hunk ve staged taramalar için gereklidir)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Uygulama çalışma dizini
WORKDIR /app

# Paket bağımlılıklarını ve kaynak kodları kopyala
COPY pyproject.toml README.md ./
COPY src/ ./src/

# aisast CLI aracını üretim modunda kur
RUN pip install --no-cache-dir .

# Taranacak hedef proje dizini
WORKDIR /workspace

# CLI Giriş Noktası
ENTRYPOINT ["aisast"]
CMD ["scan", "/workspace"]
