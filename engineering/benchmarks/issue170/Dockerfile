FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
RUN apt-get update && apt-get install -y --no-install-recommends git nodejs npm time && rm -rf /var/lib/apt/lists/*
RUN mkdir /wheels && pip download --dest /wheels onnxruntime==1.23.2 tokenizers==0.22.1 numpy==2.2.6 pytest==8.4.2 PyYAML==6.0.3 && pip install --no-index --find-links /wheels onnxruntime==1.23.2 tokenizers==0.22.1 numpy==2.2.6 pytest==8.4.2 PyYAML==6.0.3
RUN npm install --prefix /tools jscpd@4.0.5
ENV PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 TOKENIZERS_PARALLELISM=false
WORKDIR /work
