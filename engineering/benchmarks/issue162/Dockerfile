FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
RUN pip install --no-cache-dir onnxruntime==1.23.2 tokenizers==0.22.1 numpy==2.2.6 tiktoken==0.12.0
ENV PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 TOKENIZERS_PARALLELISM=false TIKTOKEN_CACHE_DIR=/codec
WORKDIR /work
