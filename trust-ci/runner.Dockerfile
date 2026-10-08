ARG PYTHON_BASE_IMAGE
FROM ${PYTHON_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/ci

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git php-cli composer nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 ci \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/ci ci

WORKDIR /opt/adaptive-trust-ci
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir ".[test]" \
        coverage==7.15.4 \
        pytest==9.1.1 \
        pytest-xdist==3.8.0 \
        pytest-cov==7.1.0 \
        ruff==0.16.2 \
        bandit==1.9.4 \
        tomli==2.4.1

ARG OPENGREP_VERSION=1.30.1
ARG OPENGREP_SHA256=d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4
RUN python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/usr/local/bin/opengrep')" \
        "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86" \
    && echo "${OPENGREP_SHA256}  /usr/local/bin/opengrep" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/opengrep \
    && opengrep --version

USER 10001:10001
WORKDIR /workspace
CMD ["python3", "--version"]
