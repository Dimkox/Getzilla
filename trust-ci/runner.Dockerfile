ARG PYTHON_BASE_IMAGE
FROM ${PYTHON_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/ci

WORKDIR /opt/adaptive-trust-ci
COPY pyproject.toml README.md uv.lock lock_profiles.py lock_profile_validation.py lock-profiles.json requirements-*.txt ./
COPY src ./src

ARG OPENGREP_VERSION=1.30.1
ARG OPENGREP_SHA256=d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git php-cli composer xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && python -c "import urllib.request; urllib.request.urlretrieve('https://nodejs.org/dist/v24.22.0/node-v24.22.0-linux-x64.tar.xz', '/tmp/node.tar.xz')" \
    && echo "cc2f601cee82d9a5a233302fe307abc600727035fd7d2c3a3571755989e95008  /tmp/node.tar.xz" | sha256sum -c - \
    && mkdir /opt/node \
    && tar -xJf /tmp/node.tar.xz --strip-components=1 -C /opt/node \
    && rm /tmp/node.tar.xz \
    && ln -s /opt/node/bin/node /usr/local/bin/node \
    && ln -s /opt/node/bin/npm /usr/local/bin/npm \
    && ln -s /opt/node/bin/npx /usr/local/bin/npx \
    && node --version && npm --version && npx --version \
    && groupadd --gid 10001 ci \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/ci ci \
    && python lock_profiles.py --check \
    && python -m pip install --no-cache-dir --only-binary=:all: --require-hashes --no-deps --no-compile -r requirements-runner.txt \
    && python -m pip install --no-cache-dir --no-deps --no-compile --no-build-isolation . \
    && python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/usr/local/bin/opengrep')" \
        "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86" \
    && echo "${OPENGREP_SHA256}  /usr/local/bin/opengrep" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/opengrep \
    && opengrep --version

USER 10001:10001
WORKDIR /workspace
CMD ["python3", "--version"]
