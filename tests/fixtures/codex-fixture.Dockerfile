FROM python@sha256:623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487
COPY --chmod=0555 fixture-codex /fixture-codex
COPY --chmod=0444 fixture.py fixture-contract.json /
USER 65534:65534
CMD ["python", "-u", "/fixture.py"]
