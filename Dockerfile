FROM python:3.13-alpine AS builder

# Install build dependencies
RUN apk add musl-dev gcc

# Create virtual env
WORKDIR /app
RUN python -m venv /app/dcfw/venv

ENV PATH="/app/dcfw/venv/bin:$PATH"

COPY requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

# Install application
COPY dcfw /app/dcfw/lib/dcfw


FROM python:3.13-alpine

LABEL authors="k.kupferschmidt@dimajix.de"

RUN apk add iptables

WORKDIR /app

COPY --from=builder /app .
ENV PATH="/app/dcfw/venv/bin:$PATH"
ENV PYTHONPATH="/app/dcfw/lib"

ENTRYPOINT ["python", "-m", "dcfw"]
