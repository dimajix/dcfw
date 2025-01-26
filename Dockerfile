FROM python:3.13-alpine AS builder

# Install build dependencies
RUN apk add musl-dev gcc

# Create virtual env
WORKDIR /app
RUN python -m venv /usr/app/venv

ENV PATH="/app/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt

# Install application
COPY dcfw /app


FROM python:3.13-alpine

LABEL authors="k.kupferschmidt@dimajix.de"

WORKDIR /app

COPY --from=builder /app .
ENV PATH="/app/venv/bin:$PATH"

#ENTRYPOINT ["top", "-b"]
