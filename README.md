# INF 345 Week 3 — Notes API

A tiny HTTP service in plain Java (no frameworks, no dependencies),
using the built-in `com.sun.net.httpserver.HttpServer`.

## What it does
- `GET /` — greeting
- `GET /healthz` — health check (200, fast, no database)
- `GET /notes` — JSON list of notes

## How to run
    ./scripts/run.sh

Listens on the `PORT` environment variable (default `8080`):

    PORT=3000 ./scripts/run.sh

## How to test
    ./scripts/test.sh

Prints `TESTS: 3/3` and exits 0 when everything passes.

## Language
Java (single-file source launch, requires JDK 11+).