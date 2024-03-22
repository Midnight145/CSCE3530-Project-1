# CSCE3530 Project 1

This is a simple JWKS endpoint to generate and serve JWTs. Private keys are stored in a sqlite3 database, unencrypted for this project. The public keys are served at the `/.well-known/jwks.json` endpoint, with a dummy auth endpoint at `/auth`.

## Installation

1. Clone the repository
2. Install the required packages (Requires Python 3.10 or above)
```bash
pip install -r requirements.txt
```

## Usage

Either:

1. Run the `main.py` file
```bash
python main.py
```
2. Run directly via `uvicorn`
```bash
uvicorn main:app --reload
```

Automatic API documentation is available at `http://<server>:<port>/docs`. thanks to FastAPI's built-in Swagger UI.

## Unit Tests

Run the unit tests using the following command:
```bash
python -m unittest
```