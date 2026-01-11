# User authentication with JWT in FastAPI

A simple FastAPI application that uses JWT Bearer Tokens for authentication. PostgreSQL is used as the database backend.

Postman is used to test the APIs.

## System Requirements

- FastAPI
- PostgreSQL
- Postman

## How to run and test?

Clone the code(copy/github clone) and then setup accordingly.

### DB Settings

```ini
System: postgresql
DB Name: loginsystem
DB User: postgres
DB Password: strongdbpass
Server: 127.0.0.1
```

```python
DATABASE_URL = "postgresql://postgres:strongdbpass@127.0.0.1/loginsystem"
```

### Activate the virtual environment and install requirements

```bash
Scripts\activate.bat
cd app
pip install -r requirements.txt
```

### To run

```bash
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```
