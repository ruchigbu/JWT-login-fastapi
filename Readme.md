# User authentication with JWT in FastAPI

### DB Settings

System: postgresql
DB Name: loginsystem
DB User: postgres
DB Password: strongdbpass
Server: 127.0.0.1

DATABASE_URL = "postgresql://postgres:strongdbpass@127.0.0.1/loginsystem"

### Activate the virtual environment

Scripts\activate.bat

### To run

uvicorn main:app --host 0.0.0.0 --port 8080 --reload
