from fastapi import HTTPException, FastAPI, Request, Depends, Security
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Boolean, TIMESTAMP, DateTime, ForeignKey, and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import os
from jose import JWTError
from uvicorn import run

app = FastAPI()


DATABASE_URL = "postgresql://postgres:strongdbpass@127.0.0.1/loginsystem"

engine = create_engine(DATABASE_URL)

SECRET_KEY = os.environ.get('SECRET_KEY', 'secret$key@login')
ALGORITHM = 'HS256'

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True)
    password = Column(String(255))
    is_sup = Column(Boolean, default=False)
    created_on = Column(TIMESTAMP(timezone=False), default=datetime.now)
    last_login_time = Column(TIMESTAMP(timezone=False))
    last_login_ip = Column(String(50))
    token = Column(String(255))


class LoginLog(Base):
    __tablename__ = "login_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    login_time = Column(TIMESTAMP(timezone=False), default=datetime.now)
    login_ip = Column(String(50))
    user_agent = Column(String(255))
    event_type = Column(String(10), index=True)


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"message": exc.detail})


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class UserCreate(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., min_length=8)
    is_sup: Optional[bool] = False


class UserLogin(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., min_length=8)


class LoginLogCreate(BaseModel):
    user_id: int
    login_ip: str
    user_agent: str
    event_type: str = 'Login'

class LogoutRequest(BaseModel):
    user_id: int
    token: str | None = None

class TokenData(BaseModel):
    user_id: Optional[int] = None


# Import your SQLAlchemy models here
from main import User, LoginLog

# Function to create the access token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_active_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)): 
    credentials_exception = HTTPException( 
        status_code=401, 
        detail="Could not validate credentials", 
        headers={"WWW-Authenticate": "Bearer"}, 
    ) 
    try: 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) 
        user_id: str = payload.get("sub") 
        if user_id is None: 
            raise credentials_exception 
        user_id_int = int(user_id)
        token_data = TokenData(user_id=user_id_int) 
    except JWTError: 
        raise credentials_exception 
    user = db.query(User).filter(User.id == token_data.user_id).first() 
    if user is None: 
        raise credentials_exception 
    return user


# Lifespan event handler for application startup
@app.on_event("startup")
async def startup_event():
    # Create tables in the database
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully")

# API root route 
@app.get("/")
def root():
    return {"message": "Welcome"}


# API route to register a new user
@app.post("/user/register/")
def register(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(email=user.email, password=hashed_password, is_sup=user.is_sup)
    db.add(db_user)
    db.commit()
    return {"message": "User registered successfully"}


# API route to login
@app.post("/user/login/")
def login(user: UserLogin, request: Request, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user and pwd_context.verify(user.password, db_user.password):
        user_agent = request.headers.get("User-Agent", "")
        login_log = LoginLogCreate(user_id=db_user.id, login_ip=request.client.host, user_agent=user_agent, event_type='Login')
        db_login_log = LoginLog(**login_log.dict())
        db.add(db_login_log)

        db_user.last_login_time = datetime.now()
        db_user.last_login_ip = request.client.host
        
        access_token_expires = timedelta(minutes=1440)
        access_token = create_access_token(data={"sub": str(db_user.id)}, expires_delta=access_token_expires)
        db_user.token = access_token
        db.commit()

        return {"message": "Login successful", "access_token": access_token, "token_type": "Bearer"}
    raise HTTPException(status_code=401, detail="Invalid email or password")

# API route to logout
@app.post("/user/logout/")
def logout(request: Request, 
    db: Session = Depends(get_db), 
    current_user: User = Security(get_current_active_user)):
    try:
        user_id = current_user.id
        user = db.query(User).filter(User.id == user_id).first()
        
        if user:
            # Delete the JWT token from the Users table
            user.token = None
            db.commit()
            
            # Log the logout event
            user_agent = request.headers.get("User-Agent", "")
            logout_log = LoginLog(user_id=user_id, login_time=datetime.now(), login_ip=request.client.host, user_agent=user_agent, event_type='Logout')
            db.add(logout_log)
            db.commit()
            
            return {"message": "Logout successful"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=e.message)


# API route to fetch login reports
@app.post("/reports/login-reports/")
def fetch_login_reports(user_id: Optional[int] = None, fromdate: Optional[datetime] = None,
                        todate: Optional[datetime] = None, db: Session = Depends(get_db), current_user: User = Security(get_current_active_user)):
    # Validate the JWT token
    if current_user.token is None:
        raise HTTPException(status_code=401, detail="Unauthorized ..." + str(user_id) + "")

    query = db.query(User.email, LoginLog.login_time, LoginLog.login_ip, LoginLog.event_type).join(LoginLog)

    if user_id:
        query = query.filter(LoginLog.user_id == user_id)

    if fromdate:
        query = query.filter(LoginLog.login_time >= fromdate.replace(tzinfo=None))

    if todate:
        query = query.filter(LoginLog.login_time <= todate.replace(tzinfo=None))

    if fromdate and not todate:
        next_day = fromdate + timedelta(days=1)
        query = query.filter(and_(LoginLog.login_time >= fromdate.replace(tzinfo=None), LoginLog.login_time < next_day.replace(tzinfo=None)))

    login_reports = query.order_by(LoginLog.login_time.desc()).limit(50).all()

    return [{"email": email, "login_time": login_time, "login_ip": login_ip, "event_type": event_type} for email, login_time, login_ip, event_type in login_reports]


# Run the application
if __name__ == "__main__":
    run(app, host="0.0.0.0", port="8080")

