from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from database import get_db_connection
from models import UserLogin, UserChangePassword
from auth import hash_password, verify_password
import mysql.connector

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize default user on startup
@app.on_event("startup")
def init_default_user():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", ("admin",))
        if cursor.fetchone()[0] == 0:
            hashed_password = hash_password("admin123")
            cursor.execute(
                "INSERT INTO users (username, hashed_password, email) VALUES (%s, %s, %s)",
                ("admin", hashed_password, "admin@example.com")
            )
            connection.commit()
        cursor.close()
        connection.close()

# Login page
@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Login endpoint
@app.post("/login")
async def login(user: UserLogin):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (user.username,))
    db_user = cursor.fetchone()
    cursor.close()
    connection.close()

    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {"redirect": "/dashboard"}

# Dashboard page
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "username": "admin"})

# Change password page
@app.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})

# Change password endpoint
@app.post("/change-password")
async def change_password(user: UserChangePassword):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", ("admin",))
    db_user = cursor.fetchone()
    
    if not db_user or not verify_password(user.old_password, db_user["hashed_password"]):
        cursor.close()
        connection.close()
        raise HTTPException(status_code=401, detail="Invalid old password")
    
    hashed_new_password = hash_password(user.new_password)
    cursor.execute(
        "UPDATE users SET hashed_password = %s WHERE username = %s",
        (hashed_new_password, "admin")
    )
    connection.commit()
    cursor.close()
    connection.close()
    
    return {"message": "Password changed successfully"}