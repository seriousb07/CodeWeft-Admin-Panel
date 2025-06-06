from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import mysql.connector
from database import get_db_connection
from models import UserLogin, UserChangePassword
from auth import hash_password, verify_password

# Define a Pydantic model for department input
class DepartmentCreate(BaseModel):
    name: str
    description: str

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

    # You might want to set some session cookie here for real auth

    return {"redirect": "/dashboard"}

# Dashboard page
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "username": "admin"})

# Change password page
@app.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})

# Departments page
@app.get("/departments", response_class=HTMLResponse)
async def departments_page(request: Request):
    return templates.TemplateResponse("departments.html", {"request": request})

# Doctors page
@app.get("/doctors", response_class=HTMLResponse)
async def doctors_page(request: Request):
    return templates.TemplateResponse("doctors.html", {"request": request})

# Edit Profile page
@app.get("/edit-profile", response_class=HTMLResponse)
async def edit_profile_page(request: Request):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT name, email, contact FROM users WHERE username = %s", ("admin",))
    profile = cursor.fetchone()
    cursor.close()
    connection.close()

    return templates.TemplateResponse("edit_profile.html", {"request": request, "profile": profile})

# Define a Pydantic model for editing profile (correct fields)
class EditProfileModel(BaseModel):
    name: str
    email: str
    contact: str

# Edit Profile endpoint (POST)
@app.post("/edit-profile")
async def edit_profile(profile: EditProfileModel):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor()
    cursor.execute(
        "UPDATE users SET name = %s, email = %s, contact = %s WHERE username = %s",
        (profile.name, profile.email, profile.contact, "admin")
    )
    connection.commit()
    cursor.close()
    connection.close()

    return {"message": "Profile updated successfully"}

# Logout page (GET shows confirmation page)
@app.get("/logout", response_class=HTMLResponse)
async def logout_page(request: Request):
    return templates.TemplateResponse("logout.html", {"request": request})

# Logout endpoint (POST clears cookie/session)
@app.post("/logout")
async def logout(response: Response):
    # Clear cookie by setting empty value and immediate expiry
    response.delete_cookie(key="session_token")  # adjust key if different in your app

    # Return JSON success message
    return JSONResponse(content={"message": "Logged out successfully"}, status_code=status.HTTP_200_OK)

# Create Department page
@app.get("/create-department", response_class=HTMLResponse)
async def create_department_page(request: Request):
    return templates.TemplateResponse("create_department.html", {"request": request})

# Create Department endpoint
@app.post("/create-department")
async def create_department(department: DepartmentCreate):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor()

    try:
        cursor.execute(
            "INSERT INTO departments (name, description) VALUES (%s, %s)",
            (department.name, department.description)
        )
        connection.commit()
    except mysql.connector.Error as err:
        connection.rollback()
        raise HTTPException(status_code=400, detail=f"Database error: {err}")
    finally:
        cursor.close()
        connection.close()

    return {"message": "Department created successfully!"}

# Create Doctor page
@app.get("/create-doctor", response_class=HTMLResponse)
async def create_doctor_page(request: Request):
    return templates.TemplateResponse("create_doctor.html", {"request": request})

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

# List Departments API endpoint for frontend fetch
@app.get("/departments/list-json")
async def list_departments_json():
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM departments")
    departments = cursor.fetchall()
    cursor.close()
    connection.close()
    return departments

# View All Departments as HTML page (optional)
@app.get("/departments/list", response_class=HTMLResponse)
async def list_departments(request: Request):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM departments")
    departments = cursor.fetchall()
    cursor.close()
    connection.close()

    return templates.TemplateResponse("departments_list.html", {"request": request, "departments": departments})

# List Doctors endpoint
@app.get("/doctors/list", response_class=HTMLResponse)
async def list_doctors(request: Request):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM doctors")
    doctors = cursor.fetchall()
    cursor.close()
    connection.close()

    return templates.TemplateResponse("doctors_list.html", {"request": request, "doctors": doctors})
