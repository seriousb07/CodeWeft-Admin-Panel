from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional
import mysql.connector
import json
from database import get_db_connection
from models import UserLogin, UserChangePassword
from auth import hash_password, verify_password

# Define Pydantic models
class DepartmentCreate(BaseModel):
    name: str
    description: str

class DepartmentUpdate(BaseModel):
    name: str
    description: str

class DoctorCreate(BaseModel):
    doctor_name: str
    specializations: List[str]
    contact: str
    fees: float
    experience: int
    departments: List[str]
    days_available: List[str]
    time_slots: List[str]
    holiday: Optional[List[str]] = None
    email: Optional[str] = None

class DoctorUpdate(BaseModel):
    doctor_name: str
    specializations: List[str]
    contact: str
    fees: float
    experience: int
    departments: List[str]
    days_available: List[str]
    time_slots: List[str]
    holiday: Optional[List[str]] = None
    email: Optional[str] = None

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

# Departments page
@app.get("/departments", response_class=HTMLResponse)
async def departments_page(request: Request):
    return templates.TemplateResponse("departments.html", {"request": request})

# Doctors page
@app.get("/doctors", response_class=HTMLResponse)
async def doctors_page(request: Request):
    return templates.TemplateResponse("doctors.html", {"request": request})

# Edit Doctor page
@app.get("/edit-doctor", response_class=HTMLResponse)
async def edit_doctor_page(request: Request, id: int):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT id, doctor_name, specializations, contact, fees, experience, departments, days_available, time_slots, holiday, email
        FROM doctors WHERE id = %s
        """,
        (id,)
    )
    doctor = cursor.fetchone()
    cursor.close()
    connection.close()

    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    # Convert JSON strings to lists for template rendering
    doctor["specializations"] = json.loads(doctor["specializations"]) if doctor["specializations"] else []
    doctor["departments"] = json.loads(doctor["departments"]) if doctor["departments"] else []
    doctor["days_available"] = json.loads(doctor["days_available"]) if doctor["days_available"] else []
    doctor["time_slots"] = json.loads(doctor["time_slots"]) if doctor["time_slots"] else []
    doctor["holiday"] = json.loads(doctor["holiday"]) if doctor["holiday"] else None

    return templates.TemplateResponse("edit_doctor.html", {"request": request, "doctor": doctor})

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

# Edit Profile endpoint
class EditProfileModel(BaseModel):
    name: str
    email: str
    contact: str

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

# Logout page
@app.get("/logout", response_class=HTMLResponse)
async def logout_page(request: Request):
    return templates.TemplateResponse("logout.html", {"request": request})

# Logout endpoint
@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="session_token")
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

# Edit Department page
@app.get("/edit-department", response_class=HTMLResponse)
async def edit_department_page(request: Request, id: int):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT id, name, description FROM departments WHERE id = %s", (id,))
    department = cursor.fetchone()
    cursor.close()
    connection.close()

    if not department:
        raise HTTPException(status_code=404, detail="Department not found")

    return templates.TemplateResponse("edit_department.html", {"request": request, "department": department})

# Get Department endpoint
@app.get("/department/{id}")
async def get_department(id: int):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT id, name, description FROM departments WHERE id = %s", (id,))
    department = cursor.fetchone()
    cursor.close()
    connection.close()

    if not department:
        raise HTTPException(status_code=404, detail="Department not found")

    return department

# Update Department endpoint
@app.put("/department/{department_id}")
async def update_department(department_id: int, department: DepartmentUpdate):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor()
    try:
        cursor.execute(
            "UPDATE departments SET name = %s, description = %s WHERE id = %s",
            (department.name, department.description, department_id)
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Department not found")
        connection.commit()
    except mysql.connector.Error as err:
        connection.rollback()
        raise HTTPException(status_code=400, detail=f"Database error: {err}")
    finally:
        cursor.close()
        connection.close()

    return {"message": "Department updated successfully"}

# Delete Department endpoint
@app.delete("/department/{department_id}")
async def delete_department(department_id: int):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM departments WHERE id = %s", (department_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Department not found")
        connection.commit()
    except mysql.connector.Error as err:
        connection.rollback()
        raise HTTPException(status_code=400, detail=f"Database error: {err}")
    finally:
        cursor.close()
        connection.close()

    return {"message": "Department deleted successfully"}

# Create Doctor page
@app.get("/create-doctor", response_class=HTMLResponse)
async def create_doctor_page(request: Request):
    return templates.TemplateResponse("create_doctor.html", {"request": request})

# Create Doctor endpoint
@app.post("/create-doctor")
async def create_doctor(doctor: DoctorCreate):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO doctors (doctor_name, specializations, contact, fees, experience, departments, days_available, time_slots, holiday, email)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                doctor.doctor_name,
                json.dumps(doctor.specializations),
                doctor.contact,
                doctor.fees,
                doctor.experience,
                json.dumps(doctor.departments),
                json.dumps(doctor.days_available),
                json.dumps(doctor.time_slots),
                json.dumps(doctor.holiday) if doctor.holiday else None,
                doctor.email
            )
        )
        connection.commit()
    except mysql.connector.Error as err:
        connection.rollback()
        error_message = str(err) if err else "Unknown database error"
        raise HTTPException(status_code=400, detail=f"Database error: {error_message}")
    finally:
        cursor.close()
        connection.close()

    return {"message": "Doctor created successfully!"}

# Get Doctor endpoint
@app.get("/doctor/{doctor_id}")
async def get_doctor(doctor_id: int):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT id, doctor_name, specializations, contact, fees, experience, departments, days_available, time_slots, holiday, email
        FROM doctors WHERE id = %s
        """,
        (doctor_id,)
    )
    doctor = cursor.fetchone()
    cursor.close()
    connection.close()

    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    # Convert JSON strings to lists for the response
    doctor["specializations"] = json.loads(doctor["specializations"]) if doctor["specializations"] else []
    doctor["departments"] = json.loads(doctor["departments"]) if doctor["departments"] else []
    doctor["days_available"] = json.loads(doctor["days_available"]) if doctor["days_available"] else []
    doctor["time_slots"] = json.loads(doctor["time_slots"]) if doctor["time_slots"] else []
    doctor["holiday"] = json.loads(doctor["holiday"]) if doctor["holiday"] else None

    return doctor

# Update Doctor endpoint
@app.put("/doctor/{doctor_id}")
async def update_doctor(doctor_id: int, doctor: DoctorUpdate):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE doctors
            SET doctor_name = %s, specializations = %s, contact = %s, fees = %s, experience = %s,
                departments = %s, days_available = %s, time_slots = %s, holiday = %s, email = %s
            WHERE id = %s
            """,
            (
                doctor.doctor_name,
                json.dumps(doctor.specializations),
                doctor.contact,
                doctor.fees,
                doctor.experience,
                json.dumps(doctor.departments),
                json.dumps(doctor.days_available),
                json.dumps(doctor.time_slots),
                json.dumps(doctor.holiday) if doctor.holiday else None,
                doctor.email,
                doctor_id
            )
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Doctor not found")
        connection.commit()
    except mysql.connector.Error as err:
        connection.rollback()
        error_message = str(err) if err else "Unknown database error"
        raise HTTPException(status_code=400, detail=f"Database error: {error_message}")
    finally:
        cursor.close()
        connection.close()

    return {"message": "Doctor updated successfully"}

# Delete Doctor endpoint
@app.delete("/doctor/{doctor_id}")
async def delete_doctor(doctor_id: int):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM doctors WHERE id = %s", (doctor_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Doctor not found")
        connection.commit()
    except mysql.connector.Error as err:
        connection.rollback()
        error_message = str(err) if err else "Unknown database error"
        raise HTTPException(status_code=400, detail=f"Database error: {error_message}")
    finally:
        cursor.close()
        connection.close()

    return {"message": "Doctor deleted successfully"}

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
    cursor.execute("SELECT id, name, description FROM departments")
    departments = cursor.fetchall()
    cursor.close()
    connection.close()
    return departments

# View All Departments as HTML page
@app.get("/departments/list", response_class=HTMLResponse)
async def list_departments(request: Request):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT id, name, description FROM departments")
    departments = cursor.fetchall()
    cursor.close()
    connection.close()

    return templates.TemplateResponse("departments_list.html", {"request": request, "departments": departments})

# List Doctors JSON endpoint for frontend fetch
@app.get("/doctors/list-json")
async def list_doctors_json():
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT id, doctor_name, specializations, contact, fees, experience, departments, days_available, time_slots, holiday, email
        FROM doctors
        """
    )
    doctors = cursor.fetchall()
    cursor.close()
    connection.close()

    # Convert JSON strings to lists for the response
    for doctor in doctors:
        doctor["specializations"] = json.loads(doctor["specializations"]) if doctor["specializations"] else []
        doctor["departments"] = json.loads(doctor["departments"]) if doctor["departments"] else []
        doctor["days_available"] = json.loads(doctor["days_available"]) if doctor["days_available"] else []
        doctor["time_slots"] = json.loads(doctor["time_slots"]) if doctor["time_slots"] else []
        doctor["holiday"] = json.loads(doctor["holiday"]) if doctor["holiday"] else None

    return doctors

# List Doctors endpoint (for HTML rendering)
@app.get("/doctors/list", response_class=HTMLResponse)
async def list_doctors(request: Request):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT id, doctor_name, specializations, contact, fees, experience, departments, days_available, time_slots, holiday, email
        FROM doctors
        """
    )
    doctors = cursor.fetchall()
    cursor.close()
    connection.close()

    # Convert JSON strings to lists for template rendering
    for doctor in doctors:
        doctor["specializations"] = json.loads(doctor["specializations"]) if doctor["specializations"] else []
        doctor["departments"] = json.loads(doctor["departments"]) if doctor["departments"] else []
        doctor["days_available"] = json.loads(doctor["days_available"]) if doctor["days_available"] else []
        doctor["time_slots"] = json.loads(doctor["time_slots"]) if doctor["time_slots"] else []
        doctor["holiday"] = json.loads(doctor["holiday"]) if doctor["holiday"] else None

    return templates.TemplateResponse("doctors_list.html", {"request": request, "doctors": doctors})