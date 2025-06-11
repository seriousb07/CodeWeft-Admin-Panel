from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional
import mysql.connector
import json
import os
from datetime import datetime
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

class EditProfileModel(BaseModel):
    username: str
    hospital_name: str

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Ensure upload directory exists
UPLOAD_DIR = "static/uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

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
                "INSERT INTO users (username, hospital_name, hashed_password) VALUES (%s, %s, %s)",
                ("admin", "Default Hospital", hashed_password)
            )
            connection.commit()
        cursor.close()
        connection.close()

# Temporary endpoint to hash existing plain-text passwords
@app.post("/hash-existing-passwords")
async def hash_existing_passwords():
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT username, hashed_password FROM users WHERE username != 'admin'")
        users = cursor.fetchall()

        updated_users = []
        for user in users:
            password = user["hashed_password"]
            if password and not password.startswith("$2b$"):
                hashed_password = hash_password(password)
                cursor.execute(
                    "UPDATE users SET hashed_password = %s WHERE username = %s",
                    (hashed_password, user["username"])
                )
                updated_users.append(user["username"])

        connection.commit()
        if updated_users:
            return {"message": f"Updated passwords for users: {updated_users}"}
        else:
            return {"message": "No users with unhashed passwords found."}
    except mysql.connector.Error as err:
        connection.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(err)}")
    finally:
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

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (user.username,))
        db_user = cursor.fetchone()

        if not db_user:
            raise HTTPException(status_code=401, detail="Invalid username")

        hashed_password = db_user["hashed_password"]
        if not hashed_password:
            raise HTTPException(status_code=500, detail="User password not set in database")

        try:
            password_verified = verify_password(user.password, hashed_password)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Password verification failed for user {user.username}: {str(e)}")

        if not password_verified:
            raise HTTPException(status_code=401, detail="Invalid password")

        return {"redirect": "/dashboard"}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Database error: {str(err)}")
    finally:
        cursor.close()
        connection.close()

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

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, doctor_name, specializations, contact, fees, experience, departments, days_available, time_slots, holiday, email
            FROM doctors WHERE id = %s
            """,
            (id,)
        )
        doctor = cursor.fetchone()

        if not doctor:
            raise HTTPException(status_code=404, detail="Doctor not found")

        try:
            doctor["specializations"] = json.loads(doctor["specializations"]) if doctor["specializations"] else []
            doctor["departments"] = json.loads(doctor["departments"]) if doctor["departments"] else []
            doctor["days_available"] = json.loads(doctor["days_available"]) if doctor["days_available"] else []
            doctor["time_slots"] = json.loads(doctor["time_slots"]) if doctor["time_slots"] else []
            doctor["holiday"] = json.loads(doctor["holiday"]) if doctor["holiday"] else None
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=500, detail=f"Invalid JSON data in database: {str(e)}")

        return templates.TemplateResponse("edit_doctor.html", {"request": request, "doctor": doctor})
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Database error: {str(err)}")
    finally:
        cursor.close()
        connection.close()

# Profile endpoint (for fetching profile data)
@app.get("/profile")
async def get_profile():
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT username, hospital_name, profile_picture FROM users WHERE username = %s", ("admin",))
        profile = cursor.fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="User not found")
        return profile
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Database error: {err}")
    finally:
        cursor.close()
        connection.close()

# Edit Profile page
@app.get("/edit-profile", response_class=HTMLResponse)
async def edit_profile_page(request: Request):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT username, hospital_name, profile_picture FROM users WHERE username = %s", ("admin",))
        profile = cursor.fetchone()
        return templates.TemplateResponse("edit_profile.html", {"request": request, "profile": profile})
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Database error: {err}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")
    finally:
        cursor.close()
        connection.close()

# Edit Profile endpoint
@app.post("/edit-profile")
async def edit_profile(
    username: str = Form(...),
    hospital_name: str = Form(...),
    profile_picture: Optional[UploadFile] = File(None)
):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    profile_picture_path = None
    if profile_picture:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{profile_picture.filename}"
        file_path = os.path.join(UPLOAD_DIR, filename)
        with open(file_path, "wb") as f:
            content = await profile_picture.read()
            f.write(content)
        profile_picture_path = f"/static/uploads/{filename}"

    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE users
            SET username = %s, hospital_name = %s, profile_picture = %s
            WHERE username = %s
            """,
            (username, hospital_name, profile_picture_path, "admin")
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
        connection.commit()
    except mysql.connector.Error as err:
        connection.rollback()
        raise HTTPException(status_code=400, detail=f"Database error: {err}")
    finally:
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

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, doctor_name, specializations, contact, fees, experience, departments, days_available, time_slots, holiday, email
            FROM doctors WHERE id = %s
            """,
            (doctor_id,)
        )
        doctor = cursor.fetchone()

        if not doctor:
            raise HTTPException(status_code=404, detail="Doctor not found")

        try:
            doctor["specializations"] = json.loads(doctor["specializations"]) if doctor["specializations"] else []
            doctor["departments"] = json.loads(doctor["departments"]) if doctor["departments"] else []
            doctor["days_available"] = json.loads(doctor["days_available"]) if doctor["days_available"] else []
            doctor["time_slots"] = json.loads(doctor["time_slots"]) if doctor["time_slots"] else []
            doctor["holiday"] = json.loads(doctor["holiday"]) if doctor["holiday"] else None
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=500, detail=f"Invalid JSON data in database: {str(e)}")

        return doctor
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Database error: {str(err)}")
    finally:
        cursor.close()
        connection.close()

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
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, name, description FROM departments")
        departments = cursor.fetchall()
        return departments
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Database error: {str(err)}")
    finally:
        cursor.close()
        connection.close()

# View All Departments as HTML page
@app.get("/departments/list", response_class=HTMLResponse)
async def list_departments(request: Request):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, name, description FROM departments")
        departments = cursor.fetchall()
        return templates.TemplateResponse("departments_list.html", {"request": request, "departments": departments})
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Database error: {str(err)}")
    finally:
        cursor.close()
        connection.close()

# List Doctors JSON endpoint for frontend fetch
@app.get("/doctors/list-json")
async def list_doctors_json():
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, doctor_name, specializations, contact, fees, experience, departments, days_available, time_slots, holiday, email
            FROM doctors
            """
        )
        doctors = cursor.fetchall()

        for doctor in doctors:
            try:
                doctor["specializations"] = json.loads(doctor["specializations"]) if doctor["specializations"] else []
                doctor["departments"] = json.loads(doctor["departments"]) if doctor["departments"] else []
                doctor["days_available"] = json.loads(doctor["days_available"]) if doctor["days_available"] else []
                doctor["time_slots"] = json.loads(doctor["time_slots"]) if doctor["time_slots"] else []
                doctor["holiday"] = json.loads(doctor["holiday"]) if doctor["holiday"] else None
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=500, detail=f"Invalid JSON data in doctor ID {doctor['id']}: {str(e)}")

        return doctors
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Database error: {str(err)}")
    finally:
        cursor.close()
        connection.close()

# List Doctors endpoint (for HTML rendering)
@app.get("/doctors/list", response_class=HTMLResponse)
async def doctors_list(request: Request):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, doctor_name, specializations, contact, fees, experience, departments, days_available, time_slots, holiday, email
            FROM doctors
            """
        )
        doctors = cursor.fetchall()

        for doctor in doctors:
            try:
                doctor["specializations"] = json.loads(doctor["specializations"]) if doctor["specializations"] else []
                doctor["departments"] = json.loads(doctor["departments"]) if doctor["departments"] else []
                doctor["days_available"] = json.loads(doctor["days_available"]) if doctor["days_available"] else []
                doctor["time_slots"] = json.loads(doctor["time_slots"]) if doctor["time_slots"] else []
                doctor["holiday"] = json.loads(doctor["holiday"]) if doctor["holiday"] else None
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=500, detail=f"Invalid JSON data in doctor ID {doctor['id']}: {str(e)}")

        return templates.TemplateResponse("doctors_list.html", {"request": request, "doctors": doctors})
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Database error: {str(err)}")
    finally:
        cursor.close()
        connection.close()