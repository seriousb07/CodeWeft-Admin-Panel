from pydantic import BaseModel

class UserLogin(BaseModel):
    username: str
    password: str

class UserChangePassword(BaseModel):
    old_password: str
    new_password: str

class DepartmentCreate(BaseModel):
    department_name: str
    description: str

class DoctorCreate(BaseModel):
    doctor_name: str
    specialization: str
    contact: str
    department: str

class ProfileUpdate(BaseModel):
    admin_name: str
    email: str
    contact: str