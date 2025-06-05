from pydantic import BaseModel
from typing import List, Optional
from datetime import date, datetime

class UserLogin(BaseModel):
    username: str
    password: str

class UserChangePassword(BaseModel):
    old_password: str
    new_password: str

class HospitalProfile(BaseModel):
    name: str
    description: Optional[str]
    picture: Optional[str]

class Department(BaseModel):
    name: str
    description: Optional[str]

class Doctor(BaseModel):
    name: str
    bio: Optional[str]
    qualifications: List[str]
    years_experience: int
    date_of_birth: date
    available_days: List[str]
    time_slots: List[str]
    department_ids: List[int]

class Appointment(BaseModel):
    patient_name: str
    doctor_id: int
    appointment_date: datetime
    status: str = "pending"

class DoctorHoliday(BaseModel):
    doctor_id: int
    holiday_date: date
    time_slot: Optional[str] = "all_day"