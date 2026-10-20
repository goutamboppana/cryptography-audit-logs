"""Validated request models and typed API response shapes."""

from pydantic import BaseModel, ConfigDict, Field


class StudentCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=100, examples=["Asha Rao"])
    student_number: str = Field(min_length=1, max_length=40, examples=["CS-2026-014"])
    marks: int = Field(ge=0, le=100, examples=[85])


class MarksUpdate(BaseModel):
    marks: int = Field(ge=0, le=100, examples=[95])


class DemoTamperRequest(BaseModel):
    sequence: int = Field(ge=1)

