try:
    import pydantic.v1 as pydantic
except ImportError:
    import pydantic # type: ignore # noqa


class BaseModelWithOrmMode(pydantic.BaseModel):
    class Config:
        orm_mode = True


class BaseModelWithOrmModeAndForbid(pydantic.BaseModel):
    class Config:
        orm_mode = True
        extra = "forbid"  # Fields must match between the JSON representation and the result objects
