try:
    # pydantic 2.x
    from pydantic.v1 import BaseModel  # TODO(#617): Remove v1
except ImportError:
    # pydantic 1.x
    from pydantic import BaseModel  # type: ignore


class BaseModelWithOrmMode(BaseModel):
    class Config:
        orm_mode = True


class BaseModelWithOrmModeAndForbid(BaseModel):
    class Config:
        orm_mode = True
        extra = "forbid"  # Fields must match between the JSON representation and the result objects
