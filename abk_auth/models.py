from pydantic import BaseModel, EmailStr


class User(BaseModel):
    email: EmailStr
    nombre: str
    roles: list[str]

    def is_admin(self) -> bool:
        return "admin" in self.roles

    def has_any_role(self, allowed_roles: list[str]) -> bool:
        return any(rol in allowed_roles for rol in self.roles)
