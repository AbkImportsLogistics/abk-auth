from pydantic import BaseModel, EmailStr


class User(BaseModel):
    email: EmailStr | None = None
    nombre: str
    roles: list[str] = []
    sub: str | None = None

    def is_admin(self) -> bool:
        return "administrador" in self.roles

    def has_any_role(self, allowed_roles: list[str]) -> bool:
        return any(rol in allowed_roles for rol in self.roles)
