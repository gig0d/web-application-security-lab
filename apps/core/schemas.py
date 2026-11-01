from pydantic import BaseModel, ConfigDict, Field


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginInput(Input):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class TicketInput(Input):
    title: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=4000)


class CommentInput(Input):
    body: str = Field(min_length=1, max_length=4000)
    private: bool = False


class AssignmentInput(Input):
    assignee_id: int = Field(gt=0)


class StatusInput(Input):
    status: str = Field(pattern="^(open|closed)$")


class RoleInput(Input):
    role: str = Field(pattern="^(customer|employee|admin)$")


class ProfileInput(Input):
    display_name: str = Field(min_length=1, max_length=80)


class ResetInput(Input):
    confirmation: str = Field(pattern="^RESET SYNTHETIC HARBORDESK$")
