"""add_password_reset_tokens

Revision ID: a34226bc59f8
Revises: 78063f1ddbe5
Create Date: 2024-12-23 15:28:35.059577

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a34226bc59f8'
down_revision: Union[str, None] = '78063f1ddbe5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
