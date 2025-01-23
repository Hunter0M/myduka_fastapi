"""add_password_reset_tokens

Revision ID: 78063f1ddbe5
Revises: 76d26b2a617b
Create Date: 2024-12-23 14:56:09.117261

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '78063f1ddbe5'
down_revision: Union[str, None] = '76d26b2a617b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
