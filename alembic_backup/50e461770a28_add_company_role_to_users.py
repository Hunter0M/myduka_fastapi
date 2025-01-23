"""add_company_role_to_users

Revision ID: 50e461770a28
Revises: e62fdee12e04
Create Date: 2025-01-22 08:55:34.054757

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '50e461770a28'
down_revision: Union[str, None] = 'e62fdee12e04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
