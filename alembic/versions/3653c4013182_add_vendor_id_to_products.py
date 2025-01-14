"""add_vendor_id_to_products

Revision ID: 3653c4013182
Revises: fc4f671b5da9
Create Date: 2024-12-23 19:30:44.754732

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3653c4013182'
down_revision: Union[str, None] = 'fc4f671b5da9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
