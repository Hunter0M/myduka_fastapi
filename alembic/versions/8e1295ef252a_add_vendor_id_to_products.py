"""add_vendor_id_to_products

Revision ID: 8e1295ef252a
Revises: 3653c4013182
Create Date: 2024-12-23 19:31:13.572685

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8e1295ef252a'
down_revision: Union[str, None] = '3653c4013182'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
