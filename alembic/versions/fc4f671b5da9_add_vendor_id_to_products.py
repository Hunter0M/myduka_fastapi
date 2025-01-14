"""add_vendor_id_to_products

Revision ID: fc4f671b5da9
Revises: 95fffc06d755
Create Date: 2024-12-23 19:13:57.160988

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fc4f671b5da9'
down_revision: Union[str, None] = '95fffc06d755'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
