"""add_vendor_id_to_products

Revision ID: 95fffc06d755
Revises: 6350118be531
Create Date: 2024-12-23 19:12:24.143261

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '95fffc06d755'
down_revision: Union[str, None] = '6350118be531'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
