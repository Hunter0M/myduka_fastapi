"""implement_multi_tenant_structure

Revision ID: 50e461770a28
Revises: 62108e5e4e4d
Create Date: 2024-03-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '50e461770a28'
down_revision: Union[str, None] = '62108e5e4e4d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
