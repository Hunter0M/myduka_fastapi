"""add status to sales table

Revision ID: 63abac0c4afd
Revises: b6f66724c8fc
Create Date: 2024-01-12 19:38:58.090708

"""
from typing import Union, Sequence
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '63abac0c4afd'
down_revision = 'b6f66724c8fc'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add columns with default values
    op.execute('ALTER TABLE sales ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT \'completed\'')
    op.execute('ALTER TABLE sales ADD COLUMN IF NOT EXISTS unit_price FLOAT DEFAULT 0')


def downgrade() -> None:
    # Remove columns if they exist
    op.execute('ALTER TABLE sales DROP COLUMN IF EXISTS status')
    op.execute('ALTER TABLE sales DROP COLUMN IF EXISTS unit_price')
