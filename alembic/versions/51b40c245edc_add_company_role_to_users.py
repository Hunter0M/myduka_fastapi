"""add_company_role_to_users

Revision ID: 51b40c245edc
Revises: 50e461770a28
Create Date: 2025-01-22 10:32:57.402105

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '51b40c245edc'
down_revision: Union[str, None] = '50e461770a28'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add company_id and company_role columns to users table
    op.add_column('users', sa.Column('company_id', sa.Integer(), nullable=True))
    op.add_column('users', sa.Column('company_role', sa.String(), nullable=True))
    
    # Add foreign key constraint
    op.create_foreign_key(
        'fk_users_company_id',
        'users', 'companies',
        ['company_id'], ['id']
    )


def downgrade() -> None:
    # Remove foreign key constraint first
    op.drop_constraint('fk_users_company_id', 'users', type_='foreignkey')
    
    # Remove columns
    op.drop_column('users', 'company_role')
    op.drop_column('users', 'company_id')
