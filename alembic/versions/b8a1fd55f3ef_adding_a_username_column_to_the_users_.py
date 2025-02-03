"""Adding username column to users table with data migration

Revision ID: b8a1fd55f3ef
Revises: dc003bb8eab8
Create Date: 2025-01-23 16:26:22.804414

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = 'b8a1fd55f3ef'
down_revision: Union[str, None] = 'dc003bb8eab8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add the username column as nullable first
    op.add_column('users', sa.Column('username', sa.String(), nullable=True))
    
    # 2. Update existing records with a generated username from email
    # Using a more robust approach to handle potential duplicates
    op.execute("""
        WITH numbered_users AS (
            SELECT id, email, ROW_NUMBER() OVER (PARTITION BY SPLIT_PART(email, '@', 1) ORDER BY id) as rn
            FROM users
            WHERE username IS NULL
        )
        UPDATE users u
        SET username = CASE 
            WHEN nu.rn = 1 THEN SPLIT_PART(u.email, '@', 1)
            ELSE SPLIT_PART(u.email, '@', 1) || nu.rn::text
        END
        FROM numbered_users nu
        WHERE u.id = nu.id;
    """)
    
    # 3. Verify all usernames are set
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM users WHERE username IS NULL) THEN
                RAISE EXCEPTION 'Some users still have NULL usernames';
            END IF;
        END
        $$;
    """)
    
    # 4. Make the column non-nullable and unique
    op.alter_column('users', 'username',
        existing_type=sa.String(),
        nullable=False
    )
    op.create_unique_constraint('uq_users_username', 'users', ['username'])


def downgrade() -> None:
    # Remove the constraints first
    op.drop_constraint('uq_users_username', 'users', type_='unique')
    # Then remove the column
    op.drop_column('users', 'username')
