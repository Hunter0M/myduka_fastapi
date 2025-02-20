from sqlalchemy import create_engine, text
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database credentials from environment variables
DB_USER = os.getenv("DATABASE_USERNAME", "postgres")
DB_PASS = os.getenv("DATABASE_PASSWORD", "0777")
DB_HOST = os.getenv("DATABASE_HOSTNAME", "localhost")
DB_PORT = os.getenv("DATABASE_PORT", "5432")
DB_NAME = os.getenv("DATABASE_NAME", "myduka_api")

# Create database URL
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

print(f"Connecting to database: {DB_HOST}:{DB_PORT}/{DB_NAME}")

try:
    # Create engine
    engine = create_engine(DATABASE_URL)

    # Execute update
    with engine.connect() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num = '62108e5e4e4d'"))
        connection.commit()
        print("Successfully updated alembic_version")
except Exception as e:
    print(f"Error: {e}") 