FROM python:3.11-slim

WORKDIR /code

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY ./app /code/app

# Create uploads directory
RUN mkdir -p /code/app/uploads

# Copy migrations
COPY alembic /code/alembic
COPY alembic.ini /code/alembic.ini

# Command to run the application
# CMD alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]