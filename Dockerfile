FROM python:3.11-slim

WORKDIR /app

# System dependencies for weasyprint PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies — web app
COPY requirements.txt requirements-web.txt pyproject.toml poetry.lock* ./
RUN pip install --no-cache-dir -r requirements-web.txt

# Install core library dependencies + editable install
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-root || true

# Application code
COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
