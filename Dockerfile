FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Force-install Chromium that matches the pip-installed Playwright version.
# This guarantees the chromium_headless_shell binary path matches whatever
# playwright pip resolves to, even if the base image's bundled browser is
# from a different release.
RUN playwright install chromium

# Copy application code
COPY . .

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "the_big_brother.gui.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
