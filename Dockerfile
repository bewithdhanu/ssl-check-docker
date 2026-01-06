FROM python:3.11-slim

# Install whois and CA certificates (required for SSL verification)
RUN apt-get update && \
    apt-get install -y --no-install-recommends whois ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the domain checker script and web app
COPY domain_checker.py /app/domain_checker.py
COPY app.py /app/app.py
RUN chmod +x /app/app.py

# Expose port
EXPOSE 5000

# Set environment variables
ENV PORT=5000
ENV HOST=0.0.0.0

# Run the web service with uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]

