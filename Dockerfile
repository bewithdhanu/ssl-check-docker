FROM python:3.11-slim

# Install whois and optimize image size
RUN apt-get update && \
    apt-get install -y --no-install-recommends whois && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory
WORKDIR /app

# Copy the domain checker script and set permissions in one layer
COPY domain_checker.py /app/domain_checker.py
RUN chmod +x /app/domain_checker.py

# Set the script as the entrypoint
ENTRYPOINT ["python3", "/app/domain_checker.py"]

# Default command (can be overridden)
CMD []

