# Use an official Python runtime as a parent image
FROM python:3.11-alpine

# Set the working directory in the container
WORKDIR /app

# Set environment variables
# Gunicorn environment variables can be set here if needed
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Install dependencies required for building certain Python packages
RUN apk add --no-cache gcc musl-dev linux-headers

# Copy the current directory contents into the container at /app
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

# Install Gunicorn
RUN pip install gunicorn

# Make port 8000 available to the world outside this container
# Gunicorn default port is 8000, but you can change it if needed
EXPOSE 8000

# Define environment variable for Gunicorn to run in a more production-like setting
ENV GUNICORN_CMD_ARGS="--bind=0.0.0.0:8000 --workers=3"

# Run the application using Gunicorn
# The number of workers is set to 3 as a starting point. Adjust based on your needs and available resources
CMD ["gunicorn", "-w", "3", "app:app"]

