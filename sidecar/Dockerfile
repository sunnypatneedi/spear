FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download model to cache it in image
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2')"

# Copy application
COPY spear_py/ ./spear_py/

# Expose port
EXPOSE 8088

# Run server
CMD ["python", "-m", "spear_py.api"]
