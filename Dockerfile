FROM python:3.11-slim
WORKDIR /usr/src/app
COPY req.txt ./
RUN pip install --no-cache-dir -r req.txt
COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "6100"]