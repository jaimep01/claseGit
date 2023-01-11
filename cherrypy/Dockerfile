FROM python:latest

COPY certificate.key ./
COPY certificate.pem ./
COPY requirements.txt ./
RUN pip install --no-cache-dir -r ./requirements.txt
COPY app.py ./
RUN chmod 0755 ./app.py

CMD [ "./app.py" ]
