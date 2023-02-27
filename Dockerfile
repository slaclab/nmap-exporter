FROM python:3.9-slim-buster

RUN mkdir /app
ADD main.py /app/main.py
ADD requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt && rm /app/requirements.txt
RUN apt-get update && apt-get install -y nmap && apt-get autoclean && apt-get autoremove && rm -rf /var/lib/apt/lists/* && rm -rf /var/cache
EXPOSE 8000

CMD ["python","-u" , "/app/main.py"]

