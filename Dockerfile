FROM python:3.7

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY x509-exporter .

EXPOSE 9090

ENTRYPOINT [ "python", "./x509-exporter" ]
CMD ["--port=9090"]