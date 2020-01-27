FROM python:2

WORKDIR /usr/src/app

COPY alarm-monitor.py ./
COPY texecomConnect.py ./
COPY hexdump.py ./

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

CMD [ "python", "alarm-monitor.py" ]
