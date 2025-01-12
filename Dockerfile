FROM zricethezav/gitleaks:latest as gitleaks

WORKDIR /app


FROM python:3.10-alpine3.16

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --from=gitleaks /usr/bin/gitleaks /app/

COPY ./gitleaks_script.py /app/

ENTRYPOINT ["python3","/app/gitleaks_script.py"]

CMD ["gitleaks", "detect", "--no-git", "--report-path", "/code/output.json", "/code/"]
