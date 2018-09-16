FROM python:3.7-slim
RUN pip install sslyze
ENTRYPOINT ["sslyze"]
CMD ["-h"]