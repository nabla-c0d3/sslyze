FROM python:3.9-slim
RUN pip install sslyze
RUN adduser -S -H -u 1001 sslyze
USER sslyze
ENTRYPOINT ["sslyze"]
CMD ["-h"]