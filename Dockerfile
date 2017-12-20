FROM python
RUN pip install sslyze
ENTRYPOINT ["sslyze"]
CMD ["-h"]
