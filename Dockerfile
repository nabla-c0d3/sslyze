FROM python:3.9-slim
COPY . /sslyze/
# install latest updates as root
RUN apt-get update \
        && apt-get install -y sudo
# install sslyze based on sourcecode
RUN python -m pip install --upgrade pip setuptools wheel
RUN python /sslyze/setup.py install
# set user to a non-root user sslyze
RUN adduser --no-create-home --disabled-password --gecos "" --uid 1001 sslyze
USER sslyze
# restrict execution to sslyze
WORKDIR /sslyze
ENTRYPOINT ["python", "-m", "sslyze"]
CMD ["-h"]