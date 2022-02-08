FROM --platform=amd64 python:3.9-slim
SHELL ["/bin/bash", "--login", "-c"]

ENV DEBIAN_FRONTEND noninteractive
ENV LANG C.UTF-8

COPY . /sslyze/
# install latest updates as root
RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo \
        ca-certificates \
	netbase \
        curl \
        git \
        bash-completion \
	&& rm -rf /var/lib/apt/lists/*

# install sslyze based on sourcecode
RUN pip install --no-cache-dir --quiet --upgrade pip && \
    pip install --no-cache-dir --quiet --upgrade setuptools && \
    pip install --no-cache-dir --quiet --upgrade wheel && \
    pip install --no-cache-dir --quiet --upgrade -e /sslyze/. \
    pip install --no-cache-dir --quiet --upgrade -r /sslyze/dev-requirements.txt 

#RUN python /sslyze/setup.py install
# set user to a non-root user sslyze
#RUN adduser --no-create-home --disabled-password --gecos "" --uid 1001 sslyze
#USER sslyze
# restrict execution to sslyze
#WORKDIR /sslyze
#ENTRYPOINT ["python", "-m", "sslyze"]
CMD ["bash"]