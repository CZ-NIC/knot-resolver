FROM debian:latest

ENV LC_ALL=C.UTF-8

# pyenv setup deps
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y build-essential git ca-certificates

# python build deps
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

# Yarn and NodeJS (following https://github.com/nodesource/distributions/blob/master/README.md#debmanual)
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y gnupg lsb-release
RUN curl -sSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add -
ENV VERSION=node_14.x
RUN echo "deb https://deb.nodesource.com/$VERSION $(lsb_release -s -c) main" | tee /etc/apt/sources.list.d/nodesource.list
RUN echo "deb-src https://deb.nodesource.com/$VERSION $(lsb_release -s -c) main" | tee -a /etc/apt/sources.list.d/nodesource.list
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y nodejs
RUN npm install -g yarn

# Add non-root user
RUN useradd -m -s /bin/bash user
USER user
WORKDIR /home/user

# install pyenv
RUN curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash
ENV PATH="/home/user/.pyenv/bin:$PATH"
# These would should be run in the shell that will be running pyenv. But it can hopefully work without it
# RUN eval "$(pyenv init -)"
# RUN eval "$(pyenv virtualenv-init -)"

# install all required versions of python via pyenv
RUN pyenv install 3.6.12
RUN pyenv install 3.7.9
RUN pyenv install 3.8.7
RUN pyenv install 3.9.1

# install poetry
USER root
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y python3 python3-distutils-extra
USER user

RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3 -
ENV PATH="/home/user/.poetry/bin:$PATH"
# force Poetry to run under python3
RUN sed -i 's/env python/env python3/' .poetry/bin/poetry
# force Poetry to use local .venv/ directory that we can cache
ENV POETRY_VIRTUALENVS_IN_PROJECT=true


# install additional project dependencies
USER root
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y libcairo2-dev libglib2.0-0 libgirepository1.0-dev
USER user
