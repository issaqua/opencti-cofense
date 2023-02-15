FROM python:3.10-alpine as build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /opt/build

# Install poetry
RUN apk add --no-cache git
RUN pip3 install poetry

# Copy Source files.
COPY src ./src

# Install package dependencies
COPY pyproject.toml ./
RUN poetry env use /usr/local/bin/python3 && \
    poetry update --lock
RUN poetry env use /usr/local/bin/python3 && \
    poetry install --no-root --no-dev

FROM python:3.10-alpine

# Install package
COPY src ./src
RUN poetry install --no-dev 

WORKDIR /opt/connector

RUN apk add --no-cache libmagic

# Copy the package
COPY --from=build /opt/build/.venv ./.venv
COPY --from=build /opt/build/src   ./

# "Activate" the venv
ENV PATH="/opt/connector/.venv/bin:${PATH}"

# Entrypoint
ENTRYPOINT ["python3", "-m", "cofense"]
