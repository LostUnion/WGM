# WGM - API Client for WireGuard Management

## Overview

`WGM` is a Python client library designed to interact with a WireGuard server API. This library enables actions such as creating, deleting, enabling, and disabling users, as well as managing sessions and retrieving user information.

## Features

- **Session Management**: Start a session with the server using provided credentials (IP, port, password).
- **User Management**: Retrieve a list of all users, and perform actions like create, delete, enable, and disable users.
- **Session Re-establishment**: Automatically re-establishes a session if authentication fails.
- **HTTP Method Support**: Supports `POST`, `DELETE`, `PUT` HTTP methods for data manipulation.
  
## Installation

To install dependencies, use [Poetry](https://python-poetry.org/). Just run the command:

```bash
poetry install
```
This will install all the dependencies specified in project.toml.

## Using WGM

```python
from WGM_api import WGM_api

# Session initialization #
session = WGM_api()

# Set up a session with the server #
session.start_session(ip_address="ip_address", port=port, password="your_password")

# Example of creating a new user #
session.create_user(name="user_name")

# Example of deleting a user #
session.delete_user(value="existing_user")

# When creating a user, we must specify the desired name, while when deleting a user, it can be done either by name or by ID. #
```

### Methods

- **start_session(ip_address, port, password)** — Initializes a session with the server.
- **get_all_users()** — Retrieves a list of all users.
- **create_user(name)** — Creates a new user.
- **delete_user(value)** — Deletes a user (by name or ID).
- **enable_user(value)** — Enables the user (by name or ID).
- **disable_user(value)** — Disables the user. (by name or ID).
- **download_config(value)** — Download config file the user. (by name or ID).

## PyPI

The `WGM` library is available on [PyPI](https://pypi.org/project/wgm_api/), making it easy to install and integrate into your projects.

Install it via `pip`:
```bash
pip install wgm_api
```
Or poetry:
```bash
poetry add wgm_api
```

<div align="center">

## Libraries in this project

[![Python](https://img.shields.io/badge/Python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-orange?logo=python&color=blue)](https://www.python.org/downloads/) [![Requests](https://img.shields.io/badge/Requests-^2.32.3-brightgreen?logo=Requests&color=green)](https://requests.readthedocs.io/en/latest/)

<i>Version 1.0.0 | Release Date: November 21, 2024</i>
</div>

