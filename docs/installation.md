# Installation Guide

This guide provides detailed instructions for setting up and running your own AuthGlow instance. We'll cover two primary methods: using Docker (recommended for ease of use and consistency) and setting up a local Python environment (for development or custom deployments).

## Prerequisites

Before you begin, ensure you have the following software installed on your system:

*   **Git**: For cloning the repository.
*   **Docker**: (Recommended) For the containerized setup.
*   **Python**: Version 3.10 or newer (if you choose the local environment method).

---

## Method 1: Docker (Recommended)

Using Docker is the simplest and most reliable way to deploy AuthGlow. It encapsulates all dependencies and ensures the application runs in a consistent environment.

### Step 1: Clone the Repository

First, clone the AuthGlow repository to your local machine using Git.

```bash
git clone https://github.com/your-username/authglow.git
cd authglow
```

### Step 2: Create the Configuration File

AuthGlow is configured via a `.env` file. Copy the provided example file to create your own. For a basic local setup, you don't need to change anything yet.

```bash
cp .env.example .env
```
**Important**: For any production use, you must edit the `.env` file and set strong, unique values for `SECRET_KEY` and `JWT_SECRET_KEY`.

### Step 3: Build the Docker Image

From the root of the project directory, run the `docker build` command. This will create a Docker image named `authglow` containing the application and all its dependencies.

```bash
docker build -t authglow .
```

### Step 4: Run the Container

Now, you can start the AuthGlow container. The following command is recommended:

```bash
docker run -p 8000:8000 --name authglow-instance \
  -v ./data:/app/data \
  --env-file .env \
  authglow
```

Let's break down this command:
*   `-p 8000:8000`: Maps port 8000 on your host machine to port 8000 inside the container.
*   `--name authglow-instance`: Assigns a memorable name to your container.
*   `-v ./data:/app/data`: **This is a crucial step.** It mounts the local `./data` directory into the container at `/app/data`. This ensures that all your user data, logs, and configurations are stored on your host machine and will persist even if you stop or remove the container.
*   `--env-file .env`: Tells Docker to load the environment variables from your `.env` file.
*   `authglow`: The name of the image to run.

### Step 5: Access AuthGlow

Your AuthGlow instance is now running! You can access it by navigating to `http://localhost:8000` in your web browser.

---

## Method 2: Local Python Environment

This method is suitable for developers who want to work on the AuthGlow source code directly.

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/authglow.git
cd authglow
```

### Step 2: Create and Activate a Virtual Environment

It is highly recommended to use a Python virtual environment to avoid conflicts with system-wide packages.

*   **On macOS / Linux:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```
*   **On Windows:**
    ```bash
    python -m venv .venv
    .venv\Scripts\activate
    ```

### Step 3: Install Dependencies

Install all the required Python packages using `pip`.

```bash
pip install -r requirements.txt
```

### Step 4: Configure Your Environment

Copy the `.env.example` file to `.env`.

```bash
cp .env.example .env
```
Make sure to review the settings in `.env`, especially the `SECRET_KEY` and `JWT_SECRET_KEY`, before running the application for any serious purpose.

### Step 5: Run the Application

Start the development server with the following command:

```bash
python main.py
```

### Step 6: Access AuthGlow

Your AuthGlow instance is now running and accessible at `http://localhost:8000`.

## First-Time Setup

On the very first run, AuthGlow will automatically create the necessary directory structure inside your `data` folder (as defined by `STORAGE_PATH` in your `.env` file). You will be guided through a setup process in the web interface to create the initial administrator account.

## Next Steps

Now that your instance is running, here are some recommended next steps:

*   **[Configuration](./configuration.md)**: Dive into the configuration file to customize your instance.
*   **[Using the Admin Panel](./guides/01-admin-panel.md)**: Learn how to manage users, roles, and OAuth clients.
*   **[OAuth/OIDC Guide](./guides/02-oauth-oidc.md)**: Start connecting your applications to AuthGlow.
