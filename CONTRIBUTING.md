# Contributing to AgentShield-X

Thank you for your interest in contributing to AgentShield-X! We appreciate your support in securing LLM interactions for the open-source community.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

---

## 🛠️ Development Setup

### 1. Prerequisites
* Python 3.10 or 3.11
* SQLite (local development) or PostgreSQL (production)
* Git

### 2. Setup Guide
1. Fork the repository and clone your fork:
   ```bash
   git clone https://github.com/Vaishnavi-Chandrawanshi/AgentShield-X.git
   cd AgentShield-X
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```
3. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy the environment template and configure local variables:
   ```bash
   cp .env.example .env
   ```
5. Apply database migrations:
   ```bash
   alembic upgrade head
   ```

---

## 🧪 Testing

We require all contributions to maintain complete test coverage. Before submitting any changes, verify that the test suite passes:
```bash
pytest
```

---

## 📝 Code Conventions & Styles

* **PEP 8 Compliance**: Follow standard Python conventions.
* **Docstrings**: Document classes, methods, and API routes cleanly.
* **No Unused Code**: Clean up unused imports, dead prints, and debug loops before committing.
* **Secure by Default**: Ensure no secrets, keys, or credentials are added to the code files.

---

## 🚀 Submitting Pull Requests

1. Create a descriptive branch:
   ```bash
   git checkout -b feature/your-awesome-feature
   ```
2. Write clean code and add unit tests.
3. Commit your changes with clear, semantic messages.
4. Push to your branch and open a Pull Request against the `main` branch.
5. Ensure the automated CI/CD pipeline completes successfully.
