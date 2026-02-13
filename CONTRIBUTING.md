# Contributing to Mesh-Pulse

First off, thanks for taking the time to contribute! ❤️

The following is a set of guidelines for contributing to Mesh-Pulse. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## How Can I Contribute?

### Reporting Bugs

Bugs are tracked as GitHub issues. When creating an issue, please include:
- A clear, descriptive title.
- Steps to reproduce the bug.
- The behavior you expected.
- Screenshots if applicable.
- Your OS and Python version.

### Suggesting Enhancements

Enhancement suggestions are also tracked as GitHub issues. Please provide:
- A clear, descriptive title.
- A step-by-step description of the suggested enhancement.
- An explanation of why this enhancement would be useful.

### Pull Requests

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes (`pytest`).
5. Make sure your code lints.

## Development Setup

1. Clone the repository.
2. Create a virtual environment: `python -m venv venv`.
3. Activate the virtual environment:
   - Linux/macOS: `source venv/bin/activate`
   - Windows: `venv\Scripts\activate`
4. Install dependencies: `pip install -r requirements.txt`.
5. Install the package in editable mode: `pip install -e .`.
6. Run tests: `pytest`.

## Styleguides

### Python Styleguide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/).

### Commit Messages

- Use the present tense ("Add feature" not "Added feature").
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...").
- Limit the first line to 72 characters or less.

## License

By contributing, you agree that your contributions will be licensed under its MIT License.
