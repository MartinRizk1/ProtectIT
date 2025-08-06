# Contributing to ProtectIT

Thank you for your interest in contributing to ProtectIT! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct.

## How Can I Contribute?

### Reporting Bugs

- Check if the bug has already been reported in the Issues section
- Use the bug report template when creating a new issue
- Include detailed steps to reproduce the bug
- Include screenshots if applicable
- Describe the expected behavior vs. the actual behavior
- Include system information (OS, Python version, etc.)

### Suggesting Enhancements

- Check if the enhancement has already been suggested in the Issues section
- Use the feature request template when creating a new issue
- Clearly describe the problem and solution
- Explain why this enhancement would be useful to most users

### Pull Requests

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Add or update tests as necessary
5. Update documentation as necessary
6. Commit your changes (with meaningful commit messages)
7. Push to your branch: `git push origin feature/your-feature-name`
8. Create a pull request

## Development Setup

### Prerequisites

- Python 3.8+
- Node.js 14+
- MongoDB (optional)

### Setup Steps

1. Clone your fork of the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`
4. Install dependencies: `pip install -r scanner_service/requirements.txt`
5. Run the setup scripts: `./setup.sh`

## Style Guides

### Git Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

### Python Style Guide

- Follow PEP 8
- Use 4 spaces for indentation
- Use docstrings for all classes and methods
- Keep lines under 100 characters

### JavaScript Style Guide

- Use 2 spaces for indentation
- Use semicolons
- Prefer const over let when variable won't be reassigned
- Use camelCase for variables and functions

## Testing

- Add tests for all new features or bug fixes
- Run the test suite before submitting a pull request
- Ensure all tests pass

## Documentation

- Update the README.md if necessary
- Add or update docstrings
- Comment complex code sections

Thank you for contributing to ProtectIT!
