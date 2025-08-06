# Contributing to ProtectIT

<<<<<<< HEAD
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
=======
Thank you for considering contributing to ProtectIT! This document outlines the process and guidelines for contributing to this project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in the Issues section
2. If not, create a new issue with a clear title and description
3. Include steps to reproduce the bug
4. Include any relevant screenshots or error messages
5. Describe your environment (OS, browser, etc.)

### Suggesting Enhancements

1. Check if the enhancement has already been suggested in the Issues section
2. If not, create a new issue with a clear title and description
3. Explain why this enhancement would benefit the project
4. Provide examples of how it would work
>>>>>>> a38f037fb783c4032cc7113cb2218a77160b46dd

### Pull Requests

1. Fork the repository
<<<<<<< HEAD
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Add or update tests as necessary
5. Update documentation as necessary
6. Commit your changes (with meaningful commit messages)
7. Push to your branch: `git push origin feature/your-feature-name`
8. Create a pull request
=======
2. Create a new branch from `main` (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run tests to ensure your changes don't break existing functionality
5. Commit your changes with a clear commit message
6. Push to your branch (`git push origin feature/your-feature`)
7. Submit a Pull Request to the `main` branch
>>>>>>> a38f037fb783c4032cc7113cb2218a77160b46dd

## Development Setup

### Prerequisites
<<<<<<< HEAD

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
=======
- Python 3.8+
- Node.js 16+
- MongoDB

### Setup

1. Clone the repository
```bash
git clone https://github.com/yourusername/ProtectIT.git
cd ProtectIT
```

2. Run the setup script
```bash
chmod +x setup.sh
./setup.sh
```

3. Start the application components
```bash
./start.sh
```

## Coding Guidelines

### Python
- Follow PEP 8 style guide
- Use docstrings for functions and classes
- Maintain test coverage for new features

### JavaScript/React
- Follow ESLint rules
- Use functional components and hooks
- Follow component-based architecture

## Testing

- Run tests before submitting PR
- Add tests for new features
>>>>>>> a38f037fb783c4032cc7113cb2218a77160b46dd
- Ensure all tests pass

## Documentation

<<<<<<< HEAD
- Update the README.md if necessary
- Add or update docstrings
- Comment complex code sections

Thank you for contributing to ProtectIT!
=======
- Update README.md if necessary
- Document new features
- Update API documentation for new endpoints

## License

By contributing to ProtectIT, you agree that your contributions will be licensed under the project's MIT License.
>>>>>>> a38f037fb783c4032cc7113cb2218a77160b46dd
