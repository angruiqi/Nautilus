# 🌟 Contributing to Nautilus

Thank you for considering contributing to **Nautilus**! 🙌  
We welcome contributions of all types, including bug reports, feature requests, documentation improvements, and code contributions. 

By contributing, you're helping build a **better decentralized and secure network framework**.  

---

## 🚀 Getting Started

Before you contribute, please take a moment to read through the following guidelines to ensure a smooth and effective process.

### 📥 Fork the Repository

1. Navigate to the Nautilus GitHub repository:  
   ```shell
   git clone https://github.com/Pierre-Aronnax/Nautilus.git
   ```
2. Create your feature branch:
    ```shell
    git checkout -b feature/my-new-feature
    ```
3. Make your changes and commit them with a clear message:
    ```shell
    git commit -m "feat: Added support for XYZ feature"
    ```
4. Push your branch to GitHub:
    ```shell
    git push origin feature/my-new-feature
    ```
5. Submit a Pull Request (PR) on GitHub.

## 🛠️ Contribution Guidelines
To ensure high-quality contributions, please follow these guidelines:

1. 📝 Code of Conduct
By participating in this project, you agree to abide by our Code of Conduct, fostering an inclusive and respectful environment.

2. 📋 Issues and Feature Requests
If you've found a bug, please open an issue.
For new features, submit a detailed feature request.
Provide as much detail as possible, including logs, system setup, and steps to reproduce.

Issue Guidelines:
- Use clear and descriptive titles.
- Provide steps to reproduce the issue.
- Include relevant logs or screenshots.
3. 🔍 Submitting a Pull Request (PR)
Before submitting a PR, ensure the following:

- Your code follows the project's coding standards and passes lint checks.
- Write appropriate unit tests and check coverage.
- Document any changes in the CHANGELOG.md (if applicable).

Use a meaningful commit message format following Conventional Commits:

```vbnet
feat: Add support for XYZ feature
fix: Resolve bug in ABC module
docs: Improve documentation for setup
```

## 🧩 Project Structure
Nautilus is organized into multiple Rust crates, each serving a specific purpose. While contributing, it's useful to understand the core structure:

/src – Core source code of the project.
/examples – Simple example implementations to guide users.
/tests – Unit and integration tests for validation.
/benchmarks – Performance tests for cryptographic algorithms.
/docs – Project documentation.

##✅ Best Practices
To ensure consistency and maintainability, please follow these best practices:

- Coding Style:

    - Follow Rust's official style guidelines and formatting via cargo fmt.
    - Use clippy for linting via cargo clippy.

- Modularity:
    - Write modular, reusable, and well-documented code.
- Testing:
    - Add tests for new functionality.
    - Run all tests before submitting a PR:
        ```shell
            cargo test --all
        ```
## 📚 Development Setup
To set up your development environment:

Ensure you have Rust (latest stable version) installed via rustup.

- Install project dependencies:
        ```shell
            cargo build
        ```
- Run test suite to verify everything works:
        ```shell
            cargo test
        ```
---
## 🎯 How You Can Help
Not sure where to start? Here are some ideas:

- Improve Documentation:
    - Help us expand and refine our docs.
- Write Tests:
    - Improve code coverage by writing tests.
- Enhance Performance:
    - Identify performance bottlenecks and optimize them.
- Tackle Open Issues