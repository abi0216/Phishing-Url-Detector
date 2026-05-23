# PhishGuard Professional

A production-level phishing URL detection system with a two-layer security architecture.

## 🏗️ Project Architecture: Production MVC

This project follows the **Model-View-Controller (MVC)** pattern, which is the industry standard for scalable web applications.

### **Folder Breakdown**
- **app/**: The core application logic.
  - **routes/**: The *Controller* layer. Handles incoming requests and directs traffic.
  - **services/**: The business logic. Contains Feature Engineering and External Intelligence gathering.
  - **models/**: The *Model* layer. Manages ML model loading and prediction logic.
  - **utils/**: Helper functions and miscellaneous tools.
- **config/**: Centralized configuration management.
- **models/**: Storage for serialized pickle files (weights).
- **logs/**: Application runtime logs for debugging in production.
- **cache/**: File-based caching storage to speed up repeated scans.
- **tests/**: Automated unit tests to ensure reliability.

## 🚀 Why Structured Folders?

1.  **Maintainability**: Separate concerns (logic vs UI vs config) make it easier to find and fix bugs.
2.  **Scalability**: You can add new routes, new ML models, or new external APIs without breaking existing code.
3.  **Collaboration**: Standardized structures allow multiple developers to work on different parts of the app simultaneously.
4.  **Security**: sensitive information (like API keys) is centralized in `.env` and `config/` rather than hardcoded in files.

![image alt](https://github.com/abi0216/Phishing-Url-Detector/blob/e501147152381e35d558c74002efcc6cafe26ce3/Screenshot%202026-05-23%20191908.png)
![image alt](https://github.com/abi0216/Phishing-Url-Detector/blob/228babcaeef16d754b5cc4e79957352786cd097a/Screenshot%202026-05-23%20194332.png)

![image alt](https://github.com/abi0216/Phishing-Url-Detector/blob/d09bf4e1647a61a876d223a2c3a408f8ff76e088/Screenshot%202026-05-23%20194321.png)







































## 🛠️ Getting Started

1.  Clone the project.
2.  Install dependencies: `pip install -r requirements.txt`
3.  Configure your `.env` file with API keys.
4.  Run the app: `python app.py`
