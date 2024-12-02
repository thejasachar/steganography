# Steganography Project

A Django-based steganography application that allows registered users to securely send and receive hidden messages embedded within images.

---

## Features
- User authentication: Register, login, and manage user accounts.
- Secure message exchange using steganography.
- Send hidden messages within images to other registered users.
- Decode and view hidden messages from received images.

---

## Getting Started

### Prerequisites
- Python 3.12
- pip (Python package manager)
- Git
- Virtual environment tools (`venv` or similar)

---

### Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/thejasachar/steganography.git
```
```
cd steganography_project
```
### 2. Create a Virtual Environment
```bash
python3 -m venv env
```
### 3. Activate the Virtual Environment
On Windows:
```bash
.\env\Scripts\activate
```
On macOS/Linux:
```bash
source env/bin/activate
```
### 4. Install Dependencies
```bash
pip install -r requirements.txt
```
### 5. Apply Migrations
```bash
python manage.py migrate
```
### 6. Run the Development Server
```bash
python manage.py runserver
```
