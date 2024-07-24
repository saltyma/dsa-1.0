# Digital Art Signature Application

## Description
This application allows users to digitally sign and manage their artwork using the DSA (Digital Signature Algorithm).

## Features
- User authentication and registration
- Upload and sign artworks
- View and manage signed artworks
- Export artwork signatures

## Installation

### Prerequisites
- Python 3.6 or higher
- Required libraries: `customtkinter`, `pillow`, `cryptography`, `sqlite3`

### Steps
1. Clone the repository:
    ```bash
    git clone https://github.com/saltyma/dsa-1.0.git
    ```

2. Navigate to the project directory:
    ```bash
    cd dsa-1.0
    ```

3. Install the required libraries:
    ```bash
    pip install customtkinter pillow cryptography
    ```

4. Initialize the database:
    ```bash
    python init_db.py
    ```

5. Run the application:
    ```bash
    python DAS2.0.py
    ```

## Usage
- Launch the application and either log in or create a new account.
- Upload and sign your artwork.
- View, manage, and export your signed artworks.

## Contributing
To contribute, follow these steps:
1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`.
3. Make your changes and commit them: `git commit -m 'Add new feature'`.
4. Push to the branch: `git push origin feature-branch`.
5. Submit a pull request.

## License
This project is licensed under the MIT License.
