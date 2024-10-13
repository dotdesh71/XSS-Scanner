# XSS Scanner Tool

A Python-based XSS vulnerability scanner with a graphical user interface (GUI) built using `Tkinter`. This tool scans websites for XSS vulnerabilities by testing with a list of payloads loaded from an external file (`xss.txt`). It provides real-time updates, allowing you to pause, resume, and stop the scan, and it saves the results for later review. Additionally, the tool includes various customization options such as dark mode and bypass techniques.

## Features

- **Batch Payload Loading**: Loads payloads in batches to avoid overloading memory.
- **Pause/Resume Scan**: You can pause and resume scanning at any time.
- **Stop Scan**: Allows stopping the scan and viewing partial results.
- **Save Results**: Save the list of vulnerable sites to a `.txt` file.
- **Dark Mode/Light Mode**: Switch between light and dark themes.
- **Real-time Display**: Vulnerable sites are shown in real-time as the scan progresses.
- **Error Handling**: Handles network errors gracefully during the scan.
- **Reset Function**: Reset the entire GUI to its default state for a new scan.
- **Progress Bar**: Visual indicator of scanning progress.

## Requirements

- Python 3.9 or higher
- `requests` library

To install the required dependencies, run:

    pip install requests

### Usage

Clone the repository and navigate to the project directory:

    git clone https://github.com/dotdesh71/XSS-Scanner.git

    cd XSS-Scanner

Ensure you have a valid xss.txt file with XSS payloads. This file should be located in the same directory as the script.

Run the tool:

    python xssscan.py

Enter the URL you want to scan and press the Scan for XSS button.

Use the Pause Scan button to pause scanning and Resume Scan to continue. You can also Stop Scan to end scanning early, saving partial results.

After the scan, you can Save Results to a file.

Reset the interface using the Reset button to clear previous scans.

File Structure

    xss_scanner_gui.py: Main Python script with GUI and scanning logic.
    xss.txt: File containing a list of XSS payloads (you need to provide this file).
    README.md: Project documentation.

Example Screenshot

License

This project is licensed under the MIT License. See the LICENSE file for more details.
Contributing

Contributions are welcome! Please submit a pull request or open an issue to suggest improvements or report bugs.
