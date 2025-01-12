import subprocess
import json
import sys
import os
from pydantic import BaseModel, ValidationError
from typing import List, Dict
from pathlib import Path


class Leak(BaseModel):
    File: str
    StartLine: int
    EndLine: int
    Description: str


def error_occurred(message: str, exit_code: int) -> None:
    """
    General message to execute if an error occurred.
    :return: None
    """

    error = {
        "exit_code": exit_code,
        "error_message": message
    }
    # Print the JSON in the desired format
    formatted_json = json.dumps(error, indent=4)
    print(formatted_json)
    sys.exit(exit_code)


def check_mount(path: str) -> None:
    """
    checks if there was mounting of directory path.
    if so, checks if the path is empty.
    :param path: The path checked if was mount.
    """

    path = Path(path)
    if not path.exists() or not path.is_dir():
        error_occurred(f"There was a problem with mounting to {path}", 1)
    elif not any(path.iterdir()):
        error_occurred(f"The directory at {path} is empty", 1)


def extract_error_message(stderr: str) -> str:
    """Extract only the main error message from stderr."""
    for line in stderr.splitlines():
        if line.startswith("Error:"):
            return line
    return "An unknown error occurred."


def run_gitleaks(command_args: List[str]) -> int:
    """
    Run the Gitleaks command with provided arguments and capture the output.

    :param command_args: List of command line arguments to pass to Gitleaks.
    :return: raw Gitleaks output
    """
    try:
        # Run Gitleaks using subprocess
        results = subprocess.run(command_args, capture_output=True, text=True,
                                 check=True)
        return results.returncode
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            error_explaintion = extract_error_message(e.stderr.strip())
            error_message = f"""Gitleaks scan failed! 
            Command: {' '.join(command_args)} 
            Error: {error_explaintion} """

            error_occurred(error_message, 2)
        return e.returncode


def extract_data(output_path: str) -> List[Dict]:
    """
    Get a file with the raw results of Gitleaks scan and extract the data to
    process is
    :param output_path: The path leads to the file with raw data
    :return: The extracted data
    """
    try:
        if not os.path.exists(output_path):
            raise FileNotFoundError

        with open(output_path, "r", encoding="utf-8") as file:
            data = file.read()
            gitleaks_data = json.loads(data)
        return gitleaks_data

    except Exception:
        error_occurred("Something is wrong with extracting the data", 1)


def transform_output_to_json(gitleaks_data: List[Dict]) -> str:
    """
    Transform Gitleaks raw output into a structured JSON format.
.
    :return: JSON data in the required format.
    """
    findings = []

    # Validate and process each finding
    for item in gitleaks_data:
        try:
            result = Leak(**item)  # Validate and parse each dictionary
            formatted_finding = {
                "filename": result.File[5:],
                "line_range": f"{result.StartLine}-{result.EndLine}",
                "description": result.Description
            }
            findings.append(formatted_finding)
        except ValidationError:
            error_occurred("Invalid format", 1)

    # Return the structured JSON format
    return json.dumps({"findings": findings}, indent=2)


def main():
    """
    Main function to handle arguments, run Gitleaks, and print the formatted
    output, and the run status of the Gitleaks run:
    the program print runcode=0 if the Gitleaks run without any problems, and
    print runcode=1 if there were findings but something got the scanning
    fail through it
    """
    command_args = sys.argv[1:]
    if len(command_args) > 0 and "gitleaks" in command_args[0]:
        command_args[0] = "/app/gitleaks"

    mount_path = '/code/'

    check_mount(mount_path)

    runcode = run_gitleaks(command_args)

    output_path = "./code/output.json"
    gitleaks_data = extract_data(output_path)
    formatted_json = transform_output_to_json(gitleaks_data)

    print("Gitleaks finished it's scan in mode:", runcode)
    print(formatted_json)


if __name__ == "__main__":
    main()
