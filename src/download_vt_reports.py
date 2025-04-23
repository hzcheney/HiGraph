import os
import requests
import json
import logging
import argparse
from pathlib import Path
from dotenv import load_dotenv 

# --- Determine Project Root (assuming script is in src/) ---
# This allows running from project root (malware-dataset-x)
# Or potentially directly (though running from root is recommended)
try:
    # Assumes structure: malware-dataset-x/src/script.py
    PROJECT_ROOT = Path(__file__).parent.parent.resolve()
except NameError:
     # Fallback if __file__ is not defined (e.g., interactive session)
     PROJECT_ROOT = Path('.').resolve()

# --- Load .env file from Project Root ---
# Looks for .env in PROJECT_ROOT and loads environment variables from it
load_dotenv(dotenv_path=PROJECT_ROOT / '.env')


# --- Configuration ---
VT_API_URL_TEMPLATE = "https://www.virustotal.com/api/v3/files/{hash}"
# Input path remains absolute
INPUT_BASE_DIR = Path("/projects/hchen5_proj/data/Androzoo/Malware_4")
# Output/Log paths relative to project root
OUTPUT_BASE_DIR = PROJECT_ROOT / "vt_reports" / "malware"
LOG_FILE_PATH = PROJECT_ROOT / "download_vt_reports.log"
YEARS_DEFAULT_START = 2014
YEARS_DEFAULT_END = 2022

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE_PATH), # Use project root path
        logging.StreamHandler()
    ]
)

def get_api_key():
    """Retrieves the VirusTotal API key from environment variables."""
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        logging.error("Error: VT_API_KEY environment variable not set.")
        logging.error("Please set the environment variable and try again.")
        logging.error("Example: export VT_API_KEY='your_actual_api_key'")
        exit(1)
    logging.info("Successfully retrieved VT_API_KEY.")
    return api_key

def fetch_vt_report(file_hash, api_key):
    """Fetches the report for a given hash from VirusTotal."""
    headers = {'x-apikey': api_key}
    url = VT_API_URL_TEMPLATE.format(hash=file_hash)
    logging.debug(f"Requesting URL: {url}")

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        logging.debug(f"Received successful response for hash: {file_hash}")
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            logging.warning(f"Hash not found on VirusTotal: {file_hash} (Status: 404)")
        elif response.status_code == 401:
             logging.error(f"Authentication error for hash {file_hash}. Check your API key. (Status: 401)")
        elif response.status_code == 429:
            # Now more likely without delay - might need better handling (e.g., backoff)
            logging.warning(f"Rate limit likely exceeded for hash {file_hash}. (Status: 429)")
        else:
            logging.error(f"HTTP error occurred for hash {file_hash}: {http_err} (Status: {response.status_code})")
        return None
    except requests.exceptions.ConnectionError as conn_err:
        logging.error(f"Connection error occurred for hash {file_hash}: {conn_err}")
        return None
    except requests.exceptions.Timeout as timeout_err:
        logging.error(f"Request timed out for hash {file_hash}: {timeout_err}")
        return None
    except requests.exceptions.RequestException as req_err:
        logging.error(f"An unexpected error occurred during request for hash {file_hash}: {req_err}")
        return None
    except json.JSONDecodeError as json_err:
        logging.error(f"Failed to decode JSON response for hash {file_hash}: {json_err}")
        return None

def save_report(report_data, output_path):
    """Saves the report data as JSON to the specified path."""
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=4)
        logging.debug(f"Successfully saved report to: {output_path}")
    except IOError as io_err:
        logging.error(f"Failed to write report to {output_path}: {io_err}")
    except Exception as e:
         logging.error(f"An unexpected error occurred saving report to {output_path}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Download VirusTotal reports for APK hashes.")
    parser.add_argument(
        "--start-year", type=int, default=YEARS_DEFAULT_START,
        help=f"First year to process (inclusive). Default: {YEARS_DEFAULT_START}"
    )
    parser.add_argument(
        "--end-year", type=int, default=YEARS_DEFAULT_END,
        help=f"Last year to process (inclusive). Default: {YEARS_DEFAULT_END}"
    )
    parser.add_argument(
        "--force-redownload", action="store_true",
        help="Force download even if a report file already exists."
    )
    parser.add_argument(
        "--input-dir", type=str, default=str(INPUT_BASE_DIR),
        help=f"Base directory containing year folders with APKs. Default: {INPUT_BASE_DIR}"
    )
    parser.add_argument(
        "--output-dir", type=str, default=str(OUTPUT_BASE_DIR),
        help=f"Base directory to save JSON reports. Default: {OUTPUT_BASE_DIR}"
    )
    args = parser.parse_args()

    input_base = Path(args.input_dir)
    output_base = Path(args.output_dir)

    logging.info("--- VirusTotal Report Downloader Started ---")
    logging.info(f"Processing years: {args.start_year} to {args.end_year}")
    logging.info(f"Input directory base: {input_base}")
    logging.info(f"Output directory base: {output_base}")
    logging.info(f"Force redownload: {args.force_redownload}")
    logging.info(f"Logging to: {LOG_FILE_PATH}")


    api_key = get_api_key()
    total_processed = 0
    total_downloaded = 0
    total_skipped = 0
    total_errors = 0

    for year in range(args.start_year, args.end_year + 1):
        year_str = str(year)
        input_year_dir = input_base / year_str
        output_year_dir = output_base / year_str # Output dir structured by year

        logging.info(f"Processing year: {year_str}...")

        if not input_year_dir.is_dir():
            logging.warning(f"Input directory not found, skipping year: {input_year_dir}")
            continue

        try:
            apk_files = list(input_year_dir.glob('*.apk'))
            if not apk_files:
                logging.info(f"No .apk files found in {input_year_dir}. Skipping year.")
                continue

            logging.info(f"Found {len(apk_files)} .apk files in {input_year_dir}.")

            for i, apk_path in enumerate(apk_files):
                file_hash = apk_path.stem
                output_path = output_year_dir / f"{file_hash}.json"
                total_processed += 1

                logging.debug(f"Processing file {i+1}/{len(apk_files)}: {apk_path.name} (Hash: {file_hash})")

                if not args.force_redownload and output_path.exists():
                    logging.info(f"Report already exists, skipping: {output_path}")
                    total_skipped += 1
                    continue

                logging.info(f"Fetching report for hash: {file_hash}...")
                report = fetch_vt_report(file_hash, api_key)

                if report:
                    save_report(report, output_path)
                    logging.info(f"Successfully downloaded and saved report for: {file_hash}")
                    total_downloaded += 1
                else:
                    logging.warning(f"Could not get or save report for hash: {file_hash}")
                    total_errors += 1


        except Exception as e:
            logging.error(f"An unexpected error occurred while processing year {year_str}: {e}", exc_info=True)
            total_errors += 1

    logging.info("--- VirusTotal Report Downloader Finished ---")
    logging.info(f"Summary: Total Files Processed: {total_processed}")
    logging.info(f"         Reports Downloaded: {total_downloaded}")
    logging.info(f"         Reports Skipped (existing): {total_skipped}")
    logging.info(f"         Errors/Not Found: {total_errors}")
    logging.info(f"Logs saved to: {LOG_FILE_PATH}")
    logging.info(f"Reports saved under: {output_base}")


if __name__ == "__main__":
    main() 