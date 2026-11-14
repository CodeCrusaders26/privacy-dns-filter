# Dataset Documentation

## Project
Privacy-Preserving Malicious Domain Detection Using Federated Learning

## Dataset Overview

The processed dataset contains 19,950 domain records and 14 columns.

## Data Sources
- Tranco: Legitimate domain data
- URLhaus: Malicious URL/domain data
- PhishTank: Phishing URL/domain data

## Dataset Statistics

| Property | Value |
|---|---:|
| Total records | 19,950 |
| Total columns | 14 |
| Legitimate domains (0) | 9,950 |
| Malicious domains (1) | 10,000 |
| Missing values | 0 |
| Duplicate domains | 0 |

## Features

The dataset includes domain-based features such as:
- Domain length
- Dots and hyphens
- Digits
- Special characters
- Subdomains
- Vowel and consonant counts
- Unique characters
- Entropy

## Target Variable

`label`

- 0 = Legitimate
- 1 = Malicious

## Files

- `raw/combined_domains.csv`: Combined source dataset.
- `processed/processed_domains.csv`: Processed dataset.
- `../notebooks/preprocessing.ipynb`: Preprocessing workflow.

## Notes

The `special_chars` feature is constant in the current dataset and should be reviewed before model training.
