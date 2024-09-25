import math
from datasets import load_dataset
from collections import Counter
import random
import sys


def load_dataset_with_column_renaming(dataset_name):
    """
    Load the dataset from the Hugging Face Hub and rename columns if necessary.
    """
    ds = load_dataset(dataset_name)
    rename_columns(ds, dataset_name)
    return ds


def rename_columns(ds, dataset_name):
    """
    Rename columns in the dataset based on the dataset name.
    """
    if dataset_name == "nimaster/primevul_dataset":
        rename_column(ds, "func", "code")
    elif dataset_name == "realvul/RealVul":
        rename_column(ds, "CWE", "cwe")
        rename_column(ds, "CVE", "cve")


def rename_column(ds, old_column_name, new_column_name):
    """
    Rename a column in the dataset.
    """
    for split in ds.keys():
        if old_column_name in ds[split].column_names:
            ds[split] = ds[split].rename_column(old_column_name, new_column_name)
        else:
            sys.exit(f"Error: '{old_column_name}' column not found in {dataset_name} dataset.")


# Dataset Overview


def print_dataset_info(ds):
    """
    Print the dataset info including column names and sample sizes with percentages.
    """
    print("\n### Column Names:")
    print("```")
    print(next(iter(ds.values())).column_names)
    print("```")
    print("\n### Sample Sizes:")
    total_samples = sum(len(dataset) for dataset in ds.values())
    for split, dataset in ds.items():
        sample_count = len(dataset)
        percentage = (sample_count / total_samples) * 100
        print(f"{split}: Number of samples: {sample_count} ({percentage:.2f}%)")


def print_code_size_distribution(ds, target=""):
    """
    Print the size distribution of samples in terms of the 'code' column for each split and all splits combined, filtered by the specified 'target'.
    """
    print(f"\n## Code Size Distribution (LOC) for Vulnerability Target: {target}")
    all_code_sizes = []
    for split, dataset in ds.items():
        filtered_dataset = (
            dataset
            if target == "both"
            else [sample for sample in dataset if sample["target"] == int(target)]
        )
        code_sizes = [
            sample["code"].count("\n") + 1 for sample in filtered_dataset
        ]  # Count the number of lines in each code snippet
        all_code_sizes.extend(code_sizes)
        if code_sizes:  # Check if there are any code sizes to print
            print(f"\n### {split}:")
            mean = sum(code_sizes) / len(code_sizes)
            print(f"Min: {min(code_sizes)}, Max: {max(code_sizes)}, Mean: {mean}")
            std_dev = math.sqrt(
                sum((x - mean) ** 2 for x in code_sizes) / len(code_sizes)
            )
            print(f"Standard Deviation: {std_dev}")

    if all_code_sizes:  # Check if there are any code sizes to print
        print("\n### All Splits:")
        mean = sum(all_code_sizes) / len(all_code_sizes)
        print(f"Min: {min(all_code_sizes)}, Max: {max(all_code_sizes)}, Mean: {mean}")
        std_dev = math.sqrt(
            sum((x - mean) ** 2 for x in all_code_sizes) / len(all_code_sizes)
        )
        print(f"Standard Deviation: {std_dev}")
    else:
        print("No code sizes to report for the specified target.")

# Sample Analysis
def print_sample_with_target(ds, target):
    print(f"## Sample row with vulnerability target: {target}")
    target = int(target)
    samples = [sample for split in ds.values() for sample in split if sample["target"] == target]
    if samples:
        sample = random.choice(samples)
        print(f"### Sample from {random.choice(list(ds.keys()))}")
        print_sample(sample)
    else:
        print("No samples found with the specified target.")

def print_sample(sample):
    for key, value in sample.items():
        print(f"{key}: {value}")


# Vulnerability Analysis


def print_vulnerability_distribution(ds):
    """
    Print the distribution of vulnerabilities in the dataset.
    """
    print("\n## Vulnerability Distribution:")
    for split, dataset in ds.items():
        vulnerability_count = sum(1 for sample in dataset if sample["target"] == 1)
        total_samples = len(dataset)
        percentage = (vulnerability_count / total_samples) * 100
        print(f"- **{split}**: {vulnerability_count} samples ({percentage:.2f}%)")


# CWE Analysis

def get_cwe_info(ds):
    """
    Extract CWE information from the dataset.
    """
    cwe_set = set()
    cwe_balance = {}
    cwe_severity_count = {}
    for split, dataset in ds.items():
        cwe_set.update(sample["cwe"] for sample in dataset if sample["cwe"])
        cwe_balance[split] = Counter(
            sample["cwe"] for sample in dataset if sample["cwe"]
        )
        if "severity" in dataset[0].keys():
            cwe_severity_count[split] = {}
            for sample in dataset:
                if sample["cwe"] not in cwe_severity_count[split]:
                    cwe_severity_count[split][sample["cwe"]] = Counter()
                cwe_severity_count[split][sample["cwe"]][sample["severity"]] += 1
    return cwe_set, cwe_balance, cwe_severity_count


def print_cwe_summary(cwe_set, cwe_balance, cwe_severity_count, ds):
    """
    Print a summary of CWE information.
    """
    print("\n## Count of Unique CWEs:")
    print(f"- Total unique CWEs: {len(cwe_set)}")
    for cwe in cwe_set:
        print(f"\n###{cwe}:")
        for split in cwe_balance.keys():
            print(f"  - {split}: {cwe_balance[split][cwe]}")
        if "severity" in next(iter(ds.values())).column_names:
            for split in cwe_severity_count.keys():
                if cwe in cwe_severity_count[split]:
                    print(f"  - Severity Counts:")
                    for severity, count in cwe_severity_count[split][cwe].items():
                        print(f"    - {severity}: {count}")


def print_count_unique_cwe(ds):
    """
    Print the count of unique CWEs in the dataset, including how many occur in each split.
    Additionally, specify which split the count is from and include a line with severity if available.
    """
    cwe_set, cwe_balance, cwe_severity_count = get_cwe_info(ds)
    print_cwe_summary(cwe_set, cwe_balance, cwe_severity_count, ds)
    return cwe_set, cwe_balance, cwe_severity_count


def print_cwes_by_severity(ds):
    if "severity" not in next(iter(ds.values())).column_names:
        return
    cwe_severity = {}
    for split in ds.keys():
        for sample in ds[split]:
            cwe = sample["cwe"]
            severity = sample["severity"]
            if severity not in cwe_severity:
                cwe_severity[severity] = set()
            cwe_severity[severity].add(cwe)
    print("## CWEs by Severity:")
    for severity, cwes in cwe_severity.items():
        print(f"### {severity}:")
        print("```")
        print("\n".join(sorted([str(cwe) for cwe in cwes])))
        print("```")
