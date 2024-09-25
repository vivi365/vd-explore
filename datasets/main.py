import sys
from utils import (
    load_dataset_with_column_renaming,
    print_dataset_info,
    print_code_size_distribution,
    print_sample_with_target,
    print_vulnerability_distribution,
    print_count_unique_cwe,
    print_cwes_by_severity,
)


datasets = {
    "primevul": "nimaster/primevul_dataset",
    "realvul": "realvul/RealVul",
}


def main(dataset_name):
    ds = load_dataset_with_column_renaming(dataset_name)
    print(f"\n##{dataset_name} Dataset Info")
    print_dataset_info(ds)
    print_code_size_distribution(ds, target="both")
    print_code_size_distribution(ds, "0")
    print_code_size_distribution(ds, "1")

    print_sample_with_target(ds, "0")
    print_sample_with_target(ds, "1")

    print_vulnerability_distribution(ds)
    cwe_set, cwe_balance, cwe_severity_count = print_count_unique_cwe(ds)
    print_cwes_by_severity(ds)


if __name__ == "__main__":
    dataset_name = sys.argv[1]
    if dataset_name not in datasets:
        print(f"Dataset {dataset_name} not found")
        sys.exit(1)
    main(datasets[dataset_name])
