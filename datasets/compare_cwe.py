import sys

def read_cwe_file(filename):
    """Reads a file and returns a set of CWEs (one CWE per line)."""
    with open(filename, "r") as f:
        return set(
            line.strip() for line in f if line.strip()
        )  # Strips lines and removes empty ones


def compare_cwe_files(file1, file2):
    """Compares two CWE files and prints overlap and differences."""
    cwe_set1 = read_cwe_file(file1)
    cwe_set2 = read_cwe_file(file2)

    # Find overlap (common CWEs) and differences
    common_cwes = cwe_set1.intersection(cwe_set2)
    only_in_file1 = cwe_set1.difference(cwe_set2)
    only_in_file2 = cwe_set2.difference(cwe_set1)

    # Print results
    print(f"Common CWEs ({len(common_cwes)}):")
    print("\n".join(sorted(common_cwes)))
    print(f"\nCWEs only in {file1} ({len(only_in_file1)}):")
    print("\n".join(sorted(only_in_file1)))
    print(f"\nCWEs only in {file2} ({len(only_in_file2)}):")
    print("\n".join(sorted(only_in_file2)))


# Usage example:
if __name__ == "__main__":
    file1 = sys.argv[1]
    file2 = sys.argv[2]
    compare_cwe_files(file1, file2)
