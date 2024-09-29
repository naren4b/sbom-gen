import json

def add_vulnerabilities_to_packages(grouped_packages_path, vulnerabilities_path, output_path):
    # Load grouped packages
    with open(grouped_packages_path, 'r') as f:
        grouped_packages = json.load(f)

    # Load vulnerabilities
    with open(vulnerabilities_path, 'r') as f:
        vulnerabilities_data = json.load(f)['matches']

    # Add vulnerabilities to packages
    for package in grouped_packages:
        package_name = package['packageName']
        package_version = package['packageVersion']
        relevant_vulnerabilities = [
            {
                "id": match['vulnerability']['id'],
                "dataResource": match['vulnerability'].get('dataSource', 'N/A'),
                "description": match['vulnerability'].get('description', 'No description available'),
                "fixVersion": ', '.join(match['vulnerability']['fix']['versions']) if match['vulnerability'].get('fix', None) else "No fix version available"
            }
            for match in vulnerabilities_data
            if match['artifact']['name'] == package_name and match['artifact']['version'] == package_version
        ]
        if not relevant_vulnerabilities:
            relevant_vulnerabilities = [{"id": "None", "dataResource": "N/A", "description": "No vulnerabilities found", "fixVersion": "N/A"}]
        package['vulnerabilities'] = relevant_vulnerabilities

    # Write the combined data to a new file
    with open(output_path, 'w') as f:
        json.dump(grouped_packages, f, indent=2)

if __name__ == "__main__":
    # Define file paths
    grouped_packages_path = '/path/to/grouped_packages_with_locations.json' # todo $IMAGE_NAME-$IMAGE_TAG-sbom.json
    vulnerabilities_path = '/path/to/vulnerabilities.json' #$IMAGE_NAME-$IMAGE_TAG-vulnerabilities.json
    output_path = '/path/to/final.json'  # todo $IMAGE_NAME-$IMAGE_TAG.json

    # Run the function
    add_vulnerabilities_to_packages(grouped_packages_path, vulnerabilities_path, output_path)
