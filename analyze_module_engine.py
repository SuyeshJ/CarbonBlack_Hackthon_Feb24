import json
import sys
from tabulate import tabulate
import textwrap


def load_rules(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []


def is_match(dynamic_rule, static_rule, rule_type):
    if rule_type in ['Custom', 'Memory', 'Registry']:
        dynamic_process_pattern = dynamic_rule.get('processPattern', '').lower()
        static_process_pattern = static_rule.get('processPattern', '').lower()
        dynamic_path_pattern = dynamic_rule.get('pathPattern', '').lower()
        static_path_pattern = static_rule.get('pathPattern', [])

        if dynamic_process_pattern != ("*" or None) and dynamic_path_pattern != ("*" or None) and static_process_pattern and static_path_pattern:
            if static_process_pattern in dynamic_process_pattern or dynamic_process_pattern in static_process_pattern:
                if static_path_pattern in dynamic_path_pattern or dynamic_path_pattern in static_path_pattern:
                    return True, static_process_pattern, static_path_pattern
        elif dynamic_process_pattern != ("*" or None) and static_process_pattern:
            if static_process_pattern in dynamic_process_pattern or dynamic_process_pattern in static_process_pattern:
                return True, static_process_pattern, None
        elif dynamic_path_pattern != ("*" or None) and static_path_pattern:
            if static_path_pattern in dynamic_path_pattern or dynamic_path_pattern in static_path_pattern:
                return True, None, static_path_pattern

    elif rule_type == 'File':
        dynamic_file_name = dynamic_rule.get('fileName', '').lower()
        static_file_name = static_rule.get('fileName', '').lower()
        dynamic_file_hash = dynamic_rule.get('hash', '').lower()
        static_file_hash = static_rule.get('hash', '').lower()
        if dynamic_file_name == static_file_name or dynamic_file_hash == static_file_hash:
            return True, None, None

    elif rule_type == 'Publisher':
        dynamic_publisher_name = dynamic_rule.get('name', '').lower()
        static_publisher_name = static_rule.get('name', '').lower()
        if static_publisher_name in dynamic_publisher_name or dynamic_publisher_name in static_publisher_name:
            return True, None, None

    elif rule_type == 'agentConfig':
        dynamic_config_name = dynamic_rule.get('name', '').lower()
        static_config_name = static_rule.get('name', '').lower()
        if dynamic_config_name == static_config_name:
            return True, None, None

    return False, None, None


def is_conflict(dynamic_rule, static_rule, rule_type):
    if rule_type in ['Custom', 'Memory', 'Registry']:
        dynamic_action_mask = dynamic_rule.get('execActionMask')
        static_action_mask = static_rule.get('execActionMask')
        dynamic_action = dynamic_rule.get('ruleAction', '')
        static_action = static_rule.get('ruleAction', '')

        if static_action_mask and static_action:
            if dynamic_action_mask != static_action_mask and dynamic_action != static_action:
                recommendation = f'It is recommended for this rule to have {static_action_mask} as execActionMask and {static_action} as ruleAction'
                return True, recommendation
            elif dynamic_action_mask != static_action_mask:
                recommendation = f'ruleAction is correct but execActionMask is recmmended to be {static_action_mask}'
                return True, recommendation
            elif dynamic_action != static_action:
                recommendation = f'execActionMask is correct but ruleAction is recmmended to be {static_action}'
                return True, recommendation
        elif static_action_mask and dynamic_action_mask != static_action_mask:
            recommendation = f'It is recommended for execActionMask to be {static_action_mask}'
            return True, recommendation
        elif static_action and dynamic_action != static_action:
            recommendation = f'It is recommended for ruleAction to be {static_action}'
            return True, recommendation

    elif rule_type == 'File':
        recommendation = static_rule.get('recommendation', '')
        if dynamic_rule.get('fileState') != static_rule.get('fileState'):
            if dynamic_rule.get('fileState') == 3 and static_rule.get('fileState') == 2:
                recommendation = 'It is recommended not to ban this file'
            elif dynamic_rule.get('fileState') == 2 and static_rule.get('fileState') == 3:
                recommendation = 'It is recommended not to approve this file'
            return True, recommendation

    elif rule_type == 'Publisher':
        recommendation = static_rule.get('recommendation', '')
        if dynamic_rule.get('publisherState') == static_rule.get('publisherState'):
            recommendation = static_rule.get('recommendation')
            return True, recommendation

    elif rule_type == 'agentConfig':
        process_name = dynamic_rule.get('value')
        recommendation = f'It is not recommend to exclude {process_name} from tracking'
        return True, recommendation
    return False, None


def analyze_rules(dynamic_rules, static_rules, rule_type):
    report = []
    for dynamic_rule in dynamic_rules:
        rule_id = dynamic_rule.get('id', 'Unknown')
        # checking if we have more than 1 pathPattern in the rule then we are recommending to narrow down the rule to improve performance
        if rule_type == ("Custom" or "Memory" or "Registry") and dynamic_rule.get('pathPattern') != ("*" or None):
            dynamic_custom_path_pattern = dynamic_rule.get('pathPattern').split("|")
            if len(dynamic_custom_path_pattern) > 5:
                recommendation = "It is recommended to narrow down the pathPattern for better performance"
                report_entry = {
                    'id': rule_id,
                    'rule_name': dynamic_rule.get('name', 'Unknown'),
                    'rule_type': rule_type,
                    'Impact': 'Low',
                    'recommendation': recommendation,
                    'severity': 'Info',
                    'processPattern': '',
                    'pathPattern': dynamic_rule.get('pathPattern'),
                    'file': ''
                }
                report.append(report_entry)
        else:
            for static_rule in static_rules:
                # See if the rule in dynamic rules dataset has an entry in static rule dataset
                match, process_pattern, path_pattern = is_match(dynamic_rule, static_rule, rule_type)
                if match:
                    # Check if the found rule is having behaviour as recommended
                    conflict_found, recommendation = is_conflict(dynamic_rule, static_rule, rule_type)

                    # Append the conflicting rule details to a report
                    if conflict_found:
                        report_entry = {
                            'id': rule_id,
                            'rule_name': dynamic_rule.get('name', 'Unknown'),
                            'rule_type': rule_type,
                            'Impact': static_rule.get('Impact', 'Unknown'),
                            'recommendation': recommendation,
                            'severity': static_rule.get('Severity', 'Unknown')
                        }
                        if rule_type in ['Custom', 'Memory', 'Registry']:
                            report_entry['processPattern'] = process_pattern
                            report_entry['pathPattern'] = path_pattern
                        else:
                            report_entry['processPattern'] = ''
                            report_entry['pathPattern'] = ''
                        if rule_type == 'File':
                            if static_rule.get('fileName'):
                                report_entry['file'] = static_rule.get('fileName')
                            if static_rule.get('hash'):
                                report_entry['file'] = static_rule.get('hash')
                        else:
                            report_entry['file'] = ''

                        report.append(report_entry)

    return report


def wrap_text(text, width):
    """
    Wraps text to the specified width.
    :param text: The text to wrap.
    :param width: The maximum width of the text.
    :return: A wrapped text.
    """
    return '\n'.join(textwrap.wrap(text, width=width))


def wrap_table_data(table_data, max_width):
    """
    Wraps the elements of a table's data to ensure that no cell exceeds the maximum width.
    :param table_data: The table data, a list of dictionaries.
    :param max_width: The maximum width for any cell.
    :return: The wrapped table data.
    """
    wrapped_data = []
    for row in table_data:
        wrapped_row = {key: wrap_text(str(value), max_width) for key, value in row.items()}
        wrapped_data.append(wrapped_row)
    return wrapped_data


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <rule_type>")
        print("Available rule types: Custom, File, Publisher, Memory, Registry")
        sys.exit(1)

    rule_type = sys.argv[1]
    if rule_type not in ['Custom', 'File', 'Publisher', 'Memory', 'Registry', 'agentConfig']:
        print("Invalid rule type. Please choose from Custom, File, Publisher, Memory, Registry.")
        sys.exit(1)

    dynamic_rules = load_rules(f'dynamic_{rule_type.lower()}_rules.json')
    static_rules = load_rules(f'static_{rule_type.lower()}_rules.json')

    report = analyze_rules(dynamic_rules, static_rules, rule_type)

    # Wrap data
    max_width = 40  # Set your desired max width
    wrapped_data = wrap_table_data(report, max_width)

    # Print table
    print(tabulate(wrapped_data, headers="keys", tablefmt="grid"))
    # Print report in tabular format on stdout
    #headers = report[0].keys()
    #rows = [x.values() for x in report]
    # Print the table
    #print(tabulate(rows, headers=headers, tablefmt="grid"))

    # Write the report to a file in json format
    report_file = f'rule_analysis_report_{rule_type}.json'
    with open(report_file, 'w') as file:
        json.dump(report, file, indent=4)

    print(f"Analysis complete for {rule_type} rules. Report saved to '{report_file}'.")
