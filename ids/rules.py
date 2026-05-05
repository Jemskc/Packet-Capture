def parse_options(options_str):
    """Parse the (...) options block of a Snort rule into a list of {key: value} dicts."""
    inner = options_str[options_str.index('(') + 1:options_str.rindex(')')]
    parsed_options = []
    for part in inner.split(';'):
        if ':' in part:
            k, v = part.strip().split(':', 1)
            parsed_options.append({k.strip(): v.strip()})

    available_options = {k: True for opt in parsed_options for k in opt}
    return parsed_options, available_options


def parse_snort_rules(filename):
    """Load and parse all rules from a Snort rules file.

    Returns a list of rule dicts with keys:
        Alert, Protocol, Source Address, Source Port, Direction,
        Destination Address, Destination Port, Options,
        Available Options, Available Option Values
    """
    parsed_rules = []

    with open(filename, 'r') as f:
        lines = f.read().splitlines()

    for line in lines:
        parts = line.strip().split()
        if len(parts) < 7:
            continue

        rule = {
            'Alert':               parts[0],
            'Protocol':            parts[1],
            'Source Address':      parts[2],
            'Source Port':         parts[3],
            'Direction':           parts[4],
            'Destination Address': parts[5],
            'Destination Port':    parts[6],
            'Options':             [],
        }

        available_options = {}
        if len(parts) > 7:
            options_str = ' '.join(parts[7:])
            rule['Options'], available_options = parse_options(options_str)

        rule['Available Options'] = list(available_options.keys())

        rule['Available Option Values'] = {}
        for opt in rule['Options']:
            for key, val in opt.items():
                if key in available_options:
                    rule['Available Option Values'][key] = (
                        rule['Available Option Values'].get(key, '') + val
                    )

        parsed_rules.append(rule)

    return parsed_rules
