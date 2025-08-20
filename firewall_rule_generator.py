import random
import pandas as pd

class FirewallRuleRequest:
    def __init__(
        self, source_address, destination_address, services, comments,
        action, rule_type, source_nat=None, destination_nat=None,
        port_translation=None, traffic_direction=None
    ):
        self.source_address = source_address
        self.destination_address = destination_address
        self.services = services
        self.comments = comments
        self.action = action
        self.rule_type = rule_type
        self.source_nat = source_nat
        self.destination_nat = destination_nat
        self.port_translation = port_translation
        self.traffic_direction = traffic_direction

def get_source_address():
    choice = input("Do you want to enter source addresses manually (m) or generate randomly (r)? ")
    if choice.lower() == 'm':
        value = input("Enter source address(es) (comma separated): ")
    else:
        value = random_address()
    return value

def get_destination_address():
    choice = input("Do you want to enter destination addresses manually (m) or generate randomly (r)? ")
    if choice.lower() == 'm':
        value = input("Enter destination address(es) (comma separated): ")
    else:
        value = random_destination_address()
    return value

def get_services():
    choice = input("Do you want to enter services manually (m) or generate randomly (r)? ")
    if choice.lower() == 'm':
        value = input("Enter services (e.g., TCP_80, UDP_53, ICMP, comma separated): ")
    else:
        protocols = ["TCP", "UDP", "ICMP"]
        ports = [80, 443, 53, 22, 8080]
        proto = random.choice(protocols)
        if proto in ["TCP", "UDP"]:
            value = f"{proto}_{random.choice(ports)}"
        else:
            value = "ICMP"
    return value

comments_list = [
    "Temporary rule for testing - expires 09/30/2025!",
    "Production access required for app deployment #42.",
    "Allow monitoring traffic from 10.0.0.0/24; requested by NetOps.",
    "Rule requested by automation script v2.1 @ 2025-08-18.",
    "Legacy system support: enable TCP_8080 for host group 'finance-servers'.",
    "Urgent: ICMP allowed for diagnostics (ticket #12345).",
    "Access for vendor system: src=192.168.1.10, dst=10.10.10.10, svc=TCP_443.",
    "Scheduled maintenance window: 08/20/2025 01:00-03:00 UTC.",
    "Temporary exception for QA team - remove by 10/01/2025.",
    "Enable UDP_53 for DNS sync; see change request CR-2025-001.",
    "Firewall rule for backup job: run nightly @ 02:00 AM.",
    "Special access: allow TCP_22 for jump host (admin only!).",
    "Rule for app migration: source=app01, dest=db01, ports=TCP_3306, UDP_161.",
    "Compliance audit: allow traffic for PCI segment (ref: PCI-2025-09).",
    "Test rule - do not use in production! #test #dev",
    "Temporary rule for partner integration: expires 2025-09-01.",
    "Allow SNMP (UDP_161) for monitoring tools; requested by ops@company.com.",
    "Rule for scheduled data sync: 08/25/2025, 04:00-06:00 UTC.",
    "Enable HTTP/HTTPS (TCP_80, TCP_443) for web servers.",
    "Exception for legacy app: src=172.16.0.5, dst=172.16.1.10, svc=TCP_1521.",
]

def generate_rule_request(choices, source_address, destination_address, services):
    # Action
    actions = ["permit", "deny"]
    action = choices['action_value'] if choices['action_mode'] == 'm' else random.choice(actions)
    # Rule Type
    rule_types = [
        "Production",
        "Pre-Prod UAT/SIT/LAB",
        "BCP/DR",
        "Management"
    ]
    rule_type = choices['rule_type_value'] if choices['rule_type_mode'] == 'm' else random.choice(rule_types)
    # Comments
    comments = choices['comments_value'] if choices['comments_mode'] == 'm' else random.choice(comments_list)
    # NAT fields
    source_nat = destination_nat = port_translation = traffic_direction = None
    if choices.get('nat_include'):
        include_nat = True if choices['nat_scope'] == 'a' else random.choice([True, False])
        if include_nat:
            nat_fields = ['source_nat', 'destination_nat', 'port_translation']
            # Randomly select how many NAT fields to include (1-3)
            num_fields = random.randint(1, 3)
            selected_fields = random.sample(nat_fields, num_fields)
            random.shuffle(selected_fields)  # Randomize order

            nat_values = {}
            # Generate NAT values that do not match original values
            def random_ip(exclude):
                while True:
                    ip = f"172.16.{random.randint(0,255)}.{random.randint(1,254)}"
                    if ip != exclude:
                        return ip
            def random_service(exclude):
                protocols = ["TCP", "UDP"]
                ports = [1000, 2000, 3000, 4000, 5000]
                while True:
                    proto = random.choice(protocols)
                    svc = f"{proto}_{random.choice(ports)}"
                    if svc != exclude:
                        return svc
            for field in selected_fields:
                if field == 'source_nat':
                    nat_values['source_nat'] = random_ip(source_address)
                elif field == 'destination_nat':
                    nat_values['destination_nat'] = random_ip(destination_address)
                elif field == 'port_translation':
                    nat_values['port_translation'] = random_service(services)
            # Always include traffic_direction if any NAT field is present
            traffic_direction = random.choice(["IN", "OUT"])
            source_nat = nat_values.get('source_nat')
            destination_nat = nat_values.get('destination_nat')
            port_translation = nat_values.get('port_translation')

    rule = FirewallRuleRequest(
        source_address=source_address,
        destination_address=destination_address,
        services=services,
        comments=comments,
        action=action,
        rule_type=rule_type,
        source_nat=source_nat,
        destination_nat=destination_nat,
        port_translation=port_translation,
        traffic_direction=traffic_direction
    )
    return rule

def generate_multiple_requests():
    num = int(input("How many firewall rule requests do you want to generate? "))
    choices = get_field_choices()
    rules = []
    for _ in range(num):
        # Generate source address
        if choices['source_mode'] == 'm':
            source_address = choices['source_value']
        else:
            source_address = random_address_list()

        # Generate destination address
        if choices['dest_mode'] == 'm':
            destination_address = choices['dest_value']
        else:
            destination_address = random_address_list()
        # Generate services
        if choices['services_mode'] == 'm':
            services = choices['services_value']
        else:
            services = random_services_list()
        # Pass all required arguments
        rule = generate_rule_request(choices, source_address, destination_address, services)
        print(vars(rule))
        rules.append(rule)
    return rules

def get_field_choices():
    choices = {}
    # NAT inclusion
    nat_include = input("Include Network Address Translation (NAT) fields? (y/n): ").lower()
    choices['nat_include'] = nat_include == 'y'
    if choices['nat_include']:
        nat_scope = input("Include NAT for all requests (a) or some requests (s)? ").lower()
        choices['nat_scope'] = nat_scope
    # Action field
    actions = ["permit", "deny"]
    choices['action_mode'] = input("Action: manual (m) or random (r)? ").lower()
    if choices['action_mode'] == 'm':
        choices['action_value'] = input(f"Enter action ({'/'.join(actions)}): ").lower()
        while choices['action_value'] not in actions:
            choices['action_value'] = input(f"Invalid. Enter one of {actions}: ").lower()
    # Rule Type field
    rule_types = [
        "Production",
        "Pre-Prod UAT/SIT/LAB",
        "BCP/DR",
        "Management"
    ]
    choices['rule_type_mode'] = input("Rule Type: manual (m) or random (r)? ").lower()
    if choices['rule_type_mode'] == 'm':
        print(f"Available Rule Types: {rule_types}")
        choices['rule_type_value'] = input("Enter Rule Type: ")
        while choices['rule_type_value'] not in rule_types:
            choices['rule_type_value'] = input(f"Invalid. Enter one of {rule_types}: ")
    # Source address
    choices['source_mode'] = input("Source addresses: manual (m) or random (r)? ").lower()
    if choices['source_mode'] == 'm':
        choices['source_value'] = input("Enter source address(es) (comma separated): ")
    # Destination address
    choices['dest_mode'] = input("Destination addresses: manual (m) or random (r)? ").lower()
    if choices['dest_mode'] == 'm':
        choices['dest_value'] = input("Enter destination address(es) (comma separated): ")
    # Services
    choices['services_mode'] = input("Services: manual (m) or random (r)? ").lower()
    if choices['services_mode'] == 'm':
        choices['services_value'] = input("Enter services (e.g., TCP_80, UDP_53, ICMP, comma separated): ")
    # Comments
    choices['comments_mode'] = input("Comments: manual (m) or random (r)? ").lower()
    if choices['comments_mode'] == 'm':
        choices['comments_value'] = input("Enter comments: ")
    return choices

def random_ip():
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def random_range():
    start = random.randint(1, 200)
    end = start + random.randint(1, 54)
    return f"192.168.1.{start}-192.168.1.{end}"

def random_cidr():
    return f"192.168.{random.randint(0,255)}.0/24"

def random_address_value():
    options = [
        random_ip,
        random_range,
        random_cidr
    ]
    return random.choice(options)()

def random_address_list():
    # 70% chance single value, 30% chance multiple values
    if random.random() < 0.7:
        return random_address_value()
    else:
        count = random.randint(2, 4)
        # Use sample to avoid duplicates
        address_types = [random_ip, random_range, random_cidr]
        values = []
        for _ in range(count):
            val = random.choice(address_types)()
            if val not in values:
                values.append(val)
        # 20% chance to use "any" as the only value
        if random.random() < 0.2:
            return "any"
        return ",".join(values)

def random_address():
    import random
    # 20% chance to use "any", otherwise generate an IP
    return "any" if random.random() < 0.2 else f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def random_destination_address():
    import random
    return "any" if random.random() < 0.2 else f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"

def random_service_value():
    protocols = ["TCP", "UDP"]
    # Highly prioritized TCP ports
    high_freq_tcp_ports = [23, 443, 3389, 8080, 53, 80]
    # Other common ports
    other_common_ports = [20, 21, 22, 25, 110, 139, 143, 445]
    well_known_ports = list(range(1, 1024))
    other_ports = [8443, 10000, 20000, 30000, 40000, 50000]

    r = random.random()
    if r < 0.7:  # Well-known ports
        if random.random() < 0.5:  # 50% chance for high frequency TCP ports
            port = random.choice(high_freq_tcp_ports)
            proto = "TCP"
        elif random.random() < 0.8:  # 40% chance for other common ports
            port = random.choice(other_common_ports)
            proto = random.choice(protocols)
        else:  # 10% chance for other well-known ports
            port = random.choice(well_known_ports)
            proto = random.choice(protocols)
    else:  # Other ports
        port = random.choice(other_ports)
        proto = random.choice(protocols)
    return f"{proto}_{port}"

def random_service_range():
    protocols = ["TCP", "UDP"]
    proto = random.choice(protocols)
    # Use well-known or other ports for range start
    r = random.random()
    if r < 0.7:
        if random.random() < 0.8:
            port_start = random.choice([20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445])
        else:
            port_start = random.randint(1, 1023)
        port_end = min(port_start + random.randint(1, 10), 1023)
    else:
        port_start = random.choice([8080, 8443, 10000, 20000, 30000, 40000, 50000])
        port_end = port_start + random.randint(1, 10)
    return f"{proto}_{port_start}-{port_end}"

def random_services_list():
    r = random.random()
    if r < 0.5:
        return random_service_value()
    elif r < 0.7:
        return random_service_range()
    else:
        count = random.randint(2, 4)
        values = set()
        while len(values) < count:
            if random.random() < 0.5:
                values.add(random_service_value())
            else:
                values.add(random_service_range())
        return ",".join(random.sample(list(values), len(values)))

def export_to_excel(rules, filename="firewall_rules.xlsx"):
    # List of dicts from FirewallRuleRequest objects
    data = [vars(rule) for rule in rules]
    # Match the column order and header titles from your screenshot
    columns = [
        "action",
        "rule_type",
        "source_address",
        "destination_address",
        "services",
        "source_nat",
        "destination_nat",
        "port_translation",
        "traffic_direction",
        "comments"
    ]
    headers = [
        "Rule Action",
        "Rule Type",
        "Source",
        "Destination",
        "Services",
        "Source Nat",
        "Destination Nat",
        "Port Translation",
        "Traffic Direction",
        "Comments"
    ]
    df = pd.DataFrame(data, columns=columns)
    df.columns = headers  # Set custom header row
    df.to_excel(filename, index=False)
    print(f"Exported {len(rules)} rules to {filename}")

if __name__ == "__main__":
    rules = generate_multiple_requests()
    export_to_excel(rules)