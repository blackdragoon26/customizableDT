custom_rules = [
    lambda row: row[0] + row[1] + row[2] > 10,  # sum > 10
    lambda row: row[2] > 4,                      # feature2 > 4
    lambda row: row[0] < row[1]                  # feature0 < feature1
]

decision_tree = {
    'rule_index': 0,
    'left': {  # if rule0 == False
        'rule_index': 1,
        'left': 'benign',   # if rule1 == False
        'right': 'malicious' # if rule1 == True
    },
    'right': {  # if rule0 == True
        'rule_index': 2,
        'left': 'malicious',    # if rule1 == False
        'right': 'benign'  # if rule1 == True
    }
}

def classify(row, node=decision_tree):
    if isinstance(node, str):  # reached leaf node (class label)
        return node
    rule_fn = custom_rules[node['rule_index']]
    if rule_fn(row):
        return classify(row, node['right'])
    else:
        return classify(row, node['left'])

# Test packets
packets = [
    [3, 3, 3],  
    [5, 5, 5],  
    [2, 3, 1],  
]

for p in packets:
    print(f"Packet {p} classified as: {classify(p)}")
