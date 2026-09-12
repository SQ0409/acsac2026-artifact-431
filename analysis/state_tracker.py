import re
import json

dot_file = "AMF.dot"
json_output = "amf_transitions_clean.json"

with open(dot_file, "r", encoding="utf-8") as f:
    dot_content = f.read()

# 匹配格式：from -> to [label = "condition / output, assign1, assign2, ..."]
edge_pattern = re.compile(r'(\w+)\s*->\s*(\w+)\s*\[label\s*=\s*"([^"]+)"\]', re.DOTALL)
edges = edge_pattern.findall(dot_content)

def clean_text(text):
    # 去掉换行符，首尾空白，内部多余空白压缩成一个空格
    return " ".join(text.replace("\n", " ").split())

def parse_label(label):
    parts = label.split("/", 1)
    condition = clean_text(parts[0]) if len(parts) > 0 else ""
    rest = clean_text(parts[1]) if len(parts) > 1 else ""

    if "," in rest:
        output, *assignments = [x.strip() for x in rest.split(",")]
    else:
        output = rest.strip()
        assignments = []

    return condition, output, assignments

transitions = []
for from_state, to_state, label in edges:
    condition, output, assignments = parse_label(label)
    transitions.append({
        "from": from_state,
        "to": to_state,
        "condition": condition,
        "output": output,
        "assignments": assignments
    })

with open(json_output, "w", encoding="utf-8") as f:
    json.dump(transitions, f, indent=2, ensure_ascii=False)

print(f"✅ 状态转移信息已写入文件：{json_output}")

