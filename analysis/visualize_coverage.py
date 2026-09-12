import json
import re
import sys
import os
import graphviz
from graphviz import Digraph

def load_coverage_report(report_file):
    """加载覆盖报告"""
    with open(report_file) as f:
        return json.load(f)

def parse_dot_file(dot_file):
    """解析DOT文件"""
    with open(dot_file, 'r') as f:
        return f.read()

def normalize_string(s):
    """规范化字符串：去除换行符和多余空格"""
    # 替换换行符为空格
    s = s.replace('\n', ' ')
    # 压缩连续空格为单个空格
    s = re.sub(r'\s+', ' ', s)
    # 去除首尾空格
    return s.strip()

def generate_colored_dot(dot_content, coverage):
    """生成带有颜色标记的DOT文件"""
    # 获取转移详细信息
    if 'transitions' in coverage and 'transition_details' in coverage['transitions']:
        transition_details = coverage['transitions']['transition_details']
    else:
        print("⚠️ Warning: 'transition_details' not found in coverage report")
        transition_details = {}
    
    # 创建图对象
    dot = Digraph(comment='AMF State Machine')
    dot.attr(rankdir='LR')
    
    # 解析原始DOT文件中的节点和边
    node_pattern = re.compile(r'node\[.*label="([^"]+)"\]\s*(\w+)\s*;')
    edge_pattern = re.compile(r'(\w+)\s*->\s*(\w+)\s*\[label\s*=\s*"([^"]+)"\]')
    
    # 添加节点
    nodes = {}
    for match in node_pattern.finditer(dot_content):
        label, node_id = match.groups()
        nodes[node_id] = label
        dot.node(node_id, label)
    
    # 添加边并精确匹配每个转移规则
    for match in edge_pattern.finditer(dot_content):
        from_node, to_node, label = match.groups()
        
        # 规范化标签：去除换行符和多余空格
        normalized_label = normalize_string(label)
        
        # 检查这个状态转移对的所有规则
        covered = False
        for trans_id, details in transition_details.items():
            # 精确匹配状态转移对
            if details['from'] == from_node and details['to'] == to_node:
                # 规范化条件字符串
                normalized_condition = normalize_string(details['condition'])
                normalized_output = normalize_string(details['output'])
                
                # 检查条件是否匹配标签
                if normalized_condition in normalized_label:
                    # 检查输出是否匹配标签
                    if normalized_output in normalized_label:
                        # 如果这个规则被覆盖，标记为绿色
                        if details['is_covered']:
                            covered = True
                            break
        
        # 设置颜色
        color = 'green' if covered else 'black'
        
        # 添加边
        dot.edge(from_node, to_node, label=label, color=color, fontcolor=color)
    
    # 添加图例
    dot.node('legend', '''<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
        <TR><TD BGCOLOR="green">Covered Transition</TD></TR>
        <TR><TD>Black: Not Covered</TD></TR>
    </TABLE>>''', shape='plaintext')
    
    return dot

def visualize_coverage(report_file, dot_file):
    """可视化覆盖结果"""
    # 加载覆盖报告
    coverage = load_coverage_report(report_file)
    
    # 解析DOT文件
    dot_content = parse_dot_file(dot_file)
    
    # 生成带颜色的DOT图
    dot_graph = generate_colored_dot(dot_content, coverage)
    
    # 保存和渲染
    output_file = os.path.splitext(dot_file)[0] + "_coverage"
    dot_graph.render(output_file, format='png', cleanup=True)
    
    return output_file + '.png'

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python visualize_coverage.py <coverage_report.json> <dot_file.dot>")
        sys.exit(1)
    
    report_file = sys.argv[1]
    dot_file = sys.argv[2]
    
    image_file = visualize_coverage(report_file, dot_file)
    print(f"Coverage visualization saved to: {image_file}")
