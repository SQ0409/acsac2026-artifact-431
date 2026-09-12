import os
import networkx as nx
import pydot

def parse_dot(dot_file):
    # 使用pydot解析.dot文件
    (graph,) = pydot.graph_from_dot_file(dot_file)
    
    # 转换为NetworkX图，便于后续操作
    G = nx.DiGraph()  # 有向图
    
    # 只添加状态节点，避免添加默认的无关节点
    for node in graph.get_nodes():
        node_name = node.get_name()
        if node_name != 'node':  # 排除'node'节点
            G.add_node(node_name)
    
    # 添加边并过滤掉无效的自循环边
    for edge in graph.get_edges():
        source = edge.get_source()
        dest = edge.get_destination()
        label = edge.get_attributes().get('label', '')
        
        if source != dest:  # 只添加有效的边
            G.add_edge(source, dest, label=label)
    
    return G

# 指定你的.dot文件路径
dot_file_amf = os.getenv("IPSM_DOT", "output/ipsm.dot")
G_amf = parse_dot(dot_file_amf)

# 输出解析后的图的节点和边
print("节点：", G_amf.nodes())
print("边：", G_amf.edges())
