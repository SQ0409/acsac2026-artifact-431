# 第一次：生成基准数据
#python coverage_analyzer.py base

# 第二次：与基准对比
#python coverage_analyzer.py comp

# 也可以指定日志文件
#python coverage_analyzer.py base ./logs/my_capture.log
#python coverage_analyzer.py comp ./logs/my_capture.log

# 普通模式（不对比）
#python coverage_analyzer.py


import json
import re
import os
import sys
from collections import defaultdict, Counter
from datetime import datetime
from Levenshtein import distance as levenshtein_distance
from msg_maps import get_abbreviation, MSG_MAPPING

class CoverageAnalyzer:
    def __init__(self, transitions_file, log_file, mode='normal'):
        self.transitions_file = transitions_file
        self.log_file = log_file
        self.mode = mode  # 'base', 'comp', 或 'normal'
        self.transitions = []
        self.log_messages = []
        self.directions = []  # 存储方向信息
        
        # ===== 新增：分类统计（仅BASE模式使用） =====
        self.invalid_messages = []    # 无效信令（错误/拒绝）
        self.unknown_messages = []    # 未知信令
        self.invalid_counter = Counter()
        self.unknown_counter = Counter()
        # =========================
        
        # ===== 新增：BASE模式黑名单 =====
        self.base_blacklist = {
            # 错误和指示类
            'err_ind', 'error_indication', 'errorindication',
            
            # 拒绝消息
            'auth_rej', 'reg_rej', 'dereg_rej', 'pdu_sess_est_rej',
            'authentication_reject', 'registration_reject',
            'authenticationreject', 'registrationreject',
            
            # 取消类消息
            'ho_cancel', 'handovercancel', 'handovercancelacknowledge',
            
            # 失败类消息
            'ng_setup_fail', 'ngsetupfailure', 'initial_context_setup_failure',
            'init_ctx_setup_fail', 'pdu_session_resource_setup_unsuccessful',
            
            # 未知消息
            'unknownprocedure_req', 'unknownprocedure_res', 
            'unknownprocedure', 'unknown',

            'ue_ctx_rel_cmd',  # UE Context Release Command
        }
        # ================================
        
    def classify_message(self, msg_abbrev):
        """
        分类消息类型
        返回: 'valid', 'invalid', 'unknown'
        """
        lower_msg = msg_abbrev.lower()
        
        # 1. 检查是否为未知消息
        if 'unknown' in lower_msg:
            return 'unknown'
        
        # 2. 检查是否没有缩写映射（原始长名称，长度>20）
        if msg_abbrev not in MSG_MAPPING.values() and len(msg_abbrev) > 20:
            return 'unknown'
        
        # 3. 检查是否为无效消息（错误/拒绝/取消/失败）
        invalid_keywords = ['err', 'error', 'rej', 'reject', 'cancel', 
                           'fail', 'failure', 'unsuccessful']
        if any(keyword in lower_msg for keyword in invalid_keywords):
            return 'invalid'
        
        # 4. 其他情况为有效消息
        return 'valid'
    
    def should_filter_in_base(self, msg_abbrev):
        """
        判断在BASE模式下是否应该过滤该消息
        返回: True=过滤, False=保留
        """
        if self.mode != 'base':
            return False  # 非BASE模式不过滤
        
        lower_msg = msg_abbrev.lower()
        
        # 1. 检查是否在黑名单中
        if lower_msg in self.base_blacklist:
            return True
        
        # 2. 检查分类（BASE模式下过滤无效和未知消息）
        msg_type = self.classify_message(msg_abbrev)
        if msg_type in ['invalid', 'unknown']:
            return True
        
        return False
        
    def load_transitions(self):
        """加载状态转移表"""
        if not os.path.exists(self.transitions_file):
            print(f"Error: Transitions file not found: {self.transitions_file}")
            sys.exit(1)
            
        with open(self.transitions_file) as f:
            self.transitions = json.load(f)
        print(f"Loaded {len(self.transitions)} transitions")
    
    def parse_log(self):
        """解析抓包日志提取消息序列和方向信息"""
        if not os.path.exists(self.log_file):
            print(f"Error: Log file not found: {self.log_file}")
            sys.exit(1)
        
        patterns = {
            'nas_sm': r'\[NAS-SM\] Message Type: (.*)',
            'nas_mm': r'\[NAS-MM\] Message Type: (.*)',
            'ngap': r'\[NGAP\] Packet.*— NGAP Message Type: (.*)'
        }
        
        direction_pattern = r'\[DIRECTION\] (.*)'
        
        # 用于临时存储当前数据包的消息
        current_packet_messages = []
        current_direction = None
        
        with open(self.log_file, encoding='utf-8') as f:
            for line in f:
                # 检测新的数据包开始
                if "========== NGAP#" in line:
                    # 处理上一个数据包
                    if current_packet_messages and current_direction:
                        self.process_packet(current_packet_messages, current_direction)
                    current_packet_messages = []
                    current_direction = None
                    continue
                
                # 提取方向信息
                direction_match = re.search(direction_pattern, line)
                if direction_match:
                    current_direction = direction_match.group(1).strip()
                    continue
                    
                # 尝试匹配各种消息类型
                for msg_type, pattern in patterns.items():
                    match = re.search(pattern, line)
                    if match:
                        full_name = match.group(1).split('(')[0].strip()
                        abbr = get_abbreviation(full_name)
                        
                        # 如果找不到缩写，直接使用原始消息名称
                        if abbr == full_name or abbr is None:
                            abbr = full_name
                        
                        current_packet_messages.append((msg_type, abbr))
                        break
        
        # 处理最后一个数据包
        if current_packet_messages and current_direction:
            self.process_packet(current_packet_messages, current_direction)
        
        print(f"\nExtracted {len(self.log_messages)} messages from log")
    
    def process_packet(self, messages, direction):
        """处理单个数据包内的消息和方向"""
        if not messages:
            return
            
        # 统计所有消息类型（NGAP、NAS-MM、NAS-SM都要）
        for msg_type, abbr in messages:
            # ===== BASE模式：记录被过滤的消息（用于分析） =====
            if self.mode == 'base':
                if self.should_filter_in_base(abbr):
                    # 分类记录但不计入log_messages
                    msg_class = self.classify_message(abbr)
                    if msg_class == 'invalid':
                        self.invalid_messages.append(abbr)
                        self.invalid_counter[abbr] += 1
                    elif msg_class == 'unknown':
                        self.unknown_messages.append(abbr)
                        self.unknown_counter[abbr] += 1
                    continue  # 跳过，不计入log_messages
            # ================================================
            
            # 计入总体统计（BASE会过滤，COMP全部统计）
            self.log_messages.append(abbr)
            self.directions.append(direction)
    
    def load_base_stats(self):
        """加载base文件的统计数据"""
        base_file = "message_stats_base.txt"
        if not os.path.exists(base_file):
            return None
        
        try:
            with open(base_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 使用正则表达式提取 msg
            msg_match = re.search(r'msg:\s*(\d+)', content)
            
            result = {}
            if msg_match:
                result['msg'] = int(msg_match.group(1))
                
            return result if result else None
        except Exception as e:
            print(f"Error loading base stats: {e}")
            return None
    
    def save_message_stats(self):
        """保存信令统计到txt文件"""
        # 统计信令类型
        unique_messages = set(self.log_messages)
        message_count = {msg: self.log_messages.count(msg) for msg in unique_messages}
        
        # 按照出现次数排序
        sorted_messages = sorted(message_count.items(), key=lambda x: x[1], reverse=True)
        
        # 计算参数
        msg = len(unique_messages)  # 消息种类覆盖
        
        # 根据模式确定文件名
        if self.mode == 'base':
            output_file = "message_stats_base.txt"
            title = "信令统计报告 - BASE (基准版本)"
        elif self.mode == 'comp':
            output_file = "message_stats_comp.txt"
            title = "信令统计报告 - COMP (对比版本)"
        else:
            output_file = "message_stats.txt"
            title = "信令统计报告"
        
        # 如果是comp模式，加载base数据
        prev_stats = None
        if self.mode == 'comp':
            prev_stats = self.load_base_stats()
            if not prev_stats:
                print("\n警告: 未找到base文件，请先运行 'python coverage_analyzer.py base' 生成基准数据")
        
        # 计算增量
        delta_msg = 0
        if prev_stats and 'msg' in prev_stats:
            delta_msg = msg - prev_stats['msg']
        
        # ===== 生成输出内容（终端和文件一致） =====
        output_lines = []
        output_lines.append("=" * 60)
        output_lines.append(title)
        output_lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output_lines.append("=" * 60)
        output_lines.append("")
        
        # 核心参数
        output_lines.append("[核心参数]")
        output_lines.append(f"msg: {msg}  (消息种类覆盖)")
        output_lines.append("")
        
        # ===== BASE模式说明 =====
        if self.mode == 'base':
            output_lines.append("[BASE模式说明]")
            output_lines.append("✓ 已自动过滤无效消息类型:")
            output_lines.append("  - 错误指示 (err_ind, error_indication)")
            output_lines.append("  - 拒绝消息 (包含 rej/reject 的消息)")
            output_lines.append("  - 取消消息 (包含 cancel 的消息)")
            output_lines.append("  - 失败消息 (包含 fail/failure 的消息)")
            output_lines.append("  - 未知消息 (unknownprocedure 等)")
            output_lines.append("  - 未映射的长消息名称")
            output_lines.append("✓ 仅统计正常流程中的有效信令")
            output_lines.append("")
            
            # BASE模式显示被过滤的消息统计
            if self.invalid_counter or self.unknown_counter:
                total_filtered = len(self.invalid_messages) + len(self.unknown_messages)
                output_lines.append("[已过滤消息统计]")
                output_lines.append(f"共过滤 {total_filtered} 条消息（未计入msg）")
                
                if self.invalid_counter:
                    output_lines.append(f"❌ 无效信令 ({len(set(self.invalid_messages))} 种):")
                    sorted_invalid = sorted(self.invalid_counter.items(), 
                                          key=lambda x: x[1], reverse=True)
                    for msg_name, count in sorted_invalid:
                        output_lines.append(f"   {msg_name}: {count}次")
                
                if self.unknown_counter:
                    output_lines.append(f"❓ 未知信令 ({len(set(self.unknown_messages))} 种):")
                    sorted_unknown = sorted(self.unknown_counter.items(), 
                                          key=lambda x: x[1], reverse=True)
                    for msg_name, count in sorted_unknown:
                        output_lines.append(f"   {msg_name}: {count}次")
                
                output_lines.append("")
        
        # 如果是comp模式且有base数据，显示对比
        if self.mode == 'comp' and prev_stats:
            output_lines.append("[与BASE版本对比]")
            output_lines.append(f"PBE: {delta_msg:+d}  (BASE版本: {prev_stats['msg']})")
            output_lines.append("")
        elif self.mode == 'comp' and not prev_stats:
            output_lines.append("[与BASE版本对比]")
            output_lines.append("未找到BASE文件，无法对比")
            output_lines.append("")
        
        # 详细信令统计
        output_lines.append("[详细信令统计]")
        output_lines.append(f"一共有 {msg} 种信令")
        output_lines.append("")
        for i, (msg_type, count) in enumerate(sorted_messages, 1):
            # BASE模式不显示图标，COMP模式也不显示（因为全部统计）
            output_lines.append(f"{i}. {msg_type}  {count}次")
        
        output_lines.append("")
        output_lines.append("=" * 60)
        
        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(output_lines))
        
        print(f"\n信令统计已保存到: {output_file}")
        
        # 打印到控制台（完全一致）
        print("")
        for line in output_lines:
            print(line)
        
        # 给出提示
        if self.mode == 'base':
            print("\n提示: BASE文件已生成，下次可以运行 'python coverage_analyzer.py comp' 进行对比分析")
    
    def run_analysis(self):
        """运行完整分析流程"""
        # 确保文件存在
        if not os.path.exists(self.log_file):
            print(f"Error: Log file not found: {self.log_file}")
            sys.exit(1)
        
        self.parse_log()
        self.save_message_stats()

# 主程序
if __name__ == "__main__":
    # 设置默认文件名
    default_transitions = "amf_transitions_clean.json"
    default_log = "./logs/capture_summary.log"
    
    # 解析命令行参数
    mode = 'normal'
    log_file = default_log
    
    if len(sys.argv) >= 2:
        arg1 = sys.argv[1].lower()
        if arg1 in ['base', 'comp']:
            mode = arg1
            if len(sys.argv) >= 3:
                log_file = sys.argv[2]
        else:
            log_file = sys.argv[1]
    
    # 显示当前模式
    if mode == 'base':
        print("模式: BASE - 生成基准数据")
    elif mode == 'comp':
        print("模式: COMP - 与基准数据对比")
    else:
        print("模式: NORMAL - 普通统计")
    
    print(f"使用日志文件: {log_file}")
    
    analyzer = CoverageAnalyzer(
        transitions_file=default_transitions,
        log_file=log_file,
        mode=mode
    )
    analyzer.run_analysis()
    
    print("\n分析完成！")

