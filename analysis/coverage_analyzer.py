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
        
        # ===== 新增：包级别的统计 =====
        self.packets = []  # 存储所有包的信息
        # ==============================
        
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
            
            # 释放命令
            'ue_ctx_rel_cmd',  # UE Context Release Command
        }
        # ================================
        
        # ===== 新增：无效消息模式黑名单（所有模式都过滤） =====
        self.invalid_patterns = [
            r'^0x[0-9a-fA-F]+$',  # 十六进制模式：0x61, 0x63 等
            r'^unknownprocedure',  # unknown开头的所有
        ]
        
        self.invalid_keywords = [
            'unsuccessfuloutcome',
            'successfuloutcome', 
            'initiatingmessage',
            'per_',
            '_element',
        ]
        # ======================================================
        
    def is_invalid_message(self, msg_abbrev):
        """
        判断是否为无效的消息类型（格式错误的消息）
        """
        if not msg_abbrev or len(msg_abbrev) < 3:
            return True
            
        lower_msg = msg_abbrev.lower()
        
        # 1. 检查关键词
        for keyword in self.invalid_keywords:
            if keyword in lower_msg:
                return True
        
        # 2. 检查正则表达式模式
        for pattern in self.invalid_patterns:
            if re.match(pattern, lower_msg):
                return True
        
        return False
        
    def classify_message(self, msg_abbrev):
        """
        分类消息类型
        返回: 'valid', 'invalid', 'unknown', 'error'
        """
        # 首先检查是否为格式错误的消息
        if self.is_invalid_message(msg_abbrev):
            return 'error'
        
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
            return False
        
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
        """解析抓包日志提取消息序列和包级别信息"""
        if not os.path.exists(self.log_file):
            print(f"Error: Log file not found: {self.log_file}")
            sys.exit(1)
        
        patterns = {
            'nas_sm': r'\[NAS-SM\] Message Type: (.*)',
            'nas_mm': r'\[NAS-MM\] Message Type: (.*)',
            'ngap': r'\[NGAP\] Packet.*— NGAP Message Type: (.*)'
        }
        
        direction_pattern = r'\[DIRECTION\] (.*)'
        packet_pattern = r'========== NGAP#(\d+) in Packet #(\d+) =========='
        
        # 用于临时存储当前数据包的信息
        current_packet = {
            'ngap_id': None,
            'packet_id': None,
            'direction': None,
            'messages': []
        }
        
        with open(self.log_file, encoding='utf-8') as f:
            for line in f:
                # 检测新的数据包开始
                packet_match = re.search(packet_pattern, line)
                if packet_match:
                    # 保存上一个数据包
                    if current_packet['messages'] and current_packet['direction']:
                        self.packets.append(current_packet.copy())
                        self.process_packet(current_packet['messages'], current_packet['direction'])
                    
                    # 开始新的数据包
                    current_packet = {
                        'ngap_id': int(packet_match.group(1)),
                        'packet_id': int(packet_match.group(2)),
                        'direction': None,
                        'messages': []
                    }
                    continue
                
                # 提取方向信息
                direction_match = re.search(direction_pattern, line)
                if direction_match:
                    current_packet['direction'] = direction_match.group(1).strip()
                    continue
                    
                # 尝试匹配各种消息类型
                for msg_type, pattern in patterns.items():
                    match = re.search(pattern, line)
                    if match:
                        full_name = match.group(1).split('(')[0].strip()
                        abbr = get_abbreviation(full_name)
                        
                        if abbr == full_name or abbr is None:
                            abbr = full_name
                        
                        # 先检查是否是无效消息
                        if not self.is_invalid_message(abbr):
                            current_packet['messages'].append(abbr)
                        break
        
        # 处理最后一个数据包
        if current_packet['messages'] and current_packet['direction']:
            self.packets.append(current_packet.copy())
            self.process_packet(current_packet['messages'], current_packet['direction'])
        
        print(f"\nExtracted {len(self.packets)} packets")
        print(f"Extracted {len(self.log_messages)} messages from log")
    
    def process_packet(self, messages, direction):
        """处理单个数据包内的消息"""
        if not messages:
            return
            
        for abbr in messages:
            # BASE模式：记录被过滤的消息
            if self.mode == 'base':
                if self.should_filter_in_base(abbr):
                    msg_class = self.classify_message(abbr)
                    if msg_class == 'invalid':
                        self.invalid_messages.append(abbr)
                        self.invalid_counter[abbr] += 1
                    elif msg_class == 'unknown':
                        self.unknown_messages.append(abbr)
                        self.unknown_counter[abbr] += 1
                    continue
            
            # 计入总体统计
            self.log_messages.append(abbr)
            self.directions.append(direction)
    
    def calculate_packet_success_rate(self):
        """
        计算信令质量统计

        第一部分：保留原来的“会话级”统计（兼容旧逻辑）
        第二部分：新增“请求语义级”统计
        第三部分：按消息类型统计请求级表现（用于有效新增覆盖分析）
        """
        # ======= 安全兜底 =======
        if not self.packets:
            return {
                # 会话级
                'total_request_sessions': 0,
                'success_sessions': 0,
                'err_ind_sessions': 0,
                'no_response_sessions': 0,
                # 包级（按请求统计）
                'total_request_packets': 0,
                'success_packets': 0,
                'err_ind_packets': 0,
                'no_response_packets': 0,
                # 成功率（默认按“请求语义级”）
                'success_rate': 0.0,
                # 额外字段
                'success_rate_session': 0.0,
                'total_requests': 0,
                'responded_requests': 0,
                'unresponded_requests': 0,
                'post_release_requests': 0,
                'success_rate_request': 0.0,
                # 每个消息的请求级统计
                'msg_request_stats': {},
            }

        # ============================================================
        # 一、原有逻辑：按“方向连续”的会话统计（尽量保持原样，兼容旧用法）
        # ============================================================
        sessions = []
        current_session = {
            'direction': None,
            'packets': [],
            'packet_indices': [],
            'start_idx': 0,
            'end_idx': 0
        }

        for i, packet in enumerate(self.packets):
            if not packet.get('direction'):
                continue

            direction = packet['direction']

            # 方向改变 -> 结束上一个会话，开启新会话
            if current_session['direction'] != direction:
                if current_session['packets']:
                    sessions.append(current_session.copy())

                current_session = {
                    'direction': direction,
                    'packets': [packet],
                    'packet_indices': [i],
                    'start_idx': i,
                    'end_idx': i
                }
            else:
                # 同方向，加入当前会话
                current_session['packets'].append(packet)
                current_session['packet_indices'].append(i)
                current_session['end_idx'] = i

        # 最后一个会话
        if current_session['packets']:
            sessions.append(current_session)

        # 会话级统计
        success_session_count = 0
        err_ind_session_count = 0
        no_response_session_count = 0

        # 包级统计（旧定义：按会话划分）
        total_gnb_packets = 0
        success_packet_count = 0
        err_ind_packet_count = 0
        no_response_packet_count = 0

        for i, session in enumerate(sessions):
            # 只看 gNB -> AMF 的会话
            if 'gNB -> AMF' not in session['direction']:
                continue

            session_packet_count = len(session['packets'])
            total_gnb_packets += session_packet_count

            has_response = False
            is_err_ind = False

            # 看下一个会话是不是 AMF -> gNB
            if i + 1 < len(sessions):
                next_session = sessions[i + 1]
                if 'AMF -> gNB' in next_session['direction']:
                    has_response = True

                    # 检查响应会话中是否包含 err_ind
                    for packet in next_session['packets']:
                        for msg in packet.get('messages', []):
                            if 'err_ind' in msg.lower():
                                is_err_ind = True
                                break
                        if is_err_ind:
                            break

            # 旧定义：err_ind / 无响应 / 成功
            if is_err_ind:
                err_ind_session_count += 1
                err_ind_packet_count += session_packet_count
            elif not has_response:
                no_response_session_count += 1
                no_response_packet_count += session_packet_count
            else:
                success_session_count += 1
                success_packet_count += session_packet_count

        total_sessions = (
            success_session_count + err_ind_session_count + no_response_session_count
        )
        success_rate_session = (
            success_session_count / total_sessions * 100
            if total_sessions > 0 else 0.0
        )

        # ============================================================
        # 二、新逻辑：基于“请求语义 + NGAP会话”的统计
        #   - 每个 gNB->AMF 包 = 一个请求
        #   - 上下文活着时，后续出现任意 AMF->gNB，则将 pending 的请求全算“有响应”
        #   - 上下文活着但 trace 结束：pending 全算“未响应”
        #   - 收到 UEContextReleaseCommand 后再发 gNB->AMF：算 post_release 请求
        #   - 同时按“消息类型”记录每个消息在这些请求里的表现
        # ============================================================
        by_ngap = defaultdict(list)
        for pkt in self.packets:
            ngap_id = pkt.get('ngap_id')
            if ngap_id is None:
                continue
            by_ngap[ngap_id].append(pkt)

        total_requests = 0
        responded_requests = 0
        unresponded_requests = 0
        post_release_requests = 0

        # 每种消息的请求级统计
        msg_request_stats = defaultdict(
            lambda: {'total': 0, 'responded': 0, 'unresponded': 0, 'post_release': 0}
        )

        for ngap_id, pkts in by_ngap.items():
            # 按 packet_id 排一下，保证时间顺序（保险起见）
            pkts = sorted(pkts, key=lambda x: x.get('packet_id', 0))

            context_alive = True
            pending_packets = []  # 当前"连续 gNB->AMF 段"中的包列表
            
            # ===== 新增：维护最近N个消息历史，用于判断是否为正常去注册流程 =====
            recent_messages = []  # 存储最近的消息（用于检测dereg）
            RECENT_WINDOW = 10    # 检查最近10个消息
            # =======================================================================

            def flush_segment(responded: bool):
                nonlocal pending_packets, responded_requests, unresponded_requests
                if not pending_packets:
                    return

                if responded:
                    responded_requests += len(pending_packets)
                else:
                    unresponded_requests += len(pending_packets)

                # 更新每个消息的请求级统计
                for rpkt in pending_packets:
                    msgs = rpkt.get('messages', [])
                    for m in msgs:
                        stat = msg_request_stats[m]
                        stat['total'] += 1
                        if responded:
                            stat['responded'] += 1
                        else:
                            stat['unresponded'] += 1

                pending_packets = []
            
            # ===== 新增：检查最近消息中是否有去注册相关信令 =====
            def has_deregister_in_recent():
                """检查最近的消息中是否包含去注册相关信令"""
                dereg_keywords = ['dereg', 'deregistration']
                for msg in recent_messages:
                    msg_lower = msg.lower()
                    if any(kw in msg_lower for kw in dereg_keywords):
                        return True
                return False
            # =====================================================

            for pkt in pkts:
                direction = pkt.get('direction', '')
                msgs = pkt.get('messages', [])
                
                # ===== 新增：更新最近消息历史 =====
                for m in msgs:
                    recent_messages.append(m)
                    if len(recent_messages) > RECENT_WINDOW:
                        recent_messages.pop(0)  # 保持窗口大小
                # ==================================

                # gNB -> AMF：计为一个请求
                if 'gNB -> AMF' in direction:
                    total_requests += 1

                    if not context_alive:
                        # 上下文已经被释放，在"尸体"上继续发
                        post_release_requests += 1
                        for m in msgs:
                            stat = msg_request_stats[m]
                            stat['total'] += 1
                            stat['post_release'] += 1
                        continue

                    # 上下文还活着，先积累到当前 pending 段
                    pending_packets.append(pkt)

                # AMF -> gNB：认为是对之前一段 pending 请求的"整体回应"
                elif 'AMF -> gNB' in direction:
                    if context_alive and pending_packets:
                        flush_segment(responded=True)

                    # 检查是否上下文释放
                    for m in msgs:
                        lm = m.lower()
                        if 'ue_ctx_rel_cmd' in lm or 'uecontextreleasecommand' in lm:
                            # ===== 关键修改：区分正常去注册和异常释放 =====
                            if has_deregister_in_recent():
                                # 正常去注册流程：重置状态，允许开始新的流程
                                context_alive = True
                                pending_packets = []
                                recent_messages = []  # 清空历史，开始新周期
                            else:
                                # 异常释放：核心网强制释放，后续请求算post_release
                                context_alive = False
                                pending_packets = []
                            # ================================================
                            break

            # 这一条 NGAP 会话结束，如果上下文还活着但还有 pending，则认为这些请求都没被理
            if context_alive and pending_packets:
                flush_segment(responded=False)

        # 按“请求语义”定义成功率：
        #   成功 = 有响应的请求
        #   失败 = 无响应 + 上下文释放后乱发
        if total_requests > 0:
            failed_requests = unresponded_requests + post_release_requests
            success_rate_request = (total_requests - failed_requests) / total_requests * 100
        else:
            success_rate_request = 0.0

        # ============================================================
        # 三、组装返回结果
        #   - 为保持兼容，success_rate 字段改为“请求级成功率”
        #   - 会话级统计、包级统计仍然保留
        #   - 额外返回 msg_request_stats 供 COMP 分析“有效新增信令”
        # ============================================================
        return {
            # —— 会话级统计（旧逻辑，方便参考）——
            'total_request_sessions': total_sessions,
            'success_sessions': success_session_count,
            'err_ind_sessions': err_ind_session_count,
            'no_response_sessions': no_response_session_count,

            # —— 包级统计（这里直接沿用“请求”的数量概念）——
            'total_request_packets': total_requests,  # == total_requests
            'success_packets': responded_requests,
            'err_ind_packets': err_ind_packet_count,  # 兼容旧逻辑
            'no_response_packets': unresponded_requests + post_release_requests,

            # —— 成功率 —— 
            # 对外暴露的 success_rate：改为“请求语义成功率”
            'success_rate': success_rate_request,

            # 额外保留一个会话成功率字段，便于调试 / 对比
            'success_rate_session': success_rate_session,

            # —— 新增的请求级详细统计 —— 
            'total_requests': total_requests,
            'responded_requests': responded_requests,
            'unresponded_requests': unresponded_requests,
            'post_release_requests': post_release_requests,
            'success_rate_request': success_rate_request,

            # —— 每个消息的请求级统计（用于判断哪些新增信令是“有效”的）——
            'msg_request_stats': dict(msg_request_stats),
        }

    
    def load_base_stats(self):
        """加载base文件的统计数据（包括BASE中的信令集合）"""
        base_file = "message_stats_base.txt"
        if not os.path.exists(base_file):
            return None
        
        try:
            with open(base_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            content = ''.join(lines)
            
            result = {}

            # msg 数
            msg_match = re.search(r'msg:\s*(\d+)', content)
            if msg_match:
                result['msg'] = int(msg_match.group(1))

            # 成功率：兼容“成功率: xx.x%”或“成功率(请求级): xx.x%”
            success_rate_match = re.search(r'成功率.*?([0-9.]+)%', content)
            if success_rate_match:
                result['success_rate'] = float(success_rate_match.group(1))

            # 解析 BASE 中的信令集合：从 [详细信令统计] 段落里的编号行提取
            base_msgs = set()
            in_detail = 0  # 0: 未进入; 1: 刚进入; 2: 正在读取列表

            for line in lines:
                stripped = line.strip()

                if stripped.startswith("[详细信令统计]"):
                    in_detail = 1
                    continue

                if in_detail == 1:
                    # 跳过 "一共有 X 种信令" 和空行
                    if not stripped or stripped.startswith("一共有"):
                        continue
                    m = re.match(r'\d+\.\s+(\S+)', stripped)
                    if m:
                        base_msgs.add(m.group(1))
                        in_detail = 2
                    continue

                if in_detail == 2:
                    if not stripped or stripped.startswith("="):
                        # 到空行或====认为结束
                        break
                    m = re.match(r'\d+\.\s+(\S+)', stripped)
                    if m:
                        base_msgs.add(m.group(1))

            if base_msgs:
                result['base_msgs'] = base_msgs
                
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
        msg = len(unique_messages)
        packet_stats = self.calculate_packet_success_rate()
        
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
        delta_success_rate = 0
        if prev_stats:
            if 'msg' in prev_stats:
                delta_msg = msg - prev_stats['msg']
            if 'success_rate' in prev_stats:
                delta_success_rate = packet_stats['success_rate'] - prev_stats['success_rate']
        
        # ===== 生成输出内容 =====
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
        
        # ===== 信令质量评估（会话 + 请求语义） =====
        output_lines.append("[信令质量评估]")
        output_lines.append("")

        # 会话视角（兼容原来的统计，方便对比）
        output_lines.append("📊 会话统计(方向连续视角):")
        output_lines.append(f"总请求会话数: {packet_stats['total_request_sessions']} (gNB -> AMF 会话)")
        output_lines.append(f"├─ ✅ 有响应会话: {packet_stats['success_sessions']}会话")
        output_lines.append(f"├─ ❌ 错误指示(err_ind): {packet_stats['err_ind_sessions']}会话")
        output_lines.append(f"└─ ⏱ 无响应会话: {packet_stats['no_response_sessions']}会话")
        output_lines.append(f"")

        # 新的“请求语义”视角
        output_lines.append("📦 请求统计(基于 NGAP 会话 / 上下文):")
        output_lines.append(f"总请求数: {packet_stats['total_requests']} (gNB -> AMF 包)")
        output_lines.append(f"├─ ✅ 有响应请求: {packet_stats['responded_requests']}条")
        output_lines.append(f"├─ ⏱ 无响应请求: {packet_stats['unresponded_requests']}条")
        output_lines.append(f"└─ ⚠ 上下文释放后仍发送的请求: {packet_stats['post_release_requests']}条")
        output_lines.append(f"")

        # 核心成功率：按“请求语义”定义
        output_lines.append(f"🎯 成功率(请求级): {packet_stats['success_rate']:.1f}%")
        output_lines.append(f"   (被核心网“理过”的请求 / 全部请求)")
        output_lines.append(f"📎 会话成功率(参考): {packet_stats['success_rate_session']:.1f}%")
        output_lines.append(f"   (有响应会话 / 总请求会话)")
        output_lines.append("")
        output_lines.append(f"💡 说明:")
        output_lines.append(f"   - 请求级成功率更敏感地反映“发出去的信令有没有被当空气”")
        output_lines.append(f"   - 上下文释放后继续发送的请求会单独统计并视为失败")
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
            output_lines.append("  - UE上下文释放命令 (ue_ctx_rel_cmd)")
            output_lines.append("✓ 已过滤格式错误的消息:")
            output_lines.append("  - 十六进制码 (0x61, 0x63 等)")
            output_lines.append("  - PDU类型标记 (unsuccessfulOutcome 等)")
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
            if 'success_rate' in prev_stats:
                output_lines.append(f"成功率变化(请求级): {delta_success_rate:+.1f}%  (BASE版本: {prev_stats['success_rate']:.1f}%)")
            output_lines.append("")
            
            # ===== 新增：相对BASE的“新增信令覆盖质量” =====
            base_msgs = prev_stats.get('base_msgs')
            msg_request_stats = packet_stats.get('msg_request_stats', {})

            if base_msgs:
                current_msgs = set(unique_messages)
                new_msgs = sorted(current_msgs - base_msgs)

                useful_new = []
                noise_new = []

                for m in new_msgs:
                    stats = msg_request_stats.get(m)
                    # 只要这个信令在“上下文活着”的请求里有过一次响应，就认为是“有效新增信令”
                    if stats and stats.get('responded', 0) > 0:
                        useful_new.append(m)
                    else:
                        noise_new.append(m)

                output_lines.append("[新增覆盖质量]")
                output_lines.append(f"新增信令种类: {len(new_msgs)} 种")
                if new_msgs:
                    output_lines.append(f"ENM(有效新增覆盖): {len(useful_new)} 种")
                output_lines.append(
                    "├─ ✅ 有响应的新信令: " +
                    (", ".join(useful_new) if useful_new else "无")
                )
                output_lines.append(
                    "└─ ⚠ 无响应/仅在异常上下文出现的新信令: " +
                    (", ".join(noise_new) if noise_new else "无")
                )
                if new_msgs:
                    ratio = len(useful_new) / len(new_msgs) * 100
                    output_lines.append(f"有效新增覆盖率: {ratio:.1f}%  ({len(useful_new)}/{len(new_msgs)})")
                output_lines.append("")

            # 对比分析
            if delta_msg > 0:
                output_lines.append("[对比分析]")
                output_lines.append(f"✓ 相比BASE增加了 {delta_msg} 种消息覆盖")
                
                if packet_stats['err_ind_sessions'] > 0:
                    err_ratio = (packet_stats['err_ind_sessions'] / packet_stats['total_request_sessions'] * 100) if packet_stats['total_request_sessions'] > 0 else 0
                    output_lines.append(f"⚠ 触发了 {packet_stats['err_ind_sessions']} 个错误指示会话 ({err_ratio:.1f}%)")
                    output_lines.append(f"  提示: 变异产生了核心网无法处理的消息")
                
                if packet_stats['no_response_sessions'] > 0:
                    no_resp_ratio = (packet_stats['no_response_sessions'] / packet_stats['total_request_sessions'] * 100) if packet_stats['total_request_sessions'] > 0 else 0
                    output_lines.append(f"⚠ 有 {packet_stats['no_response_sessions']} 个会话未得到响应 ({no_resp_ratio:.1f}%)")
                    output_lines.append(f"  提示: 可能是鉴权失败或消息格式错误导致核心网忽略")
                
                if packet_stats['success_rate'] < 50:
                    output_lines.append(f"⚠ 成功率较低 ({packet_stats['success_rate']:.1f}%)")
                    output_lines.append(f"  建议: 优化变异策略，提高有效变异比例")
                elif packet_stats['success_rate'] >= 70:
                    output_lines.append(f"✓ 成功率良好 ({packet_stats['success_rate']:.1f}%)")
                
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
            output_lines.append(f"{i}. {msg_type}  {count}次")
        
        output_lines.append("")
        output_lines.append("=" * 60)
        
        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(output_lines))
        
        print(f"\n信令统计已保存到: {output_file}")
        
        # 打印到控制台
        print("")
        for line in output_lines:
            print(line)
        
        # 给出提示
        if self.mode == 'base':
            print("\n提示: BASE文件已生成，下次可以运行 'python coverage_analyzer.py comp' 进行对比分析")
    
    def run_analysis(self):
        """运行完整分析流程"""
        if not os.path.exists(self.log_file):
            print(f"Error: Log file not found: {self.log_file}")
            sys.exit(1)
        
        self.parse_log()
        self.save_message_stats()

# 主程序
if __name__ == "__main__":
    default_transitions = "amf_transitions_clean.json"
    default_log = "./logs/capture_summary.log"
    
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
