#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pyshark
import threading
import os
import datetime
import time
import signal
import sys

import msg_maps  # 导入消息映射表

class CaptureWorker(threading.Thread):
    def __init__(self, interface=None, gnb_ip=None, amf_ip=None):
        interface = interface or os.getenv('CAPTURE_INTERFACE', 'any')
        gnb_ip = gnb_ip or os.getenv('GNB_IP', '127.0.0.1')
        amf_ip = amf_ip or os.getenv('AMF_IP', '127.0.0.1')
        super().__init__(daemon=True)
        self.interface = interface
        self.gnb_ip = gnb_ip
        self.amf_ip = amf_ip

        os.makedirs('logs', exist_ok=True)
        self.general_log_path = 'logs/capture.log'
        self.ngap_log_path    = 'logs/capture_ngap.log'
        self.summary_log_path = 'logs/capture_summary.log'  # 新增：只包含消息类型的日志

        self.general_log_file = open(self.general_log_path, 'w', encoding='utf-8')
        self.ngap_log_file    = open(self.ngap_log_path, 'w', encoding='utf-8')
        self.summary_log_file = open(self.summary_log_path, 'w', encoding='utf-8')  # 新增
        self._stop_event      = threading.Event()

    def log_general(self, text):
        now  = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        self.general_log_file.write(f"[{now}] {text}\n")
        self.general_log_file.flush()

    def log_ngap(self, text):
        now  = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        self.ngap_log_file.write(f"[{now}] {text}\n")
        self.ngap_log_file.flush()

    def log_summary(self, text):
        now  = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        self.summary_log_file.write(f"[{now}] {text}\n")
        self.summary_log_file.flush()

    def determine_direction(self, pkt):
        try:
            # 优先使用端口号判断（38412 是 NGAP 标准端口）
            if hasattr(pkt, 'sctp'):
                try:
                    src_port = str(getattr(pkt.sctp, 'srcport', ''))
                    dst_port = str(getattr(pkt.sctp, 'dstport', ''))
                    
                    # 目标端口是 38412，说明是发往 AMF
                    if '38412' in dst_port:
                        return "gNB -> AMF"
                    # 源端口是 38412，说明是从 AMF 发出
                    elif '38412' in src_port:
                        return "AMF -> gNB"
                except:
                    pass
            
            # 也检查 UDP 层（某些情况下）
            if hasattr(pkt, 'udp'):
                try:
                    src_port = str(getattr(pkt.udp, 'srcport', ''))
                    dst_port = str(getattr(pkt.udp, 'dstport', ''))
                    
                    if '38412' in dst_port:
                        return "gNB -> AMF"
                    elif '38412' in src_port:
                        return "AMF -> gNB"
                except:
                    pass
            
            # 备用方案：使用 IP 地址判断（当 IP 不同时）
            if hasattr(pkt, 'ip'):
                src, dst = pkt.ip.src, pkt.ip.dst
                if src != dst:  # 只有当 IP 不同时才用这个方法
                    if src == self.gnb_ip and dst == self.amf_ip:
                        return "gNB -> AMF"
                    if src == self.amf_ip and dst == self.gnb_ip:
                        return "AMF -> gNB"
                return f"Unknown ({src} -> {dst})"
            return "Non-IP"
        except Exception as e:
            return f"Error determining direction: {e}"

    def run(self):
        bpf = (
            f"(src host {self.gnb_ip} and dst host {self.amf_ip}) or "
            f"(src host {self.amf_ip} and dst host {self.gnb_ip})"
        )
        self.log_general(f"[INFO] Starting capture on interface {self.interface} with BPF filter: {bpf}")

        cap = pyshark.LiveCapture(
            interface=self.interface,
            bpf_filter=bpf,
            override_prefs={ 'nas-5gs.null_decipher': 'TRUE' }
        )

        count = 0
        try:
            for pkt in cap.sniff_continuously():
                if self._stop_event.is_set(): break
                count += 1
                self.log_general(f"[INFO] Packet #{count} captured")
                layers = [l.layer_name for l in pkt.layers]
                self.log_general(f"[DEBUG] Packet layers: {layers}")

                try:
                    direction = self.determine_direction(pkt)
                    ngap_layers = pkt.get_multiple_layers('ngap')
                    for idx, ngap in enumerate(ngap_layers, start=1):
                        # 原始详细日志 (保持不变)
                        self.log_ngap(f"========== NGAP#{idx} in Packet #{count} ==========")
                        self.log_ngap(f"[DIRECTION] {direction}")

                        # 输出所有字段 (保持原有逻辑)
                        for field in ngap.field_names:
                            try:
                                val = getattr(ngap, field)
                                self.log_ngap(f"  {field} = {val}")
                            except Exception as e:
                                self.log_ngap(f"  {field} = <error: {e}>")

                        # 提取 NGAP 消息类型，优先 element，排除 initiatingmessage 和 successfuloutcome
                        ngap_msg = None
                        for field in ngap.field_names:
                            if field.endswith('_element') and field not in ('initiatingmessage_element', 'successfuloutcome_element'):
                                val = getattr(ngap, field, None)
                                if val and not str(val).lower().startswith('value'):
                                    ngap_msg = val
                                    break
                        if not ngap_msg:
                            base = 'UnknownProcedure'
                            try:
                                code = int(getattr(ngap, 'procedurecode', -1))
                                base = msg_maps.ngap_msg_map.get(code, base)
                            except:
                                pass
                            try:
                                pdu = int(getattr(ngap, 'ngap_pdu', -1))
                            except:
                                pdu = -1
                            suffix = {0:'Request',1:'Response',2:'UnsuccessfulOutcome'}.get(pdu, '')
                            ngap_msg = f"{base}{suffix}"

                        # 原始详细日志中输出 NGAP 消息类型
                        self.log_ngap(f"[NGAP] Packet #{count}(#{idx}) — NGAP Message Type: {ngap_msg}")

                        # 新增：简化日志输出（添加方向信息）
                        self.log_summary(f"========== NGAP#{idx} in Packet #{count} ==========")
                        self.log_summary(f"[DIRECTION] {direction}")  # 添加方向信息
                        self.log_summary(f"[NGAP] Packet #{count}(#{idx}) — NGAP Message Type: {ngap_msg}")

                        # 提取并输出 NAS MM
                        if hasattr(ngap, 'nas_5gs_mm_message_type'):
                            raw = ngap.nas_5gs_mm_message_type
                            try:
                                i = int(raw, 16) if isinstance(raw, str) and raw.lower().startswith('0x') else int(raw)
                                name = msg_maps.nas_msg_map.get(i, hex(i))
                                # 原始详细日志
                                self.log_ngap(f"[NAS-MM] Message Type: {name} ({hex(i)})")
                                # 简化日志
                                self.log_summary(f"[NAS-MM] Message Type: {name} ({hex(i)})")
                            except Exception:
                                pass

                        # 提取并输出 NAS SM
                        if hasattr(ngap, 'nas_5gs_sm_message_type'):
                            raw = ngap.nas_5gs_sm_message_type
                            try:
                                i = int(raw, 16) if isinstance(raw, str) and raw.lower().startswith('0x') else int(raw)
                                name = msg_maps.nas_msg_map.get(i, hex(i))
                                # 原始详细日志
                                self.log_ngap(f"[NAS-SM] Message Type: {name} ({hex(i)})")
                                # 简化日志
                                self.log_summary(f"[NAS-SM] Message Type: {name} ({hex(i)})")
                            except Exception:
                                pass

                except Exception as e:
                    self.log_general(f"[ERROR] Packet#{count} processing: {e}")
        except Exception as e:
            self.log_general(f"[ERROR] Capture stopped due to exception: {e}")

    def stop(self):
        self._stop_event.set()

    def close(self):
        self.log_general("[INFO] Closing logs and stopping capture.")
        self.general_log_file.close()
        self.ngap_log_file.close()
        self.summary_log_file.close()  # 新增

    def __del__(self):
        pass


def signal_handler(sig, frame):
    print("Stopping capture...")
    worker.stop()
    worker.join()
    worker.close()
    sys.exit(0)

if __name__ == '__main__':
    worker = CaptureWorker()
    worker.start()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)
