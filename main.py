import customtkinter as ctk
import threading
import pandas as pd
import numpy as np
import os
from scapy.all import PcapReader, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import psutil
import time

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class LightweightFlowTracker:
    """
    Memory-efficient flow tracker for feature extraction
    """
    
    def __init__(self, timeout=120):
        self.flows = {}
        self.timeout = timeout
        self.packet_count = 0
        self.start_time = None
        
        # Performance tracking
        self.processing_times = []
        self.memory_usage = []
    
    def get_flow_key(self, pkt):
        """Create bidirectional flow key"""
        if IP not in pkt:
            return None
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            sport, dport = 0, 0
        
        # Bidirectional key
        if (src_ip, sport) < (dst_ip, dport):
            return (src_ip, sport, dst_ip, dport, proto)
        else:
            return (dst_ip, dport, src_ip, sport, proto)
    
    def process_packet(self, pkt):
        """Process a single packet"""
        start = time.time()
        
        if self.start_time is None:
            self.start_time = time.time()
        
        flow_key = self.get_flow_key(pkt)
        if flow_key is None:
            return
        
        timestamp = float(pkt.time)
        
        # Initialize flow if new
        if flow_key not in self.flows:
            src_ip, sport, dst_ip, dport, proto = flow_key
            self.flows[flow_key] = {
                'src_ip': src_ip, 'sport': sport,
                'dst_ip': dst_ip, 'dport': dport, 'proto': proto,
                'start_time': timestamp, 'last_time': timestamp,
                'timestamps': [timestamp],
                'fwd_pkts': 0, 'bwd_pkts': 0,
                'fwd_bytes': 0, 'bwd_bytes': 0,
                'pkt_lengths': [], 'header_lengths': [],
                'syn_count': 0, 'urg_count': 0, 'fin_count': 0,
                'ttl_values': [], 'window_sizes': [],
                'fwd_iats': [], 'bwd_iats': [],
                'last_fwd_time': None, 'last_bwd_time': None,
                'active_periods': [], 'idle_periods': [],
                'active_start': timestamp
            }
        
        flow = self.flows[flow_key]
        src_ip, sport, dst_ip, dport, proto = flow_key
        
        # Determine direction
        direction = 'fwd' if pkt[IP].src == src_ip else 'bwd'
        
        # Update flow statistics
        pkt_len = len(pkt)
        flow['pkt_lengths'].append(pkt_len)
        flow['timestamps'].append(timestamp)
        
        if direction == 'fwd':
            flow['fwd_pkts'] += 1
            flow['fwd_bytes'] += pkt_len
            if flow['last_fwd_time']:
                flow['fwd_iats'].append(timestamp - flow['last_fwd_time'])
            flow['last_fwd_time'] = timestamp
        else:
            flow['bwd_pkts'] += 1
            flow['bwd_bytes'] += pkt_len
            if flow['last_bwd_time']:
                flow['bwd_iats'].append(timestamp - flow['last_bwd_time'])
            flow['last_bwd_time'] = timestamp
        
        # Active/Idle periods
        if flow['last_time']:
            gap = timestamp - flow['last_time']
            if gap > 1.0:
                flow['idle_periods'].append(gap)
                if flow['active_start']:
                    active = flow['last_time'] - flow['active_start']
                    if active > 0:
                        flow['active_periods'].append(active)
                flow['active_start'] = timestamp
        
        flow['last_time'] = timestamp
        
        # TTL
        if IP in pkt:
            flow['ttl_values'].append(pkt[IP].ttl)
        
        # Header length
        header_len = len(pkt[IP]) - len(pkt[IP].payload) if IP in pkt else 0
        if TCP in pkt:
            header_len += 20
        elif UDP in pkt:
            header_len += 8
        flow['header_lengths'].append(header_len)
        
        # TCP flags
        if TCP in pkt:
            if pkt[TCP].flags & 0x02: flow['syn_count'] += 1
            if pkt[TCP].flags & 0x20: flow['urg_count'] += 1
            if pkt[TCP].flags & 0x01: flow['fin_count'] += 1
            flow['window_sizes'].append(pkt[TCP].window)
        
        self.packet_count += 1
        
        # Track processing time
        self.processing_times.append((time.time() - start) * 1000)  # ms
    
    def extract_features(self, flow_key):
        """Extract all 36 features from a flow"""
        flow = self.flows[flow_key]
        
        # Flow duration
        flow_duration = max(flow['last_time'] - flow['start_time'], 0.000001)
        
        # IAT statistics
        timestamps = flow['timestamps']
        iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)] if len(timestamps) > 1 else [0]
        
        # Calculate all features
        total_pkts = flow['fwd_pkts'] + flow['bwd_pkts']
        total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']
        
        features = {
            # Identifiers
            'src_ip': flow['src_ip'],
            'sport': flow['sport'],
            'dst_ip': flow['dst_ip'],
            'dport': flow['dport'],
            'proto': flow['proto'],
            
            # IAT features (4)
            'iat_mean': np.mean(iats),
            'iat_std': np.std(iats),
            'iat_min': min(iats),
            'iat_max': max(iats),
            
            # Flow timing (3)
            'flow_duration': flow_duration,
            'active_time_mean': np.mean(flow['active_periods']) if flow['active_periods'] else 0,
            'idle_time_mean': np.mean(flow['idle_periods']) if flow['idle_periods'] else 0,
            'fwd_iat_mean': np.mean(flow['fwd_iats']) if flow['fwd_iats'] else 0,
            
            # TTL (2)
            'ttl_mean': np.mean(flow['ttl_values']) if flow['ttl_values'] else 0,
            'ttl_std': np.std(flow['ttl_values']) if flow['ttl_values'] else 0,
            
            # Window size (2)
            'win_size_mean': np.mean(flow['window_sizes']) if flow['window_sizes'] else 0,
            'win_size_std': np.std(flow['window_sizes']) if flow['window_sizes'] else 0,
            
            # Flags (3)
            'syn_count': flow['syn_count'],
            'urg_count': flow['urg_count'],
            'fin_ratio': flow['fin_count'] / total_pkts if total_pkts > 0 else 0,
            
            # Header (1)
            'header_len_mean': np.mean(flow['header_lengths']) if flow['header_lengths'] else 0,
            
            # Ratios (4)
            'pkt_ratio': flow['fwd_pkts'] / (flow['bwd_pkts'] + 1),
            'byte_ratio': flow['fwd_bytes'] / (total_bytes + 1),
            'size_asymmetry': abs(flow['fwd_bytes'] - flow['bwd_bytes']) / (total_bytes + 1),
            'response_rate': flow['bwd_pkts'] / (flow['fwd_pkts'] + 1),
            
            # Packet length (3)
            'pkt_len_mean': np.mean(flow['pkt_lengths']) if flow['pkt_lengths'] else 0,
            'pkt_len_std': np.std(flow['pkt_lengths']) if flow['pkt_lengths'] else 0,
            'pkt_len_var_coeff': (np.std(flow['pkt_lengths']) / (np.mean(flow['pkt_lengths']) + 1)) if flow['pkt_lengths'] else 0,
            
            # Packet size categories (2)
            'small_pkt_ratio': sum(1 for l in flow['pkt_lengths'] if l < 100) / len(flow['pkt_lengths']) if flow['pkt_lengths'] else 0,
            'large_pkt_ratio': sum(1 for l in flow['pkt_lengths'] if l > 1000) / len(flow['pkt_lengths']) if flow['pkt_lengths'] else 0,
            
            # Header/Payload (1)
            'header_payload_ratio': sum(flow['header_lengths']) / (total_bytes - sum(flow['header_lengths']) + 1),
            
            # Flow rates (4)
            'flow_pps': total_pkts / flow_duration,
            'flow_bps': total_bytes * 8 / flow_duration,
            'fwd_bps': flow['fwd_bytes'] * 8 / flow_duration,
            'bwd_pps': flow['bwd_pkts'] / flow_duration
        }
        
        return features
    
    def get_all_features(self):
        """Extract features from all flows"""
        return [self.extract_features(fk) for fk in self.flows.keys()]
    
    def get_performance_stats(self):
        """Get performance statistics"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        return {
            'total_packets': self.packet_count,
            'total_flows': len(self.flows),
            'elapsed_time': elapsed,
            'packets_per_second': self.packet_count / elapsed if elapsed > 0 else 0,
            'avg_processing_time_ms': np.mean(self.processing_times) if self.processing_times else 0,
            'max_processing_time_ms': max(self.processing_times) if self.processing_times else 0,
            'memory_mb': psutil.Process().memory_info().rss / 1024 / 1024
        }


class PacketToolApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("UNSW-NB15 Feature Extractor - 36 Lightweight Features")
        self.geometry("850x750")
        self.resizable(False, False)

        # 1. Header
        self.header_frame = ctk.CTkFrame(self, height=60, corner_radius=10)
        self.header_frame.pack(fill="x", padx=10, pady=10)
        self.label_title = ctk.CTkLabel(
            self.header_frame, 
            text="UNSW-NB15 Feature Extractor (36 Features)", 
            font=("Roboto", 20, "bold")
        )
        self.label_title.pack(pady=15)

        # 2. Input: PCAP File
        self.frame_pcap = ctk.CTkFrame(self)
        self.frame_pcap.pack(fill="x", padx=10, pady=5)
        self.entry_pcap = ctk.CTkEntry(
            self.frame_pcap, 
            placeholder_text="Select PCAP file...", 
            width=600
        )
        self.entry_pcap.pack(side="left", padx=10, pady=10)
        self.btn_pcap = ctk.CTkButton(
            self.frame_pcap, 
            text="Browse PCAP", 
            command=lambda: self.browse_file(self.entry_pcap, "pcap"),
            width=120
        )
        self.btn_pcap.pack(side="right", padx=10, pady=10)

        # 3. Input: Ground Truth CSV
        self.frame_gt = ctk.CTkFrame(self)
        self.frame_gt.pack(fill="x", padx=10, pady=5)
        self.entry_gt = ctk.CTkEntry(
            self.frame_gt, 
            placeholder_text="Select Ground Truth CSV...", 
            width=600
        )
        self.entry_gt.pack(side="left", padx=10, pady=10)
        self.btn_gt = ctk.CTkButton(
            self.frame_gt, 
            text="Browse GT CSV", 
            fg_color="#555", 
            hover_color="#444", 
            command=lambda: self.browse_file(self.entry_gt, "csv"),
            width=120
        )
        self.btn_gt.pack(side="right", padx=10, pady=10)

        # 4. Progress Bar
        self.progress_frame = ctk.CTkFrame(self)
        self.progress_frame.pack(fill="x", padx=10, pady=5)
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, width=730)
        self.progress_bar.pack(padx=10, pady=10)
        self.progress_bar.set(0)
        
        self.progress_label = ctk.CTkLabel(
            self.progress_frame, 
            text="Ready to process", 
            font=("Roboto", 11)
        )
        self.progress_label.pack(pady=5)

        # 5. Action Button
        self.btn_analyze = ctk.CTkButton(
            self, 
            text="EXTRACT 36 FEATURES & GENERATE DATASET", 
            fg_color="#2CC985", 
            hover_color="#229C68", 
            text_color="black", 
            width=830, 
            height=45, 
            font=("Roboto", 14, "bold"),
            command=self.start_thread
        )
        self.btn_analyze.pack(pady=10)

        # 6. Logs
        self.textbox = ctk.CTkTextbox(self, width=830, height=400)
        self.textbox.pack(pady=5, padx=10)
        self.textbox.insert("0.0", "="*80 + "\n")
        self.textbox.insert("end", "UNSW-NB15 Feature Extraction & Analysis Tool\n")
        self.textbox.insert("end", "="*80 + "\n\n")
        self.textbox.insert("end", "Ready. Please select your PCAP and Ground Truth CSV files.\n\n")
        self.textbox.insert("end", "Features to be extracted:\n")
        self.textbox.insert("end", "  • 8 Time Dynamics features\n")
        self.textbox.insert("end", "  • 8 Header Invariants features\n")
        self.textbox.insert("end", "  • 4 Traffic Symmetry features\n")
        self.textbox.insert("end", "  • 6 Payload Dynamics features\n")
        self.textbox.insert("end", "  • 4 Velocity features\n")
        self.textbox.insert("end", "  • 6 Additional analysis features\n")
        self.textbox.insert("end", "  = 36 Total Features\n\n")
        self.textbox.configure(state="disabled")

    def log(self, message):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", message + "\n")
        self.textbox.see("end")
        self.textbox.configure(state="disabled")
        self.update_idletasks()

    def update_progress(self, value, message=""):
        self.progress_bar.set(value)
        if message:
            self.progress_label.configure(text=message)
        self.update_idletasks()

    def browse_file(self, entry_widget, file_type):
        if file_type == "pcap":
            ftypes = [("PCAP Files", "*.pcap"), ("PCAPNG Files", "*.pcapng"), ("All Files", "*.*")]
        else:
            ftypes = [("CSV Files", "*.csv"), ("All Files", "*.*")]
        
        file_path = ctk.filedialog.askopenfilename(filetypes=ftypes)
        if file_path:
            entry_widget.delete(0, "end")
            entry_widget.insert(0, file_path)
            
            # Show file info
            file_size = os.path.getsize(file_path) / 1024 / 1024
            self.log(f"Selected: {os.path.basename(file_path)} ({file_size:.2f} MB)")

    def start_thread(self):
        pcap = self.entry_pcap.get()
        gt = self.entry_gt.get()
        
        if not pcap or not gt:
            self.log("❌ Error: Both PCAP and Ground Truth files are required.")
            return
        
        if not os.path.exists(pcap):
            self.log(f"❌ Error: PCAP file not found: {pcap}")
            return
            
        if not os.path.exists(gt):
            self.log(f"❌ Error: Ground Truth file not found: {gt}")
            return
        
        self.btn_analyze.configure(state="disabled", text="PROCESSING...")
        self.update_progress(0, "Initializing...")
        threading.Thread(target=self.run_analysis, args=(pcap, gt), daemon=True).start()

    def run_analysis(self, pcap_file, gt_file):
        try:
            self.log("\n" + "="*80)
            self.log("STARTING FEATURE EXTRACTION")
            self.log("="*80 + "\n")
            
            # 1. Load Ground Truth
            self.update_progress(0.05, "Loading Ground Truth...")
            gt_lookup = {}
            self.log(f"[1/5] Loading Ground Truth: {os.path.basename(gt_file)}...")
            
            try:
                required_cols = ['Attack category', 'Protocol', 'Source IP', 'Destination IP', 
                               'Source Port', 'Destination Port', 'Start time', 'Last time']
                df_gt = pd.read_csv(gt_file, usecols=required_cols, encoding='latin-1')
                df_gt.columns = df_gt.columns.str.strip().str.lower().str.replace(' ', '_')

                for _, row in df_gt.iterrows():
                    proto = str(row['protocol']).lower().strip()
                    key = (
                        str(row['source_ip']).strip(), 
                        int(row['source_port']), 
                        str(row['destination_ip']).strip(), 
                        int(row['destination_port']), 
                        proto
                    )
                    
                    attack_name = str(row['attack_category']).strip()
                    if attack_name.lower() == 'nan' or attack_name == '':
                        attack_name = 'Normal'
                    
                    gt_lookup[key] = {
                        'label': attack_name,
                        'start': row['start_time'],
                        'end': row['last_time']
                    }
                    
                self.log(f"✓ Loaded {len(gt_lookup)} unique flows from Ground Truth\n")

            except Exception as e:
                self.log(f"❌ CRITICAL GT ERROR: {e}")
                self.btn_analyze.configure(state="normal", text="EXTRACT 36 FEATURES & GENERATE DATASET")
                return

            # 2. Initialize Flow Tracker
            self.update_progress(0.1, "Initializing Flow Tracker...")
            self.log(f"[2/5] Initializing Flow Tracker...")
            tracker = LightweightFlowTracker(timeout=120)
            self.log("✓ Flow Tracker initialized\n")

            # 3. Process PCAP
            self.update_progress(0.15, "Reading PCAP file...")
            self.log(f"[3/5] Processing PCAP: {os.path.basename(pcap_file)}...")
            
            packet_count = 0
            proto_map = {6: 'tcp', 17: 'udp'}
            
            try:
                for pkt in PcapReader(pcap_file):
                    tracker.process_packet(pkt)
                    packet_count += 1
                    
                    if packet_count % 10000 == 0:
                        progress = 0.15 + (0.5 * min(packet_count / 100000, 1.0))
                        self.update_progress(progress, f"Processed {packet_count:,} packets...")
                        self.log(f"  Processed {packet_count:,} packets...")
                
                self.log(f"✓ Completed processing {packet_count:,} packets\n")
                
            except Exception as e:
                self.log(f"❌ PCAP Processing Error: {e}")
                self.btn_analyze.configure(state="normal", text="EXTRACT 36 FEATURES & GENERATE DATASET")
                return

            # 4. Extract Features
            self.update_progress(0.7, "Extracting features from flows...")
            self.log(f"[4/5] Extracting 36 features from {len(tracker.flows)} flows...")
            
            features_list = tracker.get_all_features()
            df_features = pd.DataFrame(features_list)
            
            self.log(f"✓ Extracted features from {len(df_features)} flows\n")

            # 5. Match with Ground Truth Labels
            self.update_progress(0.8, "Matching with Ground Truth labels...")
            self.log(f"[5/5] Matching flows with Ground Truth labels...")
            
            # Add labels
            labels = []
            matched_count = 0
            
            for idx, row in df_features.iterrows():
                src_ip = row['src_ip']
                sport = int(row['sport'])
                dst_ip = row['dst_ip']
                dport = int(row['dport'])
                
                # Determine protocol
                if row['proto'] == 6:
                    proto = 'tcp'
                elif row['proto'] == 17:
                    proto = 'udp'
                else:
                    proto = 'other'
                
                # Try both directions
                key1 = (src_ip, sport, dst_ip, dport, proto)
                key2 = (dst_ip, dport, src_ip, sport, proto)
                
                label = "Normal"
                if key1 in gt_lookup:
                    label = gt_lookup[key1]['label']
                    matched_count += 1
                elif key2 in gt_lookup:
                    label = gt_lookup[key2]['label']
                    matched_count += 1
                
                labels.append(label)
            
            df_features['label'] = labels
            
            self.log(f"✓ Matched {matched_count} flows with Ground Truth")
            self.log(f"✓ Remaining {len(df_features) - matched_count} flows labeled as 'Normal'\n")

            # 6. Get Performance Statistics
            self.update_progress(0.9, "Calculating performance statistics...")
            perf_stats = tracker.get_performance_stats()
            
            self.log("="*80)
            self.log("PERFORMANCE STATISTICS")
            self.log("="*80)
            self.log(f"Total packets processed:     {perf_stats['total_packets']:,}")
            self.log(f"Total flows extracted:       {perf_stats['total_flows']:,}")
            self.log(f"Processing time:             {perf_stats['elapsed_time']:.2f} seconds")
            self.log(f"Throughput:                  {perf_stats['packets_per_second']:.0f} packets/second")
            self.log(f"Avg processing time:         {perf_stats['avg_processing_time_ms']:.4f} ms/packet")
            self.log(f"Max processing time:         {perf_stats['max_processing_time_ms']:.4f} ms/packet")
            self.log(f"Memory usage:                {perf_stats['memory_mb']:.2f} MB")
            self.log("="*80 + "\n")

            # 7. Raspberry Pi Feasibility Analysis
            self.log("="*80)
            self.log("RASPBERRY PI FEASIBILITY ANALYSIS")
            self.log("="*80)
            
            rpi3_cpu_factor = 0.3
            rpi4_cpu_factor = 0.6
            
            current_pps = perf_stats['packets_per_second']
            rpi3_est_pps = current_pps * rpi3_cpu_factor
            rpi4_est_pps = current_pps * rpi4_cpu_factor
            
            self.log(f"\nEstimated Throughput:")
            self.log(f"  Current machine:             {current_pps:.0f} packets/second")
            self.log(f"  Raspberry Pi 3B+ (est):      {rpi3_est_pps:.0f} packets/second")
            self.log(f"  Raspberry Pi 4 (est):        {rpi4_est_pps:.0f} packets/second")
            
            typical_home = 100
            small_office = 1000
            
            self.log(f"\nNetwork Capacity Analysis:")
            self.log(f"  Home network (~100 pps):")
            self.log(f"    → RPi 3B+ headroom:        {rpi3_est_pps/typical_home:.1f}x")
            self.log(f"    → RPi 4 headroom:          {rpi4_est_pps/typical_home:.1f}x")
            
            self.log(f"\n  Small office (~1000 pps):")
            self.log(f"    → RPi 3B+ headroom:        {rpi3_est_pps/small_office:.1f}x")
            self.log(f"    → RPi 4 headroom:          {rpi4_est_pps/small_office:.1f}x")
            
            self.log(f"\nFeasibility Verdict:")
            if rpi4_est_pps > small_office:
                self.log("  ✓ Raspberry Pi 4: FEASIBLE for home and small office deployments")
            else:
                self.log("  ✓ Raspberry Pi 4: FEASIBLE for home networks")
            
            if rpi3_est_pps > typical_home:
                self.log("  ✓ Raspberry Pi 3B+: FEASIBLE for home networks")
            else:
                self.log("  ⚠ Raspberry Pi 3B+: Limited capacity")
            
            self.log("="*80 + "\n")

            # 8. Save Output
            self.update_progress(0.95, "Saving results...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"UNSW_NB15_36Features_{timestamp}.csv"
            
            # Reorder columns
            cols = list(df_features.columns)
            if 'label' in cols:
                cols.remove('label')
                cols.append('label')
            df_features = df_features[cols]
            
            df_features.to_csv(output_file, index=False)
            
            self.log("="*80)
            self.log("DATASET GENERATED SUCCESSFULLY")
            self.log("="*80)
            self.log(f"Output file:                 {output_file}")
            self.log(f"Total flows:                 {len(df_features):,}")
            self.log(f"Total features:              36 (+ 5 identifiers)")
            self.log(f"File size:                   {os.path.getsize(output_file) / 1024:.2f} KB")
            self.log(f"\nLabel Distribution:")
            
            label_counts = df_features['label'].value_counts()
            for label, count in label_counts.items():
                percentage = (count / len(df_features)) * 100
                self.log(f"  {label:25s}: {count:6,} ({percentage:5.2f}%)")
            
            self.log("="*80 + "\n")
            
            # 9. Feature Analysis Summary
            self.log("="*80)
            self.log("FEATURE EXTRACTION SUMMARY")
            self.log("="*80)
            
            feature_groups = {
                'Time Dynamics': ['iat_mean', 'iat_std', 'iat_min', 'iat_max', 
                                 'flow_duration', 'active_time_mean', 'idle_time_mean', 'fwd_iat_mean'],
                'Header Invariants': ['ttl_mean', 'ttl_std', 'win_size_mean', 'win_size_std',
                                     'syn_count', 'urg_count', 'fin_ratio', 'header_len_mean'],
                'Traffic Symmetry': ['pkt_ratio', 'byte_ratio', 'size_asymmetry', 'response_rate'],
                'Payload Dynamics': ['pkt_len_mean', 'pkt_len_std', 'pkt_len_var_coeff',
                                    'small_pkt_ratio', 'large_pkt_ratio', 'header_payload_ratio'],
                'Velocity': ['flow_pps', 'flow_bps', 'fwd_bps', 'bwd_pps']
            }
            
            for group_name, features in feature_groups.items():
                available = [f for f in features if f in df_features.columns]
                self.log(f"\n{group_name} ({len(available)} features):")
                for feat in available:
                    mean_val = df_features[feat].mean()
                    std_val = df_features[feat].std()
                    self.log(f"  {feat:25s}: mean={mean_val:12.4f}, std={std_val:12.4f}")
            
            self.log("\n" + "="*80)
            self.log("✓ ANALYSIS COMPLETE!")
            self.log("="*80 + "\n")
            
            self.update_progress(1.0, "✓ Processing complete!")
            
        except Exception as e:
            self.log(f"\n❌ FATAL ERROR: {e}")
            import traceback
            self.log(traceback.format_exc())
        
        finally:
            self.btn_analyze.configure(state="normal", text="EXTRACT 36 FEATURES & GENERATE DATASET")


if __name__ == "__main__":
    app = PacketToolApp()
    app.mainloop()
