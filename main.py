import customtkinter as ctk
import threading
import pandas as pd
import numpy as np
import os
import time
from collections import defaultdict, deque
from scapy.all import PcapReader, IP, TCP, UDP

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class LightweightFlowTracker:
    """
    Memory-efficient flow tracker tailored for Raspberry Pi.
    Extracts 30 specific adversarial defense features with precise cost tracking.
    """
    
    def __init__(self, timeout=120):
        self.flows = {}
        self.timeout = timeout
        self.packet_count = 0
        self.start_time = None
        
        # Computational Cost Tracking (Nanoseconds)
        self.cost_accumulators = defaultdict(float)
        self.cost_counts = defaultdict(int)

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
        
        # Canonical bidirectional key (A->B and B->A share the same key)
        if (src_ip, sport) < (dst_ip, dport):
            return (src_ip, sport, dst_ip, dport, proto)
        else:
            return (dst_ip, dport, src_ip, sport, proto)

    def process_packet(self, pkt):
        """Process a single packet and update flow stats."""
        if self.start_time is None:
            self.start_time = time.time()
            
        flow_key = self.get_flow_key(pkt)
        if flow_key is None:
            return

        timestamp = float(pkt.time)
        pkt_len = len(pkt)
        
        # Initialize flow if new
        if flow_key not in self.flows:
            src_ip, sport, dst_ip, dport, proto = flow_key
            self.flows[flow_key] = {
                # Identifiers
                'src_ip': src_ip, 'sport': sport,
                'dst_ip': dst_ip, 'dport': dport, 'proto': proto,
                
                # Basics
                'start_time': timestamp, 'last_time': timestamp,
                'fwd_pkts': 0, 'bwd_pkts': 0,
                'fwd_bytes': 0, 'bwd_bytes': 0,
                
                # RASPBERRY PI OPTIMIZATION: Use deque with maxlen
                # This ensures we never store more than 100 items per flow.
                'timestamps': deque(maxlen=100),
                'pkt_lengths': deque(maxlen=100),
                'header_lengths': deque(maxlen=100),
                'ttl_values': deque(maxlen=100),
                'window_sizes': deque(maxlen=100),
                'fwd_iats': deque(maxlen=100),
                'active_periods': deque(maxlen=100),
                'idle_periods': deque(maxlen=100),
                
                # Counters
                'syn_count': 0, 'urg_count': 0, 'fin_count': 0,
                
                # State trackers
                'last_fwd_time': None, 'last_bwd_time': None,
                'active_start': timestamp
            }
            # Initial append
            self.flows[flow_key]['timestamps'].append(timestamp)

        flow = self.flows[flow_key]
        src_ip, sport, dst_ip, dport, proto = flow_key
        
        # Update Direction
        direction = 'fwd' if pkt[IP].src == src_ip else 'bwd'
        
        # Update Lists
        flow['pkt_lengths'].append(pkt_len)
        flow['timestamps'].append(timestamp)
        
        # Traffic Volume
        if direction == 'fwd':
            flow['fwd_pkts'] += 1
            flow['fwd_bytes'] += pkt_len
            if flow['last_fwd_time']:
                flow['fwd_iats'].append(timestamp - flow['last_fwd_time'])
            flow['last_fwd_time'] = timestamp
        else:
            flow['bwd_pkts'] += 1
            flow['bwd_bytes'] += pkt_len
            flow['last_bwd_time'] = timestamp

        # Active/Idle Logic
        if flow['last_time']:
            gap = timestamp - flow['last_time']
            if gap > 1.0: # Idle threshold > 1s
                flow['idle_periods'].append(gap)
                if flow['active_start']:
                    active = flow['last_time'] - flow['active_start']
                    if active > 0: flow['active_periods'].append(active)
                flow['active_start'] = timestamp
        
        flow['last_time'] = timestamp
        
        # Header Features
        if IP in pkt:
            flow['ttl_values'].append(pkt[IP].ttl)
            # IP Header Length (IHL is in 32-bit words, so * 4)
            ip_header_len = pkt[IP].ihl * 4 if hasattr(pkt[IP], 'ihl') else 20
            flow['header_lengths'].append(ip_header_len)

        if TCP in pkt:
            if pkt[TCP].flags & 0x02: flow['syn_count'] += 1 # SYN
            if pkt[TCP].flags & 0x20: flow['urg_count'] += 1 # URG
            if pkt[TCP].flags & 0x01: flow['fin_count'] += 1 # FIN
            flow['window_sizes'].append(pkt[TCP].window)
            
        self.packet_count += 1

    def measure_block(self, name, func):
        """Execute a function and measure its time in nanoseconds."""
        t0 = time.perf_counter_ns()
        result = func()
        t1 = time.perf_counter_ns()
        self.cost_accumulators[name] += (t1 - t0)
        self.cost_counts[name] += 1
        return result

    def extract_features(self, flow_key):
        """Extract the 30 specific features with cost measurement."""
        flow = self.flows[flow_key]
        features = {}

        # 0. Identifiers (No cost tracking needed)
        features['src_ip'] = flow['src_ip']
        features['dst_ip'] = flow['dst_ip']
        features['sport'] = flow['sport']
        features['dport'] = flow['dport']
        features['proto'] = flow['proto']

        # --- PREPARATION ---
        # Convert deques to lists once for calculations (small overhead)
        ts = list(flow['timestamps'])
        dur = max(flow['last_time'] - flow['start_time'], 1e-6)
        total_pkts = flow['fwd_pkts'] + flow['bwd_pkts']
        total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']

        # 1. Time Dynamics (Rhythm)
        def calc_time_dynamics():
            iats = [ts[i+1] - ts[i] for i in range(len(ts)-1)] if len(ts) > 1 else [0]
            return {
                'iat_mean': np.mean(iats),
                'iat_std': np.std(iats),
                'iat_min': np.min(iats),
                'iat_max': np.max(iats),
                'flow_duration': dur,
                'active_time_mean': np.mean(flow['active_periods']) if flow['active_periods'] else 0,
                'idle_time_mean': np.mean(flow['idle_periods']) if flow['idle_periods'] else 0,
                'fwd_iat_mean': np.mean(flow['fwd_iats']) if flow['fwd_iats'] else 0
            }
        features.update(self.measure_block('Time_Dynamics', calc_time_dynamics))

        # 2. Header Invariants (Spoofing)
        def calc_header_invariants():
            ttls = list(flow['ttl_values'])
            wins = list(flow['window_sizes'])
            return {
                'ttl_mean': np.mean(ttls) if ttls else 0,
                'ttl_std': np.std(ttls) if ttls else 0,
                'win_size_mean': np.mean(wins) if wins else 0,
                'win_size_std': np.std(wins) if wins else 0,
                'syn_count': flow['syn_count'],
                'urg_count': flow['urg_count'],
                'fin_ratio': flow['fin_count'] / total_pkts if total_pkts > 0 else 0,
                'header_len_mean': np.mean(flow['header_lengths']) if flow['header_lengths'] else 0
            }
        features.update(self.measure_block('Header_Invariants', calc_header_invariants))

        # 3. Traffic Symmetry (Interaction)
        def calc_symmetry():
            return {
                'pkt_ratio': flow['fwd_pkts'] / (flow['bwd_pkts'] + 1),
                'byte_ratio': flow['fwd_bytes'] / (total_bytes + 1),
                'size_asymmetry': abs(flow['fwd_bytes'] - flow['bwd_bytes']) / (total_bytes + 1),
                'response_rate': flow['bwd_pkts'] / dur
            }
        features.update(self.measure_block('Traffic_Symmetry', calc_symmetry))

        # 4. Payload Dynamics (Padding)
        def calc_payload():
            pkt_lens = list(flow['pkt_lengths'])
            mean_len = np.mean(pkt_lens) if pkt_lens else 0
            std_len = np.std(pkt_lens) if pkt_lens else 0
            return {
                'pkt_len_mean': mean_len,
                'pkt_len_std': std_len,
                'pkt_len_var_coeff': (std_len / (mean_len + 1e-6)),
                'small_pkt_ratio': sum(1 for x in pkt_lens if x < 64) / len(pkt_lens) if pkt_lens else 0,
                'large_pkt_ratio': sum(1 for x in pkt_lens if x > 1200) / len(pkt_lens) if pkt_lens else 0,
                'header_payload_ratio': sum(flow['header_lengths']) / (total_bytes - sum(flow['header_lengths']) + 1)
            }
        features.update(self.measure_block('Payload_Dynamics', calc_payload))

        # 5. Velocity (Load)
        def calc_velocity():
            return {
                'flow_pps': total_pkts / dur,
                'flow_bps': total_bytes * 8 / dur,
                'fwd_bps': flow['fwd_bytes'] * 8 / dur,
                'bwd_pps': flow['bwd_pkts'] / dur
            }
        features.update(self.measure_block('Velocity', calc_velocity))

        return features

    def get_avg_costs(self):
        """Return average cost per feature group in microseconds."""
        avg_costs = {}
        for key, total_ns in self.cost_accumulators.items():
            count = self.cost_counts[key]
            if count > 0:
                avg_costs[key] = (total_ns / count) / 1000.0  # ns to us
        return avg_costs

    def get_all_features(self):
        return [self.extract_features(fk) for fk in self.flows.keys()]

class PacketToolApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Raspberry Pi NIDS Feature Extractor & Labeler")
        self.geometry("900x700")
        
        # --- UI LAYOUT ---
        self.grid_columnconfigure(0, weight=1)
        
        self.lbl_title = ctk.CTkLabel(self, text="NIDS Feature Extractor + GT Labeler", font=("Arial", 20, "bold"))
        self.lbl_title.grid(row=0, column=0, pady=20)

        # File Inputs
        self.frame_files = ctk.CTkFrame(self)
        self.frame_files.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        # PCAP Input
        self.entry_pcap = ctk.CTkEntry(self.frame_files, placeholder_text="Select PCAP File...", width=500)
        self.entry_pcap.grid(row=0, column=0, padx=10, pady=10)
        self.btn_pcap = ctk.CTkButton(self.frame_files, text="Browse PCAP", command=lambda: self.browse_file(self.entry_pcap, "pcap"))
        self.btn_pcap.grid(row=0, column=1, padx=10, pady=10)

        # Ground Truth Input
        self.entry_gt = ctk.CTkEntry(self.frame_files, placeholder_text="Select Ground Truth CSV...", width=500)
        self.entry_gt.grid(row=1, column=0, padx=10, pady=10)
        self.btn_gt = ctk.CTkButton(self.frame_files, text="Browse CSV", command=lambda: self.browse_file(self.entry_gt, "csv"))
        self.btn_gt.grid(row=1, column=1, padx=10, pady=10)

        # Process Button
        self.btn_process = ctk.CTkButton(self, text="EXTRACT, LABEL & ANALYZE COSTS", 
                                         fg_color="#2CC985", text_color="black", height=50, font=("Arial", 14, "bold"),
                                         command=self.start_processing)
        self.btn_process.grid(row=2, column=0, padx=20, pady=20, sticky="ew")

        # Log Window
        self.textbox = ctk.CTkTextbox(self, height=400)
        self.textbox.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")
        self.log("Ready. Please select both PCAP and Ground Truth files.")

    def log(self, msg):
        self.textbox.insert("end", msg + "\n")
        self.textbox.see("end")

    def browse_file(self, entry, ftype):
        if ftype == "pcap":
            filetypes = [("PCAP Files", "*.pcap"), ("PCAPNG", "*.pcapng")]
        else:
            filetypes = [("CSV Files", "*.csv")]
            
        filename = ctk.filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            entry.delete(0, "end")
            entry.insert(0, filename)
            self.log(f"Selected {ftype.upper()}: {os.path.basename(filename)}")

    def start_processing(self):
        pcap_path = self.entry_pcap.get()
        gt_path = self.entry_gt.get()
        
        if not os.path.exists(pcap_path) or not os.path.exists(gt_path):
            self.log("Error: Please select both valid files.")
            return
        
        self.btn_process.configure(state="disabled", text="Processing...")
        threading.Thread(target=self.run_logic, args=(pcap_path, gt_path), daemon=True).start()

    def run_logic(self, pcap_path, gt_path):
        tracker = LightweightFlowTracker()
        self.log("-" * 60)
        
        try:
            # 1. Load Ground Truth
            self.log("[1/4] Loading Ground Truth Labels...")
            gt_lookup = {}
            try:
                # Assuming UNSW-NB15 standard columns
                df_gt = pd.read_csv(gt_path, encoding='latin-1')
                # Normalize column names
                df_gt.columns = df_gt.columns.str.strip().str.lower().str.replace(' ', '_')
                
                required = ['source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol', 'attack_category']
                if not all(col in df_gt.columns for col in required):
                    self.log("Warning: GT CSV missing standard columns. Trying to proceed anyway...")

                for _, row in df_gt.iterrows():
                    # Create a unique key for the connection
                    key = (
                        str(row['source_ip']).strip(),
                        int(row['source_port']),
                        str(row['destination_ip']).strip(),
                        int(row['destination_port']),
                        str(row['protocol']).lower().strip()
                    )
                    
                    label = str(row['attack_category']).strip()
                    if label.lower() in ['nan', '', ' ']:
                        label = 'Normal'
                    
                    gt_lookup[key] = label
                
                self.log(f"✓ Loaded {len(gt_lookup)} labeled flows from GT file.")

            except Exception as e:
                self.log(f"❌ Error loading GT: {e}")
                return

            # 2. Process PCAP
            self.log("[2/4] Reading PCAP and Extracting Features...")
            count = 0
            for pkt in PcapReader(pcap_path):
                tracker.process_packet(pkt)
                count += 1
                if count % 5000 == 0:
                    self.log(f"   Processed {count} packets...")
            
            self.log(f"✓ Finished reading. Total flows extracted: {len(tracker.flows)}")

            # 3. Match Labels
            self.log("[3/4] Matching Flows to Labels...")
            feature_list = tracker.get_all_features()
            df = pd.DataFrame(feature_list)
            
            final_labels = []
            matched_count = 0
            
            for idx, row in df.iterrows():
                # Reconstruct keys to check against GT dictionary
                src = row['src_ip']
                dst = row['dst_ip']
                sport = int(row['sport'])
                dport = int(row['dport'])
                
                # Proto mapping (scapy uses int, GT usually uses string)
                proto_num = row['proto']
                if proto_num == 6: proto_str = 'tcp'
                elif proto_num == 17: proto_str = 'udp'
                else: proto_str = 'other' # Simplify for now
                
                # Check Forward Direction
                key_fwd = (src, sport, dst, dport, proto_str)
                # Check Backward Direction
                key_bwd = (dst, dport, src, sport, proto_str)
                
                if key_fwd in gt_lookup:
                    final_labels.append(gt_lookup[key_fwd])
                    matched_count += 1
                elif key_bwd in gt_lookup:
                    final_labels.append(gt_lookup[key_bwd])
                    matched_count += 1
                else:
                    final_labels.append("Normal") # Default if not found in Attack GT
            
            df['Label'] = final_labels
            self.log(f"✓ Matched {matched_count} flows to GT attacks.")
            self.log(f"✓ Labeled {len(df)-matched_count} flows as Normal.")

            # 4. Save Outputs
            self.log("[4/4] Saving Results...")
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            
            # Save Dataset
            dataset_file = f"Labeled_Dataset_{timestamp}.csv"
            df.to_csv(dataset_file, index=False)
            self.log(f"✓ Saved Labeled Dataset: {dataset_file}")

            # Save Cost Analysis
            costs = tracker.get_avg_costs()
            feature_groups = {
                'Time_Dynamics': ['iat_mean', 'iat_std', 'iat_min', 'iat_max', 'flow_duration', 'active_time_mean', 'idle_time_mean', 'fwd_iat_mean'],
                'Header_Invariants': ['ttl_mean', 'ttl_std', 'win_size_mean', 'win_size_std', 'syn_count', 'urg_count', 'fin_ratio', 'header_len_mean'],
                'Traffic_Symmetry': ['pkt_ratio', 'byte_ratio', 'size_asymmetry', 'response_rate'],
                'Payload_Dynamics': ['pkt_len_mean', 'pkt_len_std', 'pkt_len_var_coeff', 'small_pkt_ratio', 'large_pkt_ratio', 'header_payload_ratio'],
                'Velocity': ['flow_pps', 'flow_bps', 'fwd_bps', 'bwd_pps']
            }
            
            cost_data = []
            for group, feat_names in feature_groups.items():
                group_cost_us = costs.get(group, 0)
                per_feat_cost = group_cost_us / len(feat_names) if feat_names else 0
                
                for fname in feat_names:
                    cost_data.append({
                        'Feature_Name': fname,
                        'Group': group,
                        'Avg_Cost_Microseconds': round(per_feat_cost, 4),
                        'Pi_Status': 'SAFE' if per_feat_cost < 20 else 'CAUTION'
                    })
            
            cost_file = f"Feature_Costs_{timestamp}.csv"
            pd.DataFrame(cost_data).to_csv(cost_file, index=False)
            self.log(f"✓ Saved Cost Report: {cost_file}")
            
            self.log("\nALL TASKS COMPLETED SUCCESSFULLY.")
            
        except Exception as e:
            self.log(f"❌ Critical Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.btn_process.configure(state="normal", text="EXTRACT, LABEL & ANALYZE COSTS")

if __name__ == "__main__":
    app = PacketToolApp()
    app.mainloop()
