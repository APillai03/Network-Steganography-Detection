import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
import pickle
from collections import defaultdict
from datetime import datetime
import threading
import queue
import time

class RealtimeSteganographyDetector:
    """Real-time network steganography detection"""
    
    def __init__(self, model_path, scaler_path, sequence_length=50):
        print("🔧 Initializing Real-Time Detector...")
        
        # Load trained model
        self.model = tf.keras.models.load_model(model_path)
        print(f"✓ Model loaded: {model_path}")
        
        # Load scaler
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        print(f"✓ Scaler loaded: {scaler_path}")
        
        self.sequence_length = sequence_length
        self.n_features = 13
        
        # Flow tracking
        self.flow_dict = defaultdict(list)
        self.flow_timestamps = defaultdict(lambda: time.time())
        self.flow_timeout = 60  # seconds
        
        # Statistics
        self.total_packets = 0
        self.total_flows = 0
        self.threats_detected = 0
        
        # Threading
        self.packet_queue = queue.Queue(maxsize=10000)
        self.running = False
        
        print("✅ Detector ready!\n")
    
    def extract_sequence_features(self, packet):
        """Extract 13 features from packet (same as training)"""
        features = []
        
        try:
            if IP in packet:
                features.append(min(len(packet) / 1500.0, 1.0))
                features.append(packet[IP].ttl / 255.0)
                features.append(int(packet[IP].flags) / 7.0)
                features.append((packet[IP].id % 1000) / 1000.0)
                
                if TCP in packet:
                    features.append(packet[TCP].sport / 65535.0)
                    features.append(packet[TCP].dport / 65535.0)
                    features.append(int(packet[TCP].flags) / 63.0)
                    features.append(packet[TCP].window / 65535.0)
                    
                    payload_len = len(packet[TCP].payload)
                    features.append(min(payload_len / 1500.0, 1.0))
                    features.append(min(float(len(packet[TCP].options)) / 10.0, 1.0))
                    features.append(self._payload_entropy(bytes(packet[TCP].payload)))
                    features.extend([0.0, 0.0])
                    
                elif UDP in packet:
                    features.append(packet[UDP].sport / 65535.0)
                    features.append(packet[UDP].dport / 65535.0)
                    payload_len = len(packet[UDP].payload)
                    features.append(min(payload_len / 1500.0, 1.0))
                    features.extend([0.0, 0.0, 0.0, 0.0, 0.0])
                else:
                    features.extend([0.0] * 10)
                
                features.append(1.0 if ICMP in packet else 0.0)
                features.append(1.0 if DNS in packet else 0.0)
            else:
                features = [0.0] * 13
        except:
            features = [0.0] * 13
        
        return np.array(features[:13])
    
    def _payload_entropy(self, payload):
        """Calculate Shannon entropy"""
        if not payload or len(payload) == 0:
            return 0.0
        from scipy.stats import entropy
        byte_counts = np.bincount(list(payload), minlength=256)
        probabilities = byte_counts[byte_counts > 0] / len(payload)
        ent = entropy(probabilities, base=2) / 8.0
        return min(ent, 1.0)
    
    def get_flow_key(self, packet):
        """Generate flow identifier"""
        if IP not in packet:
            return None
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = 0
            dst_port = 0
        
        # Bidirectional flow key
        flow_key = tuple(sorted([
            (src_ip, src_port, proto),
            (dst_ip, dst_port, proto)
        ]))
        
        return flow_key
    
    def packet_handler(self, packet):
        """Handle captured packet"""
        try:
            self.packet_queue.put(packet, timeout=0.1)
        except queue.Full:
            pass  # Drop packet if queue full
    
    def process_packets(self):
        """Process packets from queue"""
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                
                self.total_packets += 1
                
                # Get flow key
                flow_key = self.get_flow_key(packet)
                if not flow_key:
                    continue
                
                # Extract features
                features = self.extract_sequence_features(packet)
                
                # Add to flow
                self.flow_dict[flow_key].append(features)
                self.flow_timestamps[flow_key] = time.time()
                
                # Check if flow has enough packets for inference
                if len(self.flow_dict[flow_key]) >= self.sequence_length:
                    self.analyze_flow(flow_key)
                
                # Cleanup old flows
                if self.total_packets % 1000 == 0:
                    self.cleanup_old_flows()
                
                # Print stats every 100 packets
                if self.total_packets % 100 == 0:
                    self.print_stats()
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"❌ Error processing packet: {e}")
    
    def analyze_flow(self, flow_key):
        """Analyze flow and detect steganography"""
        packets = self.flow_dict[flow_key]
        
        # Prepare sequence
        if len(packets) < self.sequence_length:
            # Pad with zeros
            packets = packets + [np.zeros(13)] * (self.sequence_length - len(packets))
        else:
            # Take last sequence_length packets
            packets = packets[-self.sequence_length:]
        
        sequence = np.array(packets).reshape(1, self.sequence_length, self.n_features)
        
        # Normalize
        seq_reshaped = sequence.reshape(-1, self.n_features)
        seq_scaled = self.scaler.transform(seq_reshaped)
        sequence = seq_scaled.reshape(1, self.sequence_length, self.n_features)
        
        # Predict
        prediction = self.model.predict(sequence, verbose=0)[0][0]
        
        if prediction > 0.5:  # Threshold
            self.threats_detected += 1
            self.log_threat(flow_key, prediction)
    
    def log_threat(self, flow_key, confidence):
        """Log detected threat"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        flow_str = f"{flow_key[0][0]}:{flow_key[0][1]} ↔ {flow_key[1][0]}:{flow_key[1][1]}"
        
        # Console alert
        print(f"\n🚨 THREAT DETECTED!")
        print(f"   Time: {timestamp}")
        print(f"   Flow: {flow_str}")
        print(f"   Confidence: {confidence:.4f} ({confidence*100:.2f}%)")
        print(f"   Protocol: {flow_key[0][2]}")
        
        # Write to log file
        with open('threat_log.txt', 'a') as f:
            f.write(f"{timestamp} | {flow_str} | Confidence: {confidence:.4f}\n")
    
    def cleanup_old_flows(self):
        """Remove flows that haven't seen packets recently"""
        current_time = time.time()
        to_delete = []
        
        for flow_key, last_time in self.flow_timestamps.items():
            if current_time - last_time > self.flow_timeout:
                to_delete.append(flow_key)
        
        for flow_key in to_delete:
            del self.flow_dict[flow_key]
            del self.flow_timestamps[flow_key]
    
    def print_stats(self):
        """Print statistics"""
        print(f"\r📊 Packets: {self.total_packets:,} | "
              f"Flows: {len(self.flow_dict)} | "
              f"Threats: {self.threats_detected}", end='', flush=True)
    
    def start(self, interface=None):
        """Start real-time detection"""
        print("="*70)
        print(" 🚀 STARTING REAL-TIME STEGANOGRAPHY DETECTION")
        print("="*70)
        print(f"Interface: {interface if interface else 'Default'}")
        print(f"Sequence Length: {self.sequence_length}")
        print(f"Detection Threshold: 0.5")
        print("="*70)
        print("\n⏳ Capturing packets... (Press Ctrl+C to stop)\n")
        
        self.running = True
        
        # Start processing thread
        processing_thread = threading.Thread(target=self.process_packets, daemon=True)
        processing_thread.start()
        
        try:
            # Start packet capture
            sniff(
                iface=interface,
                prn=self.packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            print("\n\n⏸️  Stopping detection...")
            self.running = False
            processing_thread.join(timeout=2)
            
            print("\n" + "="*70)
            print(" 📈 FINAL STATISTICS")
            print("="*70)
            print(f"Total Packets: {self.total_packets:,}")
            print(f"Total Flows: {len(self.flow_dict)}")
            print(f"Threats Detected: {self.threats_detected}")
            print("="*70)


def main():
    """Main execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real-time Steganography Detection')
    parser.add_argument('--model', type=str, required=True, help='Path to trained model (.h5)')
    parser.add_argument('--scaler', type=str, required=True, help='Path to scaler (.pkl)')
    parser.add_argument('--interface', type=str, default=None, help='Network interface (e.g., eth0, wlan0)')
    parser.add_argument('--sequence-length', type=int, default=50, help='Sequence length (default: 50)')
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = RealtimeSteganographyDetector(
        model_path=args.model,
        scaler_path=args.scaler,
        sequence_length=args.sequence_length
    )
    
    # Start detection
    detector.start(interface=args.interface)


if __name__ == "__main__":
    main()