# security_monitor.py
import streamlit as st
import pandas as pd
import numpy as np
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go
import hashlib
import json
import time
import mmap
import concurrent.futures
from functools import lru_cache
import multiprocessing as mp

# Page config
st.set_page_config(
    page_title="Security Monitor Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS (sama seperti sebelumnya)
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e, #16213e);
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        border-bottom: 3px solid #e94560;
    }
    .stat-card {
        background: linear-gradient(135deg, #16213e, #0f3460);
        border-radius: 10px;
        padding: 1.5rem;
        text-align: center;
        border: 1px solid rgba(255,255,255,0.1);
    }
    .stat-number {
        font-size: 2.5rem;
        font-weight: bold;
        color: #e94560;
    }
    .stat-label {
        color: rgba(255,255,255,0.7);
        font-size: 0.9rem;
        margin-top: 0.5rem;
    }
    .alert-critical { border-left: 4px solid #e94560; padding-left: 1rem; }
    .alert-high { border-left: 4px solid #ff6b6b; padding-left: 1rem; }
    .alert-medium { border-left: 4px solid #ffd93d; padding-left: 1rem; }
    .alert-low { border-left: 4px solid #4ecca3; padding-left: 1rem; }
    .recommendation {
        background: rgba(78, 204, 163, 0.1);
        border-left: 3px solid #4ecca3;
        padding: 0.75rem 1rem;
        margin: 0.5rem 0;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

# ============ OPTIMIZED SECURITY MONITOR ============
class OptimizedSecurityMonitor:
    def __init__(self, log_file, max_size_gb=2.0):
        self.log_file = Path(log_file)
        self.max_size_bytes = max_size_gb * 1024 * 1024 * 1024
        self.logs = []
        self.alerts = []
        
        # Compile patterns once for speed
        self.sql_patterns = [
            re.compile(r'(?i)(union.*select|select.*from|insert.*into|delete.*from|update.*set|drop.*table|alter.*table)'),
            re.compile(r'(?i)(\'|\")(\s*or\s*|\s*and\s*)(\s*\'|\"\s*=\s*\'|\"\s*|\s*=\s*\d+)'),
            re.compile(r'(?i)(--|\#|\;|\|\||&&)'),
            re.compile(r'(?i)(benchmark|sleep|waitfor)')
        ]
        
        self.xss_patterns = [
            re.compile(r'(?i)<script.*?>.*?</script>'),
            re.compile(r'(?i)onerror\s*=|onload\s*=|onclick\s*='),
            re.compile(r'(?i)javascript\s*:'),
            re.compile(r'(?i)<img.*?src\s*=.*?alert'),
            re.compile(r'(?i)document\.cookie|alert\(|eval\(')
        ]
        
        self.path_traversal_patterns = [
            re.compile(r'\.\./\.\./'),
            re.compile(r'\.\.\\\.\.\\'),
            re.compile(r'\.\./\.\.%'),
            re.compile(r'%2e%2e%2f'),
            re.compile(r'%2e%2e\\')
        ]
        
        self.sensitive_files = [
            re.compile(r'\.env', re.IGNORECASE),
            re.compile(r'\.git/', re.IGNORECASE),
            re.compile(r'\.aws/', re.IGNORECASE),
            re.compile(r'\.ssh/', re.IGNORECASE),
            re.compile(r'config\.yml', re.IGNORECASE),
            re.compile(r'config\.yaml', re.IGNORECASE),
            re.compile(r'config\.json', re.IGNORECASE),
            re.compile(r'wp-config\.php', re.IGNORECASE),
            re.compile(r'\.htaccess', re.IGNORECASE),
            re.compile(r'\.htpasswd', re.IGNORECASE),
            re.compile(r'password', re.IGNORECASE),
            re.compile(r'secret', re.IGNORECASE),
            re.compile(r'key\.', re.IGNORECASE),
            re.compile(r'cert\.', re.IGNORECASE),
            re.compile(r'admin', re.IGNORECASE),
            re.compile(r'backup', re.IGNORECASE),
            re.compile(r'dump\.sql', re.IGNORECASE)
        ]
        
        self.suspicious_user_agents = [
            re.compile(r'(?i)nmap'),
            re.compile(r'(?i)sqlmap'),
            re.compile(r'(?i)nikto'),
            re.compile(r'(?i)wpscan'),
            re.compile(r'(?i)burp'),
            re.compile(r'(?i)zap'),
            re.compile(r'(?i)dirbuster'),
            re.compile(r'(?i)gobuster'),
            re.compile(r'(?i)masscan'),
            re.compile(r'(?i)openvas'),
            re.compile(r'(?i)nessus')
        ]
        
        # Log pattern compiled
        self.log_pattern = re.compile(
            r'(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\S+) "(.*?)" "(.*?)"'
        )

    def parse_log_line(self, line):
        """Parse a single log line"""
        match = self.log_pattern.match(line)
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'path': match.group(4),
                'protocol': match.group(5),
                'status': int(match.group(6)),
                'size': match.group(7) if match.group(7) != '-' else 0,
                'referer': match.group(8),
                'user_agent': match.group(9),
                'raw': line.strip()
            }
        return None

    def load_logs_fast(self, progress_callback=None):
        """Fast log loading using memory mapping and chunking"""
        file_size = self.log_file.stat().st_size
        chunk_size = 10 * 1024 * 1024  # 10MB chunks
        
        total_lines = 0
        self.logs = []
        
        with open(self.log_file, 'rb') as f:
            # Use memory mapping for speed
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                # Process in chunks
                for chunk_start in range(0, file_size, chunk_size):
                    chunk_end = min(chunk_start + chunk_size, file_size)
                    
                    # Read chunk
                    chunk = mm[chunk_start:chunk_end].decode('utf-8', errors='ignore')
                    
                    # Split into lines
                    lines = chunk.split('\n')
                    
                    # Handle partial lines (keep last partial for next chunk)
                    if chunk_end < file_size:
                        last_newline = chunk.rfind('\n')
                        if last_newline != -1:
                            lines = chunk[:last_newline].split('\n')
                    
                    # Parse each line
                    for line in lines:
                        if line.strip():
                            parsed = self.parse_log_line(line)
                            if parsed:
                                self.logs.append(parsed)
                                total_lines += 1
                    
                    # Update progress
                    if progress_callback:
                        progress = chunk_end / file_size
                        progress_callback(progress)
        
        if progress_callback:
            progress_callback(1.0)
        
        return self.logs

    def detect_sql_injection(self):
        """Optimized SQL injection detection"""
        alerts = []
        for log in self.logs:
            combined = f"{log['path']} {log.get('referer', '')}"
            for pattern in self.sql_patterns:
                if pattern.search(combined):
                    alerts.append({
                        'type': 'SQL Injection',
                        'ip': log['ip'],
                        'timestamp': log['timestamp'],
                        'path': log['path'][:100],
                        'details': f"SQL injection pattern detected",
                        'severity': 'Critical',
                        'mitre_id': 'T1190'
                    })
                    break
        return alerts

    def detect_xss(self):
        """Optimized XSS detection"""
        alerts = []
        for log in self.logs:
            combined = f"{log['path']} {log.get('referer', '')}"
            for pattern in self.xss_patterns:
                if pattern.search(combined):
                    alerts.append({
                        'type': 'XSS',
                        'ip': log['ip'],
                        'timestamp': log['timestamp'],
                        'path': log['path'][:100],
                        'details': f"XSS pattern detected",
                        'severity': 'High',
                        'mitre_id': 'T1059'
                    })
                    break
        return alerts

    def detect_path_traversal(self):
        """Optimized path traversal detection"""
        alerts = []
        for log in self.logs:
            for pattern in self.path_traversal_patterns:
                if pattern.search(log['path']):
                    alerts.append({
                        'type': 'Path Traversal',
                        'ip': log['ip'],
                        'timestamp': log['timestamp'],
                        'path': log['path'][:100],
                        'details': f"Path traversal detected",
                        'severity': 'High',
                        'mitre_id': 'T1006'
                    })
                    break
        return alerts

    def detect_sensitive_file_probing(self):
        """Optimized sensitive file probing detection"""
        alerts = []
        for log in self.logs:
            for pattern in self.sensitive_files:
                if pattern.search(log['path']):
                    alerts.append({
                        'type': 'Sensitive File Probing',
                        'ip': log['ip'],
                        'timestamp': log['timestamp'],
                        'path': log['path'][:100],
                        'details': f"Sensitive file access detected",
                        'severity': 'High',
                        'mitre_id': 'T1083'
                    })
                    break
        return alerts

    def detect_directory_scanning(self):
        """Optimized directory scanning detection"""
        ip_paths = defaultdict(list)
        for log in self.logs:
            if log['status'] in [404, 403]:
                ip_paths[log['ip']].append(log['path'])
        
        alerts = []
        for ip, paths in ip_paths.items():
            if len(paths) > 20:
                alerts.append({
                    'type': 'Directory Scanning',
                    'ip': ip,
                    'timestamp': datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z'),
                    'path': ', '.join(paths[:3]) + ('...' if len(paths) > 3 else ''),
                    'details': f"Accessed {len(paths)} error pages",
                    'severity': 'Medium',
                    'mitre_id': 'T1046'
                })
        return alerts

    def detect_suspicious_user_agent(self):
        """Optimized suspicious user-agent detection"""
        alerts = []
        for log in self.logs:
            ua = log.get('user_agent', '')
            for pattern in self.suspicious_user_agents:
                if pattern.search(ua):
                    alerts.append({
                        'type': 'Suspicious User-Agent',
                        'ip': log['ip'],
                        'timestamp': log['timestamp'],
                        'path': log['path'][:100],
                        'details': f"Suspicious user-agent detected",
                        'severity': 'Medium',
                        'mitre_id': 'T1595'
                    })
                    break
        return alerts

    def detect_brute_force(self):
        """Optimized brute force detection"""
        ip_failures = defaultdict(int)
        for log in self.logs:
            if ('login' in log['path'].lower() or 'auth' in log['path'].lower()):
                if log['status'] in [401, 403]:
                    ip_failures[log['ip']] += 1
        
        alerts = []
        for ip, failures in ip_failures.items():
            if failures > 10:
                alerts.append({
                    'type': 'Brute Force',
                    'ip': ip,
                    'timestamp': datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z'),
                    'path': '/login',
                    'details': f"{failures} failed login attempts",
                    'severity': 'High',
                    'mitre_id': 'T1110'
                })
        return alerts

    def detect_request_rate_anomaly(self):
        """Optimized request rate anomaly detection"""
        ip_requests = defaultdict(list)
        for log in self.logs:
            try:
                dt = datetime.strptime(log['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
                ip_requests[log['ip']].append(dt)
            except:
                continue
        
        alerts = []
        for ip, times in ip_requests.items():
            if len(times) > 100 and len(times) > 1:
                time_diff = (times[-1] - times[0]).total_seconds() / 60
                rate = len(times) / time_diff if time_diff > 0 else len(times)
                if rate > 60:
                    alerts.append({
                        'type': 'Request Rate Anomaly',
                        'ip': ip,
                        'timestamp': times[-1].strftime('%d/%b/%Y:%H:%M:%S %z'),
                        'path': f'Rate: {rate:.1f} req/min',
                        'details': f"{len(times)} requests in {time_diff:.1f} minutes",
                        'severity': 'Medium',
                        'mitre_id': 'T1499'
                    })
        return alerts

    def calculate_ip_risk_score(self):
        """Optimized IP risk score calculation"""
        ip_scores = defaultdict(lambda: {'score': 0, 'factors': []})
        severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
        
        for alert in self.alerts:
            ip = alert['ip']
            weight = severity_weights.get(alert.get('severity', 'Low'), 1)
            ip_scores[ip]['score'] += weight
            ip_scores[ip]['factors'].append(alert['type'])
        
        risk_alerts = []
        max_score = max([data['score'] for data in ip_scores.values()]) if ip_scores else 1
        
        for ip, data in ip_scores.items():
            normalized_score = min(100, (data['score'] / max_score) * 100)
            risk_level = 'Critical' if normalized_score > 75 else 'High' if normalized_score > 50 else 'Medium' if normalized_score > 25 else 'Low'
            
            risk_alerts.append({
                'type': 'IP Risk Score',
                'ip': ip,
                'timestamp': datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z'),
                'path': f"Risk Score: {normalized_score:.1f}",
                'details': f"Score: {normalized_score:.1f}/100 - {risk_level}",
                'severity': risk_level,
                'mitre_id': 'TA0001'
            })
        
        return risk_alerts

    def correlate_events(self):
        """Optimized event correlation"""
        ip_events = defaultdict(list)
        for alert in self.alerts:
            ip_events[alert['ip']].append(alert)
        
        correlated = []
        for ip, events in ip_events.items():
            if len(events) >= 3:
                types = {e['type'] for e in events}
                
                if 'SQL Injection' in types and 'Path Traversal' in types:
                    correlated.append({
                        'type': 'Correlation - Web Attack Chain',
                        'ip': ip,
                        'timestamp': datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z'),
                        'path': f"Multiple attack types",
                        'details': f"IP {ip} performed multiple attack types",
                        'severity': 'Critical',
                        'mitre_id': 'TA0001'
                    })
                elif 'Directory Scanning' in types and 'Sensitive File Probing' in types:
                    correlated.append({
                        'type': 'Correlation - Reconnaissance',
                        'ip': ip,
                        'timestamp': datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z'),
                        'path': f"Reconnaissance pattern",
                        'details': f"IP {ip} performing reconnaissance",
                        'severity': 'High',
                        'mitre_id': 'TA0007'
                    })
                elif 'Brute Force' in types:
                    correlated.append({
                        'type': 'Correlation - Authentication Attack',
                        'ip': ip,
                        'timestamp': datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z'),
                        'path': f"Brute force attack",
                        'details': f"IP {ip} performing brute force",
                        'severity': 'High',
                        'mitre_id': 'TA0006'
                    })
        
        return correlated

    def run_all_detections_parallel(self):
        """Run detections in parallel for speed"""
        self.alerts = []
        
        # Run detections in parallel using ThreadPool
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.detect_sql_injection),
                executor.submit(self.detect_xss),
                executor.submit(self.detect_path_traversal),
                executor.submit(self.detect_sensitive_file_probing),
                executor.submit(self.detect_directory_scanning),
                executor.submit(self.detect_suspicious_user_agent),
                executor.submit(self.detect_brute_force),
                executor.submit(self.detect_request_rate_anomaly),
            ]
            
            for future in concurrent.futures.as_completed(futures):
                self.alerts.extend(future.result())
        
        # Run sequential detections that need all alerts
        self.alerts.extend(self.calculate_ip_risk_score())
        self.alerts.extend(self.correlate_events())
        
        return self.alerts

# ============ MAIN APP ============
def main():
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/security-checked--v1.png", width=80)
        st.title("🛡️ Security Monitor")
        st.markdown("---")
        
        # File upload
        st.subheader("📁 Upload Log File")
        uploaded_file = st.file_uploader(
            "Choose access.log file",
            type=['log', 'txt'],
            help="Upload access.log file (max 2GB)"
        )
        
        if uploaded_file is not None:
            # Save uploaded file
            file_path = Path("uploads") / uploaded_file.name
            file_path.parent.mkdir(exist_ok=True)
            
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            st.success(f"✅ File uploaded: {uploaded_file.name}")
            st.info(f"📊 Size: {uploaded_file.size / (1024*1024):.2f} MB")
            
            if st.button("🚀 Start Analysis", use_container_width=True):
                with st.spinner("Analyzing logs..."):
                    # Process logs
                    monitor = OptimizedSecurityMonitor(file_path, max_size_gb=2.0)
                    
                    # Progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    def update_progress(progress):
                        progress_bar.progress(progress)
                        status_text.text(f"Processing: {int(progress * 100)}%")
                    
                    # Load logs with progress
                    monitor.load_logs_fast(update_progress)
                    
                    # Run detections
                    status_text.text("Running detections...")
                    monitor.run_all_detections_parallel()
                    
                    # Store in session
                    st.session_state['monitor'] = monitor
                    st.session_state['alerts'] = monitor.alerts
                    st.session_state['logs'] = monitor.logs
                    
                    progress_bar.progress(1.0)
                    status_text.text("✅ Analysis complete!")
                    st.success(f"🎯 Found {len(monitor.alerts)} security alerts")
                    st.balloons()
        else:
            st.info("📂 Upload an access.log file to start analysis")
    
    # Main content (sama seperti sebelumnya)
    if 'alerts' in st.session_state and st.session_state['alerts']:
        alerts = st.session_state['alerts']
        logs = st.session_state.get('logs', [])
        
        # Header
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ Security Dashboard</h1>
            <p style="color: rgba(255,255,255,0.7);">Real-time security monitoring and threat detection</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Statistics row
        col1, col2, col3, col4 = st.columns(4)
        
        critical_count = len([a for a in alerts if a.get('severity') == 'Critical'])
        high_count = len([a for a in alerts if a.get('severity') == 'High'])
        
        with col1:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-number">{len(alerts)}</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-number" style="color: #e94560;">{critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-number" style="color: #ff6b6b;">{high_count}</div>
                <div class="stat-label">High</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-number" style="color: #ffd93d;">{len(logs):,}</div>
                <div class="stat-label">Total Logs</div>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Overview", "🚨 Alerts", "🌐 IP Analysis", 
            "🎯 MITRE ATT&CK", "📋 Report"
        ])
        
        with tab1:
            st.subheader("📊 Overview Dashboard")
            
            # Create charts in two columns
            col1, col2 = st.columns(2)
            
            with col1:
                # Severity distribution
                severity_data = Counter([a.get('severity', 'Unknown') for a in alerts])
                if severity_data:
                    fig_severity = px.pie(
                        values=list(severity_data.values()),
                        names=list(severity_data.keys()),
                        title="Alert Severity Distribution",
                        color_discrete_sequence=['#e94560', '#ff6b6b', '#ffd93d', '#4ecca3']
                    )
                    fig_severity.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='white'
                    )
                    st.plotly_chart(fig_severity, use_container_width=True)
            
            with col2:
                # Top attack types
                attack_data = Counter([a.get('type', 'Unknown') for a in alerts])
                if attack_data:
                    top_attacks = dict(attack_data.most_common(10))
                    fig_attacks = px.bar(
                        x=list(top_attacks.values()),
                        y=list(top_attacks.keys()),
                        orientation='h',
                        title="Top Attack Types",
                        color_discrete_sequence=['#e94560']
                    )
                    fig_attacks.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='white',
                        xaxis_title="Count",
                        yaxis_title="Attack Type"
                    )
                    st.plotly_chart(fig_attacks, use_container_width=True)
            
            # Top attacking IPs
            st.subheader("🌐 Top Attacking IPs")
            ip_data = Counter([a.get('ip', 'Unknown') for a in alerts])
            if ip_data:
                top_ips = dict(ip_data.most_common(10))
                df_ips = pd.DataFrame({
                    'IP': list(top_ips.keys()),
                    'Alerts': list(top_ips.values())
                })
                fig_ips = px.bar(
                    df_ips,
                    x='Alerts',
                    y='IP',
                    orientation='h',
                    title="Top 10 Attacking IPs",
                    color='Alerts',
                    color_continuous_scale='Reds'
                )
                fig_ips.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color='white'
                )
                st.plotly_chart(fig_ips, use_container_width=True)
        
        with tab2:
            st.subheader("🚨 Security Alerts")
            
            # Filters
            col1, col2, col3 = st.columns(3)
            with col1:
                severity_filter = st.selectbox(
                    "Filter by Severity",
                    ['All', 'Critical', 'High', 'Medium', 'Low']
                )
            with col2:
                attack_filter = st.selectbox(
                    "Filter by Attack Type",
                    ['All'] + sorted(list(set([a.get('type', 'Unknown') for a in alerts])))
                )
            with col3:
                search_query = st.text_input("🔍 Search IP or Path", placeholder="Search...")
            
            # Apply filters
            filtered_alerts = alerts
            if severity_filter != 'All':
                filtered_alerts = [a for a in filtered_alerts if a.get('severity') == severity_filter]
            if attack_filter != 'All':
                filtered_alerts = [a for a in filtered_alerts if a.get('type') == attack_filter]
            if search_query:
                filtered_alerts = [
                    a for a in filtered_alerts 
                    if search_query.lower() in a.get('ip', '').lower() 
                    or search_query.lower() in a.get('path', '').lower()
                ]
            
            # Display alerts
            st.info(f"Showing {len(filtered_alerts)} alerts")
            
            # Create DataFrame for display
            df_alerts = pd.DataFrame(filtered_alerts)
            if not df_alerts.empty:
                display_cols = ['timestamp', 'type', 'ip', 'path', 'severity', 'mitre_id']
                df_display = df_alerts[[c for c in display_cols if c in df_alerts.columns]]
                st.dataframe(df_display, use_container_width=True, height=400)
            else:
                st.info("No alerts matching the filters")
            
            # Export button
            if st.button("📥 Export to CSV"):
                csv = df_alerts.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name="security_alerts.csv",
                    mime="text/csv"
                )
        
        with tab3:
            st.subheader("🌐 IP Risk Analysis")
            
            # Group by IP
            ip_analysis = defaultdict(lambda: {
                'alerts': [],
                'types': [],
                'severities': []
            })
            
            for alert in alerts:
                ip = alert.get('ip')
                if ip:
                    ip_analysis[ip]['alerts'].append(alert)
                    ip_analysis[ip]['types'].append(alert.get('type', 'Unknown'))
                    ip_analysis[ip]['severities'].append(alert.get('severity', 'Unknown'))
            
            # Calculate risk scores
            ip_risk_data = []
            for ip, data in ip_analysis.items():
                severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
                risk_score = sum(severity_weights.get(s, 1) for s in data['severities'])
                
                ip_risk_data.append({
                    'IP': ip,
                    'Total Alerts': len(data['alerts']),
                    'Unique Attack Types': len(set(data['types'])),
                    'Risk Score': risk_score,
                    'Critical Count': data['severities'].count('Critical'),
                    'High Count': data['severities'].count('High')
                })
            
            if ip_risk_data:
                df_ip_risk = pd.DataFrame(ip_risk_data)
                df_ip_risk = df_ip_risk.sort_values('Risk Score', ascending=False)
                
                st.dataframe(df_ip_risk.head(20), use_container_width=True)
                
                # Visualization
                fig = px.scatter(
                    df_ip_risk.head(20),
                    x='Total Alerts',
                    y='Risk Score',
                    size='Unique Attack Types',
                    color='Critical Count',
                    hover_name='IP',
                    title="IP Risk Analysis",
                    color_continuous_scale='Reds'
                )
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color='white'
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with tab4:
            st.subheader("🎯 MITRE ATT&CK Mapping")
            
            mitre_mapping = {
                'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
                'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
                'T1006': {'name': 'File and Directory Permissions Modification', 'tactic': 'Defense Evasion'},
                'T1083': {'name': 'File and Directory Discovery', 'tactic': 'Discovery'},
                'T1046': {'name': 'Network Service Scanning', 'tactic': 'Discovery'},
                'T1110': {'name': 'Brute Force', 'tactic': 'Credential Access'},
                'T1595': {'name': 'Active Scanning', 'tactic': 'Discovery'},
                'T1499': {'name': 'Endpoint Denial of Service', 'tactic': 'Command and Control'},
                'TA0001': {'name': 'Initial Access', 'tactic': 'TA0001'},
                'TA0007': {'name': 'Discovery', 'tactic': 'TA0007'},
                'TA0006': {'name': 'Credential Access', 'tactic': 'TA0006'}
            }
            
            mitre_counts = Counter([a.get('mitre_id', 'Unknown') for a in alerts])
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.subheader("Technique Distribution")
                if mitre_counts:
                    mitre_data = []
                    for mitre_id, count in mitre_counts.most_common():
                        if mitre_id in mitre_mapping:
                            info = mitre_mapping[mitre_id]
                            mitre_data.append({
                                'MITRE ID': mitre_id,
                                'Technique': info['name'],
                                'Tactic': info['tactic'],
                                'Detections': count
                            })
                    
                    if mitre_data:
                        df_mitre = pd.DataFrame(mitre_data)
                        fig = px.bar(
                            df_mitre,
                            x='Detections',
                            y='Technique',
                            color='Tactic',
                            orientation='h',
                            title="MITRE ATT&CK Techniques Detected",
                            color_discrete_sequence=px.colors.qualitative.Set3
                        )
                        fig.update_layout(
                            paper_bgcolor='rgba(0,0,0,0)',
                            plot_bgcolor='rgba(0,0,0,0)',
                            font_color='white'
                        )
                        st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.subheader("Tactic Summary")
                tactic_summary = defaultdict(int)
                for mitre_id, count in mitre_counts.items():
                    if mitre_id in mitre_mapping:
                        tactic = mitre_mapping[mitre_id]['tactic']
                        tactic_summary[tactic] += count
                
                if tactic_summary:
                    for tactic, count in tactic_summary.items():
                        st.metric(
                            label=tactic,
                            value=count,
                            delta=f"{count/len(alerts)*100:.1f}%"
                        )
        
        with tab5:
            st.subheader("📋 Incident Report")
            
            type_counts = Counter([a.get('type', 'Unknown') for a in alerts])
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 📊 Summary Statistics")
                st.markdown(f"""
                - **Total Logs Analyzed**: {len(logs):,}
                - **Total Alerts**: {len(alerts)}
                - **Critical Alerts**: {critical_count}
                - **High Alerts**: {high_count}
                - **Unique IPs**: {len(set([a.get('ip', '') for a in alerts]))}
                - **Attack Types**: {len(type_counts)}
                """)
            
            with col2:
                st.markdown("### 🎯 Attack Type Breakdown")
                for attack, count in type_counts.most_common(10):
                    st.progress(count / len(alerts), text=f"{attack}: {count}")
            
            # Recommendations
            st.markdown("### 💡 Security Recommendations")
            
            recommendations = []
            if 'SQL Injection' in type_counts:
                recommendations.append("🛡️ Implement prepared statements and input validation for SQL queries")
            if 'XSS' in type_counts:
                recommendations.append("🛡️ Implement CSP (Content Security Policy) and output encoding")
            if 'Brute Force' in type_counts:
                recommendations.append("🛡️ Implement account lockout policies and rate limiting")
            if 'Directory Scanning' in type_counts:
                recommendations.append("🛡️ Implement proper access controls and directory listing restrictions")
            if 'Sensitive File Probing' in type_counts:
                recommendations.append("🛡️ Review file permissions and implement additional access controls")
            if 'Path Traversal' in type_counts:
                recommendations.append("🛡️ Implement proper path validation and sanitization")
            
            for rec in recommendations:
                st.markdown(f'<div class="recommendation">{rec}</div>', unsafe_allow_html=True)
            
            # Export report
            st.markdown("### 📥 Export Report")
            
            report_data = {
                'generated': datetime.now().isoformat(),
                'total_logs': len(logs),
                'total_alerts': len(alerts),
                'critical_count': critical_count,
                'high_count': high_count,
                'attack_types': dict(type_counts),
                'top_ips': Counter([a.get('ip', '') for a in alerts]).most_common(10),
                'recommendations': recommendations
            }
            
            if st.button("📥 Download JSON Report"):
                st.download_button(
                    label="Download Report",
                    data=json.dumps(report_data, indent=2),
                    file_name="incident_report.json",
                    mime="application/json"
                )
    
    else:
        # Welcome message
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ Security Monitor Dashboard</h1>
            <p style="color: rgba(255,255,255,0.7);">
                Upload an access.log file from the sidebar to start monitoring for security threats
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns(3)
        
        features = [
            ("🎯", "10+ Detection Methods", "SQL Injection, XSS, Brute Force, and more"),
            ("📊", "Interactive Dashboard", "Visualize threats with charts and graphs"),
            ("🛡️", "MITRE ATT&CK Mapping", "Map detections to industry standards")
        ]
        
        for col, (icon, title, desc) in zip([col1, col2, col3], features):
            with col:
                st.markdown(f"""
                <div class="stat-card">
                    <div style="font-size: 3rem;">{icon}</div>
                    <h3>{title}</h3>
                    <p style="color: rgba(255,255,255,0.7);">{desc}</p>
                </div>
                """, unsafe_allow_html=True)

if __name__ == "__main__":
    Path("uploads").mkdir(exist_ok=True)
    main()