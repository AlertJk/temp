import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import re
import email
import joblib
import numpy as np
import requests
import time
from datetime import datetime
from urllib.parse import urlparse
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
import hashlib
import base64
import warnings
from sklearn.exceptions import InconsistentVersionWarning
import threading
import email.parser

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

MODEL_PATH = os.path.abspath("phishing_model_v2.joblib")

class PhishingDetector:
    def __init__(self):
        self.model_path = MODEL_PATH
        self.components = None
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.load_model()

    def load_model(self):
        try:
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            self.components = joblib.load(self.model_path)
        except Exception as e:
            self.components = None
            print(f"Error loading model: {e}")

    def validate_input(self, text):
        if len(text.strip()) == 0:
            raise ValueError("Input cannot be empty")
        if len(text) > 10000:
            raise ValueError("Input text is too long (max 10,000 characters)")
        return text.strip()

    def preprocess_text(self, text):
        text = re.sub(r'http\S+', '', text)
        text = re.sub(r'[^\w\s]', '', text)
        text = text.lower()
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def extract_urls(self, text):
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))

    def validate_url(self, url):
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False
            if parsed.scheme not in ['http', 'https']:
                return False
            return True
        except Exception:
            return False

    def analyze_url_virustotal(self, url):
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not available"}
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"X-Apikey": self.vt_api_key, "Content-Type": "application/json"}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers, timeout=30)
            if response.status_code == 404:
                submit_response = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers, data={"url": url}, timeout=30)
                if submit_response.status_code == 200:
                    time.sleep(15)
                    response = requests.get(
                        f"https://www.virustotal.com/api/v3/urls/{url_id}",
                        headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                clean = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total_scans = malicious + suspicious + clean + undetected
                if total_scans == 0:
                    return {"status": "No analysis data available", "url": url}
                if malicious > 0:
                    classification = "Malicious"
                elif suspicious > 2:
                    classification = "Suspicious"
                else:
                    classification = "Legitimate"
                return {
                    "url": url,
                    "classification": classification,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "clean": clean,
                    "total_scans": total_scans,
                    "scan_date": data.get('data', {}).get('attributes', {}).get('last_analysis_date')
                }
            else:
                return {"error": f"API request failed with status {response.status_code}"}
        except requests.exceptions.Timeout:
            return {"error": "Request timeout"}
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

    def predict_email(self, email_text):
        try:
            email_text = self.validate_input(email_text)
            if not self.components:
                return {"error": "Model not loaded"}
            tfidf_vectorizer = self.components['tfidf_vectorizer']
            voting_classifier = self.components['voting_classifier']
            label_encoder = self.components['label_encoder']
            processed_text = self.preprocess_text(email_text)
            email_tfidf = tfidf_vectorizer.transform([processed_text])
            prediction = voting_classifier.predict(email_tfidf)
            probabilities = voting_classifier.predict_proba(email_tfidf)
            return {
                'class': label_encoder.inverse_transform(prediction)[0],
                'probability': float(np.max(probabilities)),
                'probabilities': {
                    label_encoder.classes_[0]: float(probabilities[0][0]),
                    label_encoder.classes_[1]: float(probabilities[0][1])
                }
            }
        except Exception as e:
            return {"error": f"Prediction failed: {str(e)}"}

def analyze_headers_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            msg = email.message_from_file(f)
        parser = email.parser.HeaderParser()
        headers = parser.parsestr(msg.as_string())
        meta = {
            "message-id": "",
            "spf-record": False,
            "dkim-record": False,
            "dmarc-record": False,
            "spoofed": False,
            "ip-address": "",
            "sender-client": "",
            "spoofed-mail": "",
            "dt": "",
            "content-type": "",
            "from": "",
            "reply-to": "",
            "return-path": "",
            "x-originating-ip": "",
            "multiple-received": 0,
            "threat-level": "LEGITIMATE",
            "threat-score": 0
        }
        received_count = 0
        for h in headers.items():
            if h[0].lower() == "message-id":
                meta["message-id"] = h[1]
            if h[0].lower() == "from":
                meta["from"] = h[1]
            if h[0].lower() == "return-path":
                meta["return-path"] = h[1]
            if h[0].lower() == "received":
                received_count += 1
                if received_count == 1:
                    meta["sender-client"] = h[1]
            if h[0].lower() == "x-originating-ip":
                ip = re.search(r"(\d{1,3}\.){3}\d{1,3}", h[1])
                if ip:
                    meta["ip-address"] = str(ip.group())
            if h[0].lower() == "authentication-results":
                if re.search(r"spf=pass", h[1], re.IGNORECASE):
                    meta["spf-record"] = True
                if re.search(r"dkim=pass", h[1], re.IGNORECASE):
                    meta["dkim-record"] = True
                if re.search(r"dmarc=pass", h[1], re.IGNORECASE):
                    meta["dmarc-record"] = True
                if re.search(r"does not designate|spf=fail|dkim=fail|dmarc=fail", h[1], re.IGNORECASE):
                    meta["spoofed"] = True
            if h[0].lower() == "reply-to":
                meta["reply-to"] = h[1]
                meta["spoofed-mail"] = h[1]
            if h[0].lower() == "date":
                meta["dt"] = h[1]
            if h[0].lower() == "content-type":
                meta["content-type"] = h[1]
        meta["multiple-received"] = received_count
        threat_score = 0
        threat_reasons = []
        if meta["spoofed"]:
            threat_score += 40
            threat_reasons.append("Authentication failures detected")
        if not meta["spf-record"]:
            threat_score += 15
            threat_reasons.append("SPF record failed")
        if not meta["dkim-record"]:
            threat_score += 15
            threat_reasons.append("DKIM verification failed")
        if not meta["dmarc-record"]:
            threat_score += 15
            threat_reasons.append("DMARC verification failed")
        if meta["from"] and meta["reply-to"] and meta["from"] != meta["reply-to"]:
            threat_score += 20
            threat_reasons.append("From and Reply-To headers mismatch")
        if meta["multiple-received"] > 8:
            threat_score += 15
            threat_reasons.append("Excessive email routing detected")
        if not meta["message-id"]:
            threat_score += 10
            threat_reasons.append("Missing Message-ID")
        if threat_score >= 70:
            meta["threat-level"] = "MALICIOUS"
        elif threat_score >= 30:
            meta["threat-level"] = "SUSPICIOUS"
        else:
            meta["threat-level"] = "LEGITIMATE"
        meta["threat-score"] = threat_score
        meta["threat-reasons"] = threat_reasons
        return meta
    except Exception as e:
        return {"error": str(e)}

def get_header_recommendation(threat_level, threat_score, threat_reasons):
    if threat_level == "MALICIOUS":
        return "DO NOT INTERACT with this email. Delete immediately and report to IT security team. This email shows strong indicators of malicious intent."
    elif threat_level == "SUSPICIOUS":
        return "EXERCISE CAUTION. Do not click links or download attachments. Verify sender through alternative communication method before taking any action."
    else:
        return "Email appears legitimate. However, always exercise standard email security practices."

class ModernStyle:
    """Modern styling constants for the GUI"""
    COLORS = {
        'bg_primary': '#1e1e1e',
        'bg_secondary': '#2d2d2d',
        'bg_tertiary': '#3e3e3e',
        'accent': '#007acc',
        'accent_hover': '#005a9e',
        'success': '#4caf50',
        'warning': '#ff9800',
        'danger': '#f44336',
        'text_primary': '#ffffff',
        'text_secondary': '#cccccc',
        'border': '#555555'
    }
    
    FONTS = {
        'default': ('Segoe UI', 10),
        'heading': ('Segoe UI', 12, 'bold'),
        'large_heading': ('Segoe UI', 14, 'bold'),
        'mono': ('Consolas', 9)
    }

class PhishingGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Phishing Email Analyzer")
        self.geometry("1200x800")
        self.resizable(True, True)
        self.configure(bg=ModernStyle.COLORS['bg_primary'])
        
        # Configure modern styling
        self.setup_styles()
        
        self.detector = PhishingDetector()
        self.create_widgets()
        
        # Variables for tracking analysis results
        self.content_analysis_results = None
        self.content_report_path = None
        self.content_log_path = None
        self.screenshot_paths = []
        self.header_analysis_results = None
        self.header_report_path = None
        self.header_log_path = None

    def setup_styles(self):
        """Configure modern ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure notebook style
        style.configure('Modern.TNotebook', 
                       background=ModernStyle.COLORS['bg_primary'],
                       borderwidth=0)
        style.configure('Modern.TNotebook.Tab',
                       background=ModernStyle.COLORS['bg_secondary'],
                       foreground=ModernStyle.COLORS['text_primary'],
                       padding=[20, 10],
                       font=ModernStyle.FONTS['default'])
        style.map('Modern.TNotebook.Tab',
                 background=[('selected', ModernStyle.COLORS['accent']),
                           ('active', ModernStyle.COLORS['bg_tertiary'])])
        
        # Configure button styles
        style.configure('Modern.TButton',
                       background=ModernStyle.COLORS['accent'],
                       foreground=ModernStyle.COLORS['text_primary'],
                       borderwidth=0,
                       focuscolor='none',
                       padding=[15, 8],
                       font=ModernStyle.FONTS['default'])
        style.map('Modern.TButton',
                 background=[('active', ModernStyle.COLORS['accent_hover'])])
        
        # Configure frame styles
        style.configure('Modern.TFrame',
                       background=ModernStyle.COLORS['bg_primary'],
                       borderwidth=0)
        
        # Configure label styles
        style.configure('Modern.TLabel',
                       background=ModernStyle.COLORS['bg_primary'],
                       foreground=ModernStyle.COLORS['text_primary'],
                       font=ModernStyle.FONTS['default'])
        
        style.configure('Heading.TLabel',
                       background=ModernStyle.COLORS['bg_primary'],
                       foreground=ModernStyle.COLORS['text_primary'],
                       font=ModernStyle.FONTS['heading'])

    def create_widgets(self):
        # Main container
        main_container = ttk.Frame(self, style='Modern.TFrame')
        main_container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_container, 
                               text="Advanced Phishing Email Analyzer",
                               font=ModernStyle.FONTS['large_heading'],
                               style='Heading.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Notebook with modern styling
        self.tab_control = ttk.Notebook(main_container, style='Modern.TNotebook')
        self.tab_content = ttk.Frame(self.tab_control, style='Modern.TFrame')
        self.tab_headers = ttk.Frame(self.tab_control, style='Modern.TFrame')
        
        self.tab_control.add(self.tab_content, text='Email Content & URL Analysis')
        self.tab_control.add(self.tab_headers, text='Header Analysis')
        self.tab_control.pack(expand=1, fill='both')
        
        # Create tab contents
        self.create_content_tab()
        self.create_headers_tab()

    def create_content_tab(self):
        frame = self.tab_content
        
        # Email input section
        input_section = ttk.Frame(frame, style='Modern.TFrame')
        input_section.pack(fill='x', pady=(0, 20))
        
        ttk.Label(input_section, 
                 text="Email Content Input",
                 style='Heading.TLabel').pack(anchor='nw', pady=(0, 10))
        
        ttk.Label(input_section,
                 text="Paste email text or load from file:",
                 style='Modern.TLabel').pack(anchor='nw', pady=(0, 5))
        
        self.email_text = scrolledtext.ScrolledText(
            input_section, 
            height=10,
            bg=ModernStyle.COLORS['bg_secondary'],
            fg=ModernStyle.COLORS['text_primary'],
            insertbackground=ModernStyle.COLORS['text_primary'],
            font=ModernStyle.FONTS['mono'],
            selectbackground=ModernStyle.COLORS['accent']
        )
        self.email_text.pack(fill='x', pady=(0, 10))
        
        # Button frame
        btn_frame = ttk.Frame(input_section, style='Modern.TFrame')
        btn_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(btn_frame, text="Load from File", 
                  command=self.load_email_file,
                  style='Modern.TButton').pack(side='left', padx=(0, 10))
        
        ttk.Button(btn_frame, text="Analyze Email", 
                  command=self.run_content_analysis,
                  style='Modern.TButton').pack(side='left', padx=(0, 10))
        
        self.btn_screenshot = ttk.Button(btn_frame, text="Capture Screenshots", 
                                        command=self.capture_screenshots,
                                        state='disabled',
                                        style='Modern.TButton')
        self.btn_screenshot.pack(side='left', padx=(0, 10))
        
        self.btn_save_content_log = ttk.Button(btn_frame, text="Save Log", 
                                              command=self.save_content_log,
                                              state='disabled',
                                              style='Modern.TButton')
        self.btn_save_content_log.pack(side='left', padx=(0, 10))
        
        self.btn_save_content_report = ttk.Button(btn_frame, text="Save Report", 
                                                 command=self.save_content_report,
                                                 state='disabled',
                                                 style='Modern.TButton')
        self.btn_save_content_report.pack(side='left')
        
        # Results section with prominent classification display
        self.create_results_section(frame)
        
        # Screenshot preview section
        self.create_screenshot_section(frame)

    def create_results_section(self, parent):
        """Create a modern results section with prominent classification display"""
        results_section = ttk.Frame(parent, style='Modern.TFrame')
        results_section.pack(fill='both', expand=True, pady=(0, 20))
        
        ttk.Label(results_section,
                 text="Analysis Results",
                 style='Heading.TLabel').pack(anchor='nw', pady=(0, 10))
        
        # Classification display frame (prominent)
        self.classification_frame = tk.Frame(
            results_section,
            bg=ModernStyle.COLORS['bg_secondary'],
            relief='solid',
            bd=2
        )
        self.classification_frame.pack(fill='x', pady=(0, 15))
        
        # Classification labels (initially hidden)
        self.classification_title = tk.Label(
            self.classification_frame,
            text="EMAIL CLASSIFICATION",
            font=('Segoe UI', 14, 'bold'),
            bg=ModernStyle.COLORS['bg_secondary'],
            fg=ModernStyle.COLORS['text_primary']
        )
        
        self.classification_result = tk.Label(
            self.classification_frame,
            text="",
            font=('Segoe UI', 24, 'bold'),
            bg=ModernStyle.COLORS['bg_secondary'],
            fg=ModernStyle.COLORS['text_primary']
        )
        
        self.confidence_label = tk.Label(
            self.classification_frame,
            text="",
            font=('Segoe UI', 16),
            bg=ModernStyle.COLORS['bg_secondary'],
            fg=ModernStyle.COLORS['text_secondary']
        )
        
        # Detailed results text area
        self.content_results = scrolledtext.ScrolledText(
            results_section,
            height=12,
            state='disabled',
            bg=ModernStyle.COLORS['bg_secondary'],
            fg=ModernStyle.COLORS['text_primary'],
            font=ModernStyle.FONTS['mono'],
            selectbackground=ModernStyle.COLORS['accent']
        )
        self.content_results.pack(fill='both', expand=True)

    def create_screenshot_section(self, parent):
        """Create screenshot preview section with 'View More' functionality"""
        screenshot_section = ttk.Frame(parent, style='Modern.TFrame')
        screenshot_section.pack(fill='x', pady=(20, 0))
        
        self.screenshot_title = ttk.Label(screenshot_section,
                                         text="Website Screenshots",
                                         style='Heading.TLabel')
        self.screenshot_title.pack(anchor='nw', pady=(0, 10))
        self.screenshot_title.pack_forget()  # Initially hidden
        
        # Container for screenshots
        self.screenshot_container = ttk.Frame(screenshot_section, style='Modern.TFrame')
        self.screenshot_container.pack(fill='x')
        
        # Visible screenshots frame (shows first 2)
        self.visible_screenshots_frame = ttk.Frame(self.screenshot_container, style='Modern.TFrame')
        self.visible_screenshots_frame.pack(side='top', fill='x')
        
        # Hidden screenshots frame (shows rest when expanded)
        self.hidden_screenshots_frame = ttk.Frame(self.screenshot_container, style='Modern.TFrame')
        
        # View More button
        self.view_more_btn = ttk.Button(self.screenshot_container,
                                       text="View More Screenshots",
                                       command=self.toggle_screenshot_view,
                                       style='Modern.TButton')
        
        # Track screenshot display state
        self.screenshots_expanded = False
        self.screenshot_images = []  # To keep references to PhotoImage objects

    def create_headers_tab(self):
        frame = self.tab_headers
        
        # Header input section
        input_section = ttk.Frame(frame, style='Modern.TFrame')
        input_section.pack(fill='x', pady=(0, 20))
        
        ttk.Label(input_section,
                 text="Email Header Analysis",
                 style='Heading.TLabel').pack(anchor='nw', pady=(0, 10))
        
        ttk.Label(input_section,
                 text="Select .eml or header file:",
                 style='Modern.TLabel').pack(anchor='nw', pady=(0, 5))
        
        # Button frame
        btn_frame = ttk.Frame(input_section, style='Modern.TFrame')
        btn_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(btn_frame, text="Load Header File",
                  command=self.load_header_file,
                  style='Modern.TButton').pack(side='left', padx=(0, 10))
        
        ttk.Button(btn_frame, text="Analyze Headers",
                  command=self.run_header_analysis,
                  style='Modern.TButton').pack(side='left', padx=(0, 10))
        
        self.btn_save_header_log = ttk.Button(btn_frame, text="Save Log",
                                             command=self.save_header_log,
                                             state='disabled',
                                             style='Modern.TButton')
        self.btn_save_header_log.pack(side='left', padx=(0, 10))
        
        self.btn_save_header_report = ttk.Button(btn_frame, text="Save Report",
                                                command=self.save_header_report,
                                                state='disabled',
                                                style='Modern.TButton')
        self.btn_save_header_report.pack(side='left')
        
        # File path display
        self.header_file_path = tk.StringVar()
        path_label = ttk.Label(input_section, textvariable=self.header_file_path,
                              style='Modern.TLabel')
        path_label.pack(anchor='nw', pady=(0, 10))
        
        # Results section
        ttk.Label(input_section,
                 text="Header Analysis Results",
                 style='Heading.TLabel').pack(anchor='nw', pady=(10, 5))
        
        self.header_results = scrolledtext.ScrolledText(
            frame,
            height=25,
            state='disabled',
            bg=ModernStyle.COLORS['bg_secondary'],
            fg=ModernStyle.COLORS['text_primary'],
            font=ModernStyle.FONTS['mono'],
            selectbackground=ModernStyle.COLORS['accent']
        )
        self.header_results.pack(fill='both', expand=True)

    def display_content_results(self, results):
        """Enhanced results display with prominent classification"""
        email_result = results.get('email_analysis', {})
        
        # Update prominent classification display
        if 'error' not in email_result:
            classification = email_result.get('class', 'Unknown').upper()
            confidence = email_result.get('probability', 0) * 100
            
            # Show classification frame
            self.classification_title.pack(pady=(15, 5))
            self.classification_result.pack(pady=(0, 5))
            self.confidence_label.pack(pady=(0, 15))
            
            # Set classification text and color
            self.classification_result.config(text=classification)
            self.confidence_label.config(text=f"Confidence: {confidence:.1f}%")
            
            # Color coding based on classification
            if classification == 'PHISHING':
                bg_color = ModernStyle.COLORS['danger']
                self.classification_frame.config(bg=bg_color, highlightbackground=bg_color)
                self.classification_title.config(bg=bg_color)
                self.classification_result.config(bg=bg_color, fg='white')
                self.confidence_label.config(bg=bg_color, fg='white')
            elif classification == 'SUSPICIOUS':
                bg_color = ModernStyle.COLORS['warning']
                self.classification_frame.config(bg=bg_color, highlightbackground=bg_color)
                self.classification_title.config(bg=bg_color)
                self.classification_result.config(bg=bg_color, fg='white')
                self.confidence_label.config(bg=bg_color, fg='white')
            else:
                bg_color = ModernStyle.COLORS['success']
                self.classification_frame.config(bg=bg_color, highlightbackground=bg_color)
                self.classification_title.config(bg=bg_color)
                self.classification_result.config(bg=bg_color, fg='white')
                self.confidence_label.config(bg=bg_color, fg='white')
        
        # Update detailed results
        self.content_results.config(state='normal')
        self.content_results.delete('1.0', tk.END)
        
        # Email analysis details
        if 'error' not in email_result:
            self.content_results.insert(tk.END, "=" * 60 + "\n")
            self.content_results.insert(tk.END, "EMAIL CLASSIFICATION ANALYSIS\n")
            self.content_results.insert(tk.END, "=" * 60 + "\n\n")
            
            self.content_results.insert(tk.END, f"Classification: {email_result.get('class', 'N/A')}\n")
            self.content_results.insert(tk.END, f"Confidence Score: {email_result.get('probability', 0)*100:.2f}%\n\n")
            
            # Probability breakdown
            if 'probabilities' in email_result:
                self.content_results.insert(tk.END, "Detailed Probability Breakdown:\n")
                self.content_results.insert(tk.END, "-" * 40 + "\n")
                for label, prob in email_result['probabilities'].items():
                    self.content_results.insert(tk.END, f"{label}: {prob*100:.2f}%\n")
                self.content_results.insert(tk.END, "\n")
        else:
            self.content_results.insert(tk.END, f"Email Analysis Error: {email_result['error']}\n\n")
        
        # URL analysis section
        urls = results.get('url_analysis', [])
        if urls:
            self.content_results.insert(tk.END, "=" * 60 + "\n")
            self.content_results.insert(tk.END, "URL SECURITY ANALYSIS\n")
            self.content_results.insert(tk.END, "=" * 60 + "\n\n")
            
            self.content_results.insert(tk.END, f"Total URLs Found: {len(urls)}\n\n")
            
            for i, url_result in enumerate(urls, 1):
                self.content_results.insert(tk.END, f"URL {i}:\n")
                self.content_results.insert(tk.END, f"Address: {url_result.get('url', 'N/A')}\n")
                
                if 'error' not in url_result:
                    classification = url_result.get('classification', 'Unknown')
                    self.content_results.insert(tk.END, f"Security Status: {classification}\n")
                    self.content_results.insert(tk.END, f"Malicious Detections: {url_result.get('malicious', 0)}\n")
                    self.content_results.insert(tk.END, f"Suspicious Detections: {url_result.get('suspicious', 0)}\n")
                    self.content_results.insert(tk.END, f"Total Security Scans: {url_result.get('total_scans', 0)}\n")
                    
                    # Add scan date if available
                    if 'scan_date' in url_result and url_result['scan_date']:
                        scan_date = datetime.fromtimestamp(url_result['scan_date']).strftime('%Y-%m-%d %H:%M:%S')
                        self.content_results.insert(tk.END,
