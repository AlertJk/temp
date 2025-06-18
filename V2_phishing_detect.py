import joblib
import numpy as np
import warnings
import re
import os
import requests
import time
import hashlib
import base64
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from sklearn.exceptions import InconsistentVersionWarning
from dotenv import load_dotenv
import html
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Suppress sklearn warnings
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

class SecurePhishingDetector:
    def __init__(self, model_path):
        """Initialize the phishing detector with secure practices"""
        self.model_path = self._validate_file_path(model_path)
        self.components = self._load_model()
        self.vt_api_key = self._get_api_key()
        self.session = requests.Session()
        
        # Set up secure headers
        self.session.headers.update({
            'User-Agent': 'PhishingDetector/1.0',
            'Accept': 'application/json'
        })
        
        # Rate limiting for API calls
        self.last_api_call = 0
        self.api_rate_limit = 15  # seconds between calls for free tier
        
    def _validate_file_path(self, path):
        """Validate file path to prevent directory traversal attacks"""
        if not path or not isinstance(path, str):
            raise ValueError("Invalid file path")
        
        # Normalize path and check if it exists
        normalized_path = os.path.normpath(path)
        if not os.path.exists(normalized_path):
            raise FileNotFoundError(f"Model file not found: {normalized_path}")
        
        # Additional security: ensure it's a .joblib file
        if not normalized_path.endswith('.joblib'):
            raise ValueError("Invalid model file format")
        
        return normalized_path
    
    def _load_model(self):
        """Load the machine learning model securely"""
        try:
            return joblib.load(self.model_path)
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def _get_api_key(self):
        """Get VirusTotal API key from environment variables"""
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key:
            logger.warning("VirusTotal API key not found in environment variables")
            return None
        return api_key
    
    def _sanitize_input(self, text):
        """Sanitize input text to prevent injection attacks"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")
        
        # Limit input length to prevent DoS
        if len(text) > 10000:
            raise ValueError("Input text too long (max 10000 characters)")
        
        # HTML escape to prevent XSS if output is used in web context
        sanitized = html.escape(text)
        return sanitized
    
    def _validate_url(self, url):
        """Validate URL format and security"""
        if not isinstance(url, str):
            return False
        
        # Basic URL validation
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Only allow http/https
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Prevent local network access
            if parsed.netloc.startswith('localhost') or parsed.netloc.startswith('127.'):
                return False
            
            return True
        except Exception:
            return False
    
    def preprocess_text(self, text):
        """Preprocess email text with input validation"""
        text = self._sanitize_input(text)
        
        # Remove URLs (but extract them first for separate analysis)
        text = re.sub(r'http\S+', '', text)
        
        # Remove special characters
        text = re.sub(r'[^\w\s]', '', text)
        
        # Convert to lowercase
        text = text.lower()
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def extract_urls(self, text):
        """Extract URLs from text securely"""
        if not isinstance(text, str):
            return []
        
        # Find URLs in text
        url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
        urls = re.findall(url_pattern, text)
        
        # Validate each URL
        valid_urls = []
        for url in urls:
            if self._validate_url(url) and len(url) < 2048:  # Limit URL length
                valid_urls.append(url)
        
        return valid_urls
    
    def _rate_limit_check(self):
        """Implement rate limiting for API calls"""
        current_time = time.time()
        time_since_last_call = current_time - self.last_api_call
        
        if time_since_last_call < self.api_rate_limit:
            sleep_time = self.api_rate_limit - time_since_last_call
            logger.info(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        self.last_api_call = time.time()
    
    def analyze_url_with_virustotal(self, url):
        """Analyze URL using VirusTotal API"""
        if not self.vt_api_key:
            return {
                'status': 'error',
                'message': 'VirusTotal API key not configured'
            }
        
        if not self._validate_url(url):
            return {
                'status': 'error',
                'message': 'Invalid URL format'
            }
        
        try:
            # Rate limiting
            self._rate_limit_check()
            
            # Encode URL for VirusTotal
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            # VirusTotal API endpoint
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            headers = {
                "x-apikey": self.vt_api_key,
                "Accept": "application/json"
            }
            
            response = self.session.get(vt_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_virustotal_response(data)
            elif response.status_code == 404:
                # URL not found, submit for analysis
                return self._submit_url_for_analysis(url)
            else:
                return {
                    'status': 'error',
                    'message': f'VirusTotal API error: {response.status_code}'
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API request failed: {e}")
            return {
                'status': 'error',
                'message': 'Failed to connect to VirusTotal API'
            }
        except Exception as e:
            logger.error(f"VirusTotal analysis failed: {e}")
            return {
                'status': 'error',
                'message': 'URL analysis failed'
            }
    
    def _submit_url_for_analysis(self, url):
        """Submit URL to VirusTotal for analysis"""
        try:
            submit_url = "https://www.virustotal.com/api/v3/urls"
            
            headers = {
                "x-apikey": self.vt_api_key,
                "Accept": "application/json"
            }
            
            data = {"url": url}
            
            response = self.session.post(submit_url, headers=headers, data=data, timeout=10)
            
            if response.status_code == 200:
                return {
                    'status': 'pending',
                    'message': 'URL submitted for analysis. Please try again in a few minutes.',
                    'classification': 'Unknown'
                }
            else:
                return {
                    'status': 'error',
                    'message': 'Failed to submit URL for analysis'
                }
                
        except Exception as e:
            logger.error(f"URL submission failed: {e}")
            return {
                'status': 'error',
                'message': 'Failed to submit URL for analysis'
            }
    
    def _parse_virustotal_response(self, data):
        """Parse VirusTotal API response"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            clean = stats.get('harmless', 0)
            total = sum(stats.values())
            
            # Classification logic
            if malicious > 0:
                classification = 'Malicious'
                risk_level = 'High'
            elif suspicious > 2:
                classification = 'Suspicious'
                risk_level = 'Medium'
            elif suspicious > 0:
                classification = 'Suspicious'
                risk_level = 'Low'
            else:
                classification = 'Legitimate'
                risk_level = 'Low'
            
            return {
                'status': 'success',
                'classification': classification,
                'risk_level': risk_level,
                'stats': {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'clean': clean,
                    'total': total
                },
                'scan_date': attributes.get('last_analysis_date')
            }
            
        except Exception as e:
            logger.error(f"Failed to parse VirusTotal response: {e}")
            return {
                'status': 'error',
                'message': 'Failed to parse analysis results'
            }
    
    def capture_screenshot(self, url, output_path=None):
        """Capture screenshot of webpage securely"""
        if not self._validate_url(url):
            return {
                'status': 'error',
                'message': 'Invalid URL format'
            }
        
        # Set up Chrome options for security
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-plugins')
        chrome_options.add_argument('--disable-images')  # Faster loading
        chrome_options.add_argument('--disable-javascript')  # Security measure
        chrome_options.add_argument('--window-size=1920,1080')
        
        # Additional security options
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--disable-features=VizDisplayCompositor')
        
        # # Suppress Chrome logs and error messages
        # chrome_options.add_argument('--log-level=3')  # Suppress INFO, WARNING, ERROR
        # chrome_options.add_argument('--silent')
        # chrome_options.add_argument('--disable-logging')
        # chrome_options.add_argument('--disable-gpu-logging')
        # chrome_options.add_argument('--disable-software-rasterizer')
        # chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
        # chrome_options.add_experimental_option('useAutomationExtension', False)
        

        
        driver = None
        try:
            # Automatically download and setup ChromeDriver
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(10)  # Limit load time
            
            # Navigate to URL
            driver.get(url)
            
            # Wait for page to load (max 5 seconds)
            WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Generate secure filename if not provided
            if not output_path:
                safe_filename = hashlib.md5(url.encode()).hexdigest()
                output_path = f"screenshot_{safe_filename}.png"
            
            # Validate output path
            output_path = os.path.normpath(output_path)
            if not output_path.endswith('.png'):
                output_path += '.png'
            
            # Take screenshot
            driver.save_screenshot(output_path)
            
            return {
                'status': 'success',
                'screenshot_path': output_path,
                'message': 'Screenshot captured successfully'
            }
            
        except TimeoutException:
            return {
                'status': 'error',
                'message': 'Page load timeout'
            }
        except WebDriverException as e:
            logger.error(f"WebDriver error: {e}")
            return {
                'status': 'error',
                'message': 'Failed to capture screenshot'
            }
        except Exception as e:
            logger.error(f"Screenshot capture failed: {e}")
            return {
                'status': 'error',
                'message': 'Screenshot capture failed'
            }
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
    
    def predict_email(self, email_text):
        """Predict if email is phishing with URL analysis"""
        try:
            # Validate input
            if not email_text or not isinstance(email_text, str):
                raise ValueError("Invalid email text")
            
            # Extract URLs before preprocessing
            urls = self.extract_urls(email_text)
            
            # Preprocess email text
            processed_text = self.preprocess_text(email_text)
            
            # Get ML model components
            tfidf_vectorizer = self.components['tfidf_vectorizer']
            voting_classifier = self.components['voting_classifier']
            label_encoder = self.components['label_encoder']
            
            # Transform text and predict
            email_tfidf = tfidf_vectorizer.transform([processed_text])
            prediction = voting_classifier.predict(email_tfidf)
            probabilities = voting_classifier.predict_proba(email_tfidf)
            
            # Analyze URLs
            url_analysis = []
            for url in urls:
                analysis = self.analyze_url_with_virustotal(url)
                url_analysis.append({
                    'url': url,
                    'analysis': analysis
                })
            
            # Combine results
            result = {
                'email_classification': {
                    'class': label_encoder.inverse_transform(prediction)[0],
                    'probability': float(np.max(probabilities)),
                    'probabilities': {
                        label_encoder.classes_[0]: float(probabilities[0][0]),
                        label_encoder.classes_[1]: float(probabilities[0][1])
                    }
                },
                'urls_found': len(urls),
                'url_analysis': url_analysis,
                'overall_risk': self._calculate_overall_risk(prediction, url_analysis)
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Email prediction failed: {e}")
            return {
                'status': 'error',
                'message': 'Email analysis failed'
            }
    
    def _calculate_overall_risk(self, email_prediction, url_analysis):
        """Calculate overall risk level"""
        email_class = self.components['label_encoder'].inverse_transform(email_prediction)[0]
        
        # Start with email classification
        if email_class.lower() == 'phishing':
            base_risk = 'High'
        else:
            base_risk = 'Low'
        
        # Adjust based on URL analysis
        malicious_urls = sum(1 for analysis in url_analysis 
                           if analysis['analysis'].get('classification') == 'Malicious')
        suspicious_urls = sum(1 for analysis in url_analysis 
                            if analysis['analysis'].get('classification') == 'Suspicious')
        
        if malicious_urls > 0:
            return 'High'
        elif suspicious_urls > 0 and base_risk == 'Low':
            return 'Medium'
        else:
            return base_risk

def main():
    """Main function with secure input handling"""
    try:
        import os
        os.environ['WDM_LOG'] = '0'  # Suppress webdriver-manager warning
        
        # Suppress urllib3 warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        model_path = 'D:/SEM 6/FYP/tools/phishing_model_v2.joblib'
        detector = SecurePhishingDetector(model_path)
        
        print("=== Secure Phishing Detection System ===")
        print("Enter the email text to analyze (press Enter twice to finish):")
        
        # input validation
        lines = []
        while True:
            try:
                line = input()
                if line == "" and lines:
                    break
                lines.append(line)
            except KeyboardInterrupt:
                print("\nAnalysis cancelled.")
                return

        
        email_text = "\n".join(lines)
        
        if not email_text.strip():
            print("No email text provided.")
            return
        
        # Analyze email
        print("\nAnalyzing email...")
        result = detector.predict_email(email_text)
        
        if 'status' in result and result['status'] == 'error':
            print(f"Error: {result['message']}")
            return
        
        # Display results
        print("\n" + "="*50)
        print("ANALYSIS RESULTS")
        print("="*50)
        
        # Email classification
        email_result = result['email_classification']
        print(f"Email Classification: {email_result['class']}")
        print(f"Confidence: {email_result['probability']*100:.2f}%")
        
        # URL analysis
        if result['urls_found'] > 0:
            print(f"\nURLs Found: {result['urls_found']}")
            print("-" * 30)
            
            for i, url_data in enumerate(result['url_analysis'], 1):
                print(f"\nURL {i}: {url_data['url']}")
                analysis = url_data['analysis']
                
                if analysis['status'] == 'success':
                    print(f"Classification: {analysis['classification']}")
                    print(f"Risk Level: {analysis['risk_level']}")
                    if 'stats' in analysis:
                        stats = analysis['stats']
                        print(f"Scan Results: {stats['malicious']} malicious, "
                              f"{stats['suspicious']} suspicious, "
                              f"{stats['clean']} clean out of {stats['total']} engines")
                    
                    # Offer screenshot
                    if analysis['classification'] in ['Suspicious', 'Legitimate']:
                        screenshot_choice = input(f"Capture screenshot of this URL? (y/n): ").lower()
                        if screenshot_choice == 'y':
                            screenshot_result = detector.capture_screenshot(url_data['url'])
                            if screenshot_result['status'] == 'success':
                                print(f"Screenshot saved: {screenshot_result['screenshot_path']}")
                            else:
                                print(f"Screenshot failed: {screenshot_result['message']}")
                
                else:
                    print(f"Analysis Status: {analysis['status']}")
                    print(f"Message: {analysis['message']}")
        
        # Overall risk
        print(f"\nOverall Risk Level: {result['overall_risk']}")
        
        # Security recommendations
        print("\n" + "="*50)
        print("SECURITY RECOMMENDATIONS")
        print("="*50)
        
        if result['overall_risk'] == 'High':
            print("HIGH RISK - Do not interact with this email")
            print("• Do not click any links")
            print("• Do not download attachments")
            print("• Report as phishing")
        elif result['overall_risk'] == 'Medium':
            print("MEDIUM RISK - Exercise caution")
            print("• Verify sender authenticity")
            print("• Be cautious with links and attachments")
            print("• Consider additional verification")
        else:
            print("LOW RISK - Appears legitimate")
            print("• Still exercise normal email caution")
            print("• Verify important requests independently")
        
    except Exception as e:
        logger.error(f"Main execution failed: {e}")
        print("An error occurred during analysis.")

if __name__ == "__main__":
    main()