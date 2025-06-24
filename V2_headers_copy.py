import email
import re
import os
from datetime import datetime
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH

def analyze_email_headers():
    file_path = input("\nEnter the path to the email file: ").strip().strip('"').strip("'")
    
    if not file_path:
        print("No file path provided")
        return
    
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

        # Count received headers to detect email bouncing
        received_count = 0
        
        for h in headers.items():
            # Message ID
            if h[0].lower() == "message-id":
                meta["message-id"] = h[1]

            # From header
            if h[0].lower() == "from":
                meta["from"] = h[1]

            # Return path for comparison
            if h[0].lower() == "return-path":
                meta["return-path"] = h[1]

            # Count received headers
            if h[0].lower() == "received":
                received_count += 1
                if received_count == 1:  # Use first received header as sender client
                    meta["sender-client"] = h[1]

            # X-Originating-IP header
            if h[0].lower() == "x-originating-ip":
                meta["x-originating-ip"] = h[1]

            # Authentication detected by mail server
            if h[0].lower() == "authentication-results":
                if re.search(r"spf=pass", h[1], re.IGNORECASE):
                    meta["spf-record"] = True
                if re.search(r"dkim=pass", h[1], re.IGNORECASE):
                    meta["dkim-record"] = True
                if re.search(r"dmarc=pass", h[1], re.IGNORECASE):
                    meta["dmarc-record"] = True
                if re.search(r"does not designate|spf=fail|dkim=fail|dmarc=fail", h[1], re.IGNORECASE):
                    meta["spoofed"] = True
                if re.search(r"(\d{1,3}\.){3}\d{1,3}", h[1]):
                    ip = re.search(r"(\d{1,3}\.){3}\d{1,3}", h[1])
                    meta["ip-address"] = str(ip.group())

            if h[0].lower() == "reply-to":
                meta["reply-to"] = h[1]
                meta["spoofed-mail"] = h[1]

            if h[0].lower() == "date":
                meta["dt"] = h[1]

            if h[0].lower() == "content-type":
                meta["content-type"] = h[1]



        meta["multiple-received"] = received_count

        # Threat Assessment Logic
        threat_score = 0
        threat_reasons = []

        # Authentication failures (high risk)
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


        # Mismatched sender information
        if meta["from"] and meta["reply-to"] and meta["from"] != meta["reply-to"]:
            threat_score += 20
            threat_reasons.append("From and Reply-To headers mismatch")

        # Excessive email hops (potential email bouncing)
        if meta["multiple-received"] > 8:
            threat_score += 15
            threat_reasons.append("Excessive email routing detected")

        # No proper sender identification
        if not meta["message-id"]:
            threat_score += 10
            threat_reasons.append("Missing Message-ID")

        # Determine threat level
        if threat_score >= 70:
            meta["threat-level"] = "MALICIOUS"
        elif threat_score >= 30:
            meta["threat-level"] = "SUSPICIOUS"
        else:
            meta["threat-level"] = "LEGITIMATE"

        meta["threat-score"] = threat_score
        meta["threat-reasons"] = threat_reasons

        # Display Results
        print("\n" + "="*50)
        print("EMAIL HEADER ANALYSIS RESULTS")
        print("="*50)

        print(f"Message ID: {meta['message-id']}")
        print(f"From: {meta['from']}")
        print(f"Date: {meta['dt']}")
        
        print(f"\nAuthentication Status:")
        print(f"SPF Records: {'PASS' if meta['spf-record'] else 'FAIL'}")
        print(f"DKIM: {'PASS' if meta['dkim-record'] else 'FAIL'}")
        print(f"DMARC: {'PASS' if meta['dmarc-record'] else 'FAIL'}")

        print(f"\nTechnical Details:")
        print(f"IP Address: {meta['ip-address']}")
        print(f"Content-Type: {meta['content-type']}")
        print(f"Received Headers Count: {meta['multiple-received']}")
        
        if meta["reply-to"]:
            print(f"Reply-To: {meta['reply-to']}")

        print(f"\nTHREAT ASSESSMENT:")
        print(f"Threat Level: {meta['threat-level']}")
        print(f"Threat Score: {meta['threat-score']}/100")
        
        if threat_reasons:
            print(f"Risk Factors:")
            for reason in threat_reasons:
                print(f"  - {reason}")

        # Provide recommendation
        recommendation = get_recommendation(meta["threat-level"], meta["threat-score"], threat_reasons)
        print(f"\nRECOMMENDATION: {recommendation}")

        print("="*50)

        log_choice = input("\nWould you like to log these results to a text file? (y/n): ").strip().lower()
        if log_choice == 'y':
            log_results(meta, threat_reasons, recommendation, file_path)

        report_choice = input("Would you like to generate a detailed report document? (y/n): ").strip().lower()
        if report_choice == 'y':
            generate_report(meta, threat_reasons, recommendation, file_path)
        
        print("\n Analysis completed successfully!")

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def get_recommendation(threat_level, threat_score, threat_reasons):
    """Generate recommendation based on threat assessment"""
    if threat_level == "MALICIOUS":
        return "DO NOT INTERACT with this email. Delete immediately and report to IT security team. This email shows strong indicators of malicious intent."
    elif threat_level == "SUSPICIOUS":
        return "EXERCISE CAUTION. Do not click links or download attachments. Verify sender through alternative communication method before taking any action."
    else:
        return "Email appears legitimate. However, always exercise standard email security practices."

def log_results(meta, threat_reasons, recommendation, original_file):
    """Log analysis results to a text file in logs folder"""
    # Create logs directory if it doesn't exist
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(logs_dir, f"email_analysis_log_{timestamp}.txt")
    
    try:
        with open(log_filename, 'w', encoding='utf-8') as log_file:
            log_file.write("EMAIL HEADER ANALYSIS LOG\n")
            log_file.write("="*50 + "\n")
            log_file.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_file.write(f"Original File: {original_file}\n")
            log_file.write(f"Message ID: {meta['message-id']}\n")
            log_file.write(f"From: {meta['from']}\n")
            log_file.write(f"Date: {meta['dt']}\n")
            log_file.write(f"Threat Level: {meta['threat-level']}\n")
            log_file.write(f"Threat Score: {meta['threat-score']}/100\n")
            log_file.write(f"SPF: {'PASS' if meta['spf-record'] else 'FAIL'}\n")
            log_file.write(f"DKIM: {'PASS' if meta['dkim-record'] else 'FAIL'}\n")
            log_file.write(f"DMARC: {'PASS' if meta['dmarc-record'] else 'FAIL'}\n")
            log_file.write(f"IP Address: {meta['ip-address']}\n")
            
            if threat_reasons:
                log_file.write("\nRisk Factors:\n")
                for reason in threat_reasons:
                    log_file.write(f"- {reason}\n")
            
            log_file.write(f"\nRecommendation: {recommendation}\n")
            
        print(f"Results logged to: {log_filename}")
    except Exception as e:
        print(f"Error creating log file: {str(e)}")

def generate_report(meta, threat_reasons, recommendation, original_file):
    """Generate a detailed report document as DOCX in reports folder"""
    # Create reports directory if it doesn't exist
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = os.path.join(reports_dir, f"email_headers_report_{timestamp}.docx")
    
    try:
        # Create a new Document
        doc = Document()
        
        # Title
        title = doc.add_heading('EMAIL HEADERS ANALYSIS REPORT', 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        # Add a line break
        doc.add_paragraph()
        
        # Executive Summary
        doc.add_heading('EXECUTIVE SUMMARY', level=1)
        summary_table = doc.add_table(rows=4, cols=2)
        summary_table.style = 'Table Grid'
        
        summary_data = [
            ('Threat Level:', meta['threat-level']),
            ('Risk Score:', f"{meta['threat-score']}/100"),
            ('Analysis Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            ('Email File Analyzed:', original_file)
        ]
        
        for i, (key, value) in enumerate(summary_data):
            summary_table.cell(i, 0).text = key
            summary_table.cell(i, 1).text = str(value)
        
        doc.add_paragraph()
        
        # Email Details
        doc.add_heading('EMAIL DETAILS', level=1)
        details_table = doc.add_table(rows=4 + (1 if meta['reply-to'] else 0), cols=2)
        details_table.style = 'Table Grid'
        
        details_data = [
            ('Message ID:', meta['message-id']),
            ('From:', meta['from']),
            ('Date Sent:', meta['dt']),
            ('Content Type:', meta['content-type'])
        ]
        
        if meta['reply-to']:
            details_data.append(('Reply-To:', meta['reply-to']))
        
        for i, (key, value) in enumerate(details_data):
            details_table.cell(i, 0).text = key
            details_table.cell(i, 1).text = str(value)
        
        doc.add_paragraph()
        
        # Technical Analysis
        doc.add_heading('TECHNICAL ANALYSIS', level=1)
        tech_table = doc.add_table(rows=3, cols=2)
        tech_table.style = 'Table Grid'
        
        tech_data = [
            ('Sender IP Address:', meta['ip-address']),
            ('Email Routing Hops:', str(meta['multiple-received'])),
            ('Sender Client:', meta['sender-client'][:100] + "..." if len(meta['sender-client']) > 100 else meta['sender-client'])
        ]
        
        for i, (key, value) in enumerate(tech_data):
            tech_table.cell(i, 0).text = key
            tech_table.cell(i, 1).text = str(value)
        
        doc.add_paragraph()
        
        # Authentication Results
        doc.add_heading('AUTHENTICATION VERIFICATION', level=1)
        auth_table = doc.add_table(rows=3, cols=2)
        auth_table.style = 'Table Grid'
        
        auth_data = [
            ('SPF (Sender Policy Framework):', 'PASS' if meta['spf-record'] else 'FAIL'),
            ('DKIM (DomainKeys Identified Mail):', 'PASS' if meta['dkim-record'] else 'FAIL'),
            ('DMARC (Domain-based Message Authentication):', 'PASS' if meta['dmarc-record'] else 'FAIL')
        ]
        
        for i, (key, value) in enumerate(auth_data):
            auth_table.cell(i, 0).text = key
            auth_table.cell(i, 1).text = str(value)
        
        doc.add_paragraph()
        
        # Risk Assessment
        doc.add_heading('RISK ASSESSMENT', level=1)
        
        if threat_reasons:
            doc.add_paragraph('Identified Risk Factors:')
            for i, reason in enumerate(threat_reasons, 1):
                doc.add_paragraph(f"{i}. {reason}", style='List Number')
        else:
            doc.add_paragraph('No significant risk factors identified.')
    
        
        doc.add_paragraph(f"Overall Risk Score: {meta['threat-score']}/100")
        
        doc.add_paragraph('Risk Level Interpretation:')
        doc.add_paragraph(' 0-29: LEGITIMATE (Low Risk)', style='List Bullet')
        doc.add_paragraph(' 30-69: SUSPICIOUS (Medium Risk)', style='List Bullet')
        doc.add_paragraph(' 70-100: MALICIOUS (High Risk)', style='List Bullet')
        
        doc.add_paragraph()
        
        # Recommendations
        doc.add_heading('RECOMMENDATIONS', level=1)
        doc.add_paragraph(f"Primary Recommendation: {recommendation}")
        doc.add_paragraph()
        
        doc.add_paragraph('General Security Best Practices:')
        best_practices = [
            'Verify sender identity through alternative communication channels',
            'Do not click suspicious links or download unexpected attachments',
            'Report suspicious emails to your IT security team',
            'Keep email security software updated',
            'Enable multi-factor authentication where possible'
        ]
        
        for practice in best_practices:
            doc.add_paragraph(practice, style='List Number')
        
        doc.add_paragraph()
        
        # Conclusion
        doc.add_heading('CONCLUSION', level=1)
        if meta['threat-level'] == "MALICIOUS":
            conclusion = "This email exhibits multiple characteristics of malicious communication and should be treated as a security threat."
        elif meta['threat-level'] == "SUSPICIOUS":
            conclusion = "This email shows suspicious characteristics that warrant careful review before any interaction."
        else:
            conclusion = "This email appears to be legitimate based on standard authentication and content analysis."
        
        conclusion += " Users should follow the recommended actions outlined above."
        doc.add_paragraph(conclusion)
        
        # Add footer
        doc.add_paragraph()
        footer = doc.add_paragraph('End of Report')
        footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        # Save the document
        doc.save(report_filename)
        print(f"Detailed report generated: {report_filename}")
        
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        print("Note: Make sure you have python-docx installed: pip install python-docx")

