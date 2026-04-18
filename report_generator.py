import io
import csv
import json
import logging
from datetime import datetime
import pytz
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import tempfile
import os

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _get_local_time(self):
        """Get current time in user's timezone"""
        user_timezone = pytz.timezone('Asia/Kolkata')  # GMT+5:30
        return datetime.now(user_timezone)
    
    def _convert_to_local_time(self, datetime_obj):
        """Convert datetime to local timezone - now that we store in local time, just return as-is"""
        # Since we now store times in local timezone (Asia/Kolkata), 
        # we don't need to convert anymore - just return the datetime
        if datetime_obj.tzinfo is None:
            # Add timezone info if missing (assume it's already in local time)
            local_timezone = pytz.timezone('Asia/Kolkata')
            return local_timezone.localize(datetime_obj)
        return datetime_obj
    
    def _setup_custom_styles(self):
        """Setup custom styles for reports"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#0d6efd'),
            alignment=TA_CENTER
        ))
        
        # Heading style
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#6f42c1'),
            borderWidth=1,
            borderColor=colors.HexColor('#6f42c1'),
            borderPadding=5
        ))
        
        # Subheading style
        self.styles.add(ParagraphStyle(
            name='CustomSubheading',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=10,
            textColor=colors.HexColor('#198754')
        ))
        
        # Warning style
        self.styles.add(ParagraphStyle(
            name='Warning',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#dc3545'),
            backColor=colors.HexColor('#f8f9fa'),
            borderWidth=1,
            borderColor=colors.HexColor('#dc3545'),
            borderPadding=10,
            spaceAfter=12
        ))
        
        # Safe style
        self.styles.add(ParagraphStyle(
            name='Safe',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#198754'),
            backColor=colors.HexColor('#f8f9fa'),
            borderWidth=1,
            borderColor=colors.HexColor('#198754'),
            borderPadding=10,
            spaceAfter=12
        ))
    
    def generate_url_report(self, url_check, user=None, format='pdf'):
        """Generate a comprehensive URL security report"""
        if format == 'pdf':
            return self._generate_url_pdf_report(url_check, user)
        elif format == 'csv':
            return self._generate_url_csv_report(url_check, user)
        else:
            raise ValueError("Unsupported format. Use 'pdf' or 'csv'")
    
    def _generate_url_pdf_report(self, url_check, user=None):
        """Generate PDF report for URL security analysis"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        
        story = []
        
        # Header
        story.append(Paragraph("CyberGuard Pro - URL Security Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Report metadata
        story.append(Paragraph("Report Information", self.styles['CustomHeading']))
        
        # Convert analysis time from UTC to local time (for existing data)
        local_analysis_time = self._convert_to_local_time(url_check.checked_at)
        analysis_time = local_analysis_time.strftime('%Y-%m-%d %H:%M:%S')
        report_generation_time = self._get_local_time().strftime('%Y-%m-%d %H:%M:%S')
        
        report_data = [
            ['Report Generated:', report_generation_time],
            ['URL Analyzed:', url_check.url],
            ['Analysis Performed:', analysis_time],
        ]
        
        if user:
            report_data.append(['Generated for:', f"{user.username} ({user.email})"])
        
        report_table = Table(report_data, colWidths=[2*inch, 4*inch])
        report_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(report_table)
        story.append(Spacer(1, 20))
        
        # Security Score
        story.append(Paragraph("Security Analysis Summary", self.styles['CustomHeading']))
        
        score_color = colors.HexColor('#198754') if url_check.security_score >= 70 else \
                     colors.HexColor('#fd7e14') if url_check.security_score >= 40 else \
                     colors.HexColor('#dc3545')
        
        score_text = f"Security Score: {url_check.security_score}/100"
        safety_status = "SAFE" if url_check.is_safe else "POTENTIALLY DANGEROUS"
        
        story.append(Paragraph(f"<font color='{score_color.hexval()}'><b>{score_text}</b></font>", self.styles['Normal']))
        story.append(Paragraph(f"<font color='{score_color.hexval()}'><b>Status: {safety_status}</b></font>", self.styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Detailed Analysis
        story.append(Paragraph("Detailed Security Analysis", self.styles['CustomHeading']))
        
        analysis_data = [
            ['Security Aspect', 'Status', 'Details'],
            ['SSL Certificate', url_check.ssl_status, self._get_ssl_description(url_check.ssl_status)],
            ['Phishing Check', url_check.phishing_status, self._get_phishing_description(url_check.phishing_status)],
            ['Malware Check', url_check.malware_status, self._get_malware_description(url_check.malware_status)],
        ]
        
        if url_check.domain_age:
            analysis_data.append(['Domain Age', f"{url_check.domain_age} days", self._get_age_description(url_check.domain_age)])
        
        analysis_table = Table(analysis_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
        analysis_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        story.append(analysis_table)
        story.append(Spacer(1, 20))
        
        # Threat Types
        if url_check.threat_types:
            threat_list = json.loads(url_check.threat_types) if isinstance(url_check.threat_types, str) else url_check.threat_types
            if threat_list:
                story.append(Paragraph("Identified Threats", self.styles['CustomHeading']))
                for threat in threat_list:
                    story.append(Paragraph(f"• {threat}", self.styles['Warning']))
                story.append(Spacer(1, 15))
        
        # Mistake Description (for registered users)
        if user and url_check.mistake_description:
            story.append(Paragraph("Security Issues Identified", self.styles['CustomHeading']))
            story.append(Paragraph(url_check.mistake_description, self.styles['Warning']))
            story.append(Spacer(1, 15))
        
        # Recommendations
        if url_check.recommendations:
            recommendations = json.loads(url_check.recommendations) if isinstance(url_check.recommendations, str) else url_check.recommendations
            if recommendations:
                story.append(Paragraph("Security Recommendations", self.styles['CustomHeading']))
                for i, recommendation in enumerate(recommendations, 1):
                    story.append(Paragraph(f"{i}. {recommendation}", self.styles['Normal']))
                story.append(Spacer(1, 15))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph("This report was generated by CyberGuard Pro, a comprehensive cybersecurity analysis platform.", self.styles['Normal']))
        story.append(Paragraph("For more information and advanced security tools, visit our platform.", self.styles['Normal']))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def _generate_url_csv_report(self, url_check, user=None):
        """Generate CSV report for URL security analysis"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
        # Convert analysis time from UTC to local time (for existing data)
        local_analysis_time = self._convert_to_local_time(url_check.checked_at)
        analysis_time = local_analysis_time.strftime('%Y-%m-%d %H:%M:%S')
        report_generation_time = self._get_local_time().strftime('%Y-%m-%d %H:%M:%S')
        
        # Headers
        writer.writerow(['URL Security Analysis Report'])
        writer.writerow(['Report Generated:', report_generation_time])
        if user:
            writer.writerow(['User:', f"{user.username} ({user.email})"])
        writer.writerow([])  # Empty row
        
        # URL Information
        writer.writerow(['URL Analyzed:', url_check.url])
        writer.writerow(['Analysis Performed:', analysis_time])
        writer.writerow(['Security Score:', f"{url_check.security_score}/100"])
        writer.writerow(['Safety Status:', 'SAFE' if url_check.is_safe else 'POTENTIALLY DANGEROUS'])
        writer.writerow([])  # Empty row
        
        # Detailed Analysis
        writer.writerow(['Security Analysis Details'])
        writer.writerow(['Aspect', 'Status', 'Description'])
        writer.writerow(['SSL Certificate', url_check.ssl_status, self._get_ssl_description(url_check.ssl_status)])
        writer.writerow(['Phishing Check', url_check.phishing_status, self._get_phishing_description(url_check.phishing_status)])
        writer.writerow(['Malware Check', url_check.malware_status, self._get_malware_description(url_check.malware_status)])
        
        if url_check.domain_age:
            writer.writerow(['Domain Age', f"{url_check.domain_age} days", self._get_age_description(url_check.domain_age)])
        
        writer.writerow([])  # Empty row
        
        # Threats
        if url_check.threat_types:
            threat_list = json.loads(url_check.threat_types) if isinstance(url_check.threat_types, str) else url_check.threat_types
            if threat_list:
                writer.writerow(['Identified Threats'])
                for threat in threat_list:
                    writer.writerow(['', threat])
                writer.writerow([])  # Empty row
        
        # Mistake Description
        if user and url_check.mistake_description:
            writer.writerow(['Security Issues'])
            writer.writerow(['', url_check.mistake_description])
            writer.writerow([])  # Empty row
        
        # Recommendations
        if url_check.recommendations:
            recommendations = json.loads(url_check.recommendations) if isinstance(url_check.recommendations, str) else url_check.recommendations
            if recommendations:
                writer.writerow(['Recommendations'])
                for i, recommendation in enumerate(recommendations, 1):
                    writer.writerow([f"{i}.", recommendation])
        
        buffer.seek(0)
        return buffer
    
    def generate_password_report(self, password_check, user=None, format='pdf'):
        """Generate a comprehensive password security report"""
        if format == 'pdf':
            return self._generate_password_pdf_report(password_check, user)
        elif format == 'csv':
            return self._generate_password_csv_report(password_check, user)
        else:
            raise ValueError("Unsupported format. Use 'pdf' or 'csv'")
    
    def _generate_password_pdf_report(self, password_check, user=None):
        """Generate PDF report for password security analysis"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        
        story = []
        
        # Header
        story.append(Paragraph("CyberGuard Pro - Password Security Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Report metadata
        story.append(Paragraph("Report Information", self.styles['CustomHeading']))
        
        # Convert analysis time from UTC to local time (for existing data)
        local_analysis_time = self._convert_to_local_time(password_check.checked_at)
        analysis_time = local_analysis_time.strftime('%Y-%m-%d %H:%M:%S')
        report_generation_time = self._get_local_time().strftime('%Y-%m-%d %H:%M:%S')
        
        report_data = [
            ['Report Generated:', report_generation_time],
            ['Analysis Performed:', analysis_time],
        ]
        
        if user:
            report_data.append(['Generated for:', f"{user.username} ({user.email})"])
        
        report_table = Table(report_data, colWidths=[2*inch, 4*inch])
        report_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(report_table)
        story.append(Spacer(1, 20))
        
        # Password Strength Score
        story.append(Paragraph("Password Strength Analysis", self.styles['CustomHeading']))
        
        score_color = colors.HexColor('#198754') if password_check.strength_score >= 80 else \
                     colors.HexColor('#fd7e14') if password_check.strength_score >= 60 else \
                     colors.HexColor('#dc3545')
        
        story.append(Paragraph(f"<font color='{score_color.hexval()}'><b>Strength Score: {password_check.strength_score}/100</b></font>", self.styles['Normal']))
        story.append(Paragraph(f"<font color='{score_color.hexval()}'><b>Strength Level: {password_check.strength_level}</b></font>", self.styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Character Analysis
        story.append(Paragraph("Character Analysis", self.styles['CustomHeading']))
        
        char_data = [
            ['Character Type', 'Present', 'Recommendation'],
            ['Uppercase Letters (A-Z)', '✓' if password_check.has_uppercase else '✗', 'Required for strong passwords'],
            ['Lowercase Letters (a-z)', '✓' if password_check.has_lowercase else '✗', 'Required for strong passwords'],
            ['Numbers (0-9)', '✓' if password_check.has_numbers else '✗', 'Adds complexity'],
            ['Special Characters (!@#$)', '✓' if password_check.has_symbols else '✗', 'Significantly increases security'],
        ]
        
        char_table = Table(char_data, colWidths=[2*inch, 1*inch, 3*inch])
        char_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6f42c1')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(char_table)
        story.append(Spacer(1, 20))
        
        # Security Metrics
        story.append(Paragraph("Security Metrics", self.styles['CustomHeading']))
        
        metrics_data = [
            ['Metric', 'Value', 'Assessment'],
            ['Password Entropy', f"{password_check.entropy:.1f} bits", self._get_entropy_assessment(password_check.entropy)],
            ['Character Diversity', self._get_character_diversity(password_check), 'Higher diversity improves security'],
        ]
        
        metrics_table = Table(metrics_data, colWidths=[2*inch, 1.5*inch, 2.5*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 20))
        
        # Mistake Description (for registered users)
        if user and password_check.mistake_description:
            story.append(Paragraph("Password Weaknesses Identified", self.styles['CustomHeading']))
            story.append(Paragraph(password_check.mistake_description, self.styles['Warning']))
            story.append(Spacer(1, 15))
        
        # Recommendations
        if password_check.recommendations:
            recommendations = json.loads(password_check.recommendations) if isinstance(password_check.recommendations, str) else password_check.recommendations
            if recommendations:
                story.append(Paragraph("Security Recommendations", self.styles['CustomHeading']))
                for i, recommendation in enumerate(recommendations, 1):
                    story.append(Paragraph(f"{i}. {recommendation}", self.styles['Normal']))
                story.append(Spacer(1, 15))
        
        # General Password Security Tips
        story.append(Paragraph("General Password Security Best Practices", self.styles['CustomHeading']))
        tips = [
            "Use unique passwords for each account",
            "Enable two-factor authentication when available",
            "Use a reputable password manager",
            "Regularly update passwords for critical accounts",
            "Avoid using personal information in passwords",
            "Consider using passphrases for easy-to-remember strong passwords"
        ]
        
        for i, tip in enumerate(tips, 1):
            story.append(Paragraph(f"{i}. {tip}", self.styles['Normal']))
        
        story.append(Spacer(1, 30))
        story.append(Paragraph("This report was generated by CyberGuard Pro, a comprehensive cybersecurity analysis platform.", self.styles['Normal']))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def _generate_password_csv_report(self, password_check, user=None):
        """Generate CSV report for password security analysis"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
        # Convert analysis time from UTC to local time (for existing data)
        local_analysis_time = self._convert_to_local_time(password_check.checked_at)
        analysis_time = local_analysis_time.strftime('%Y-%m-%d %H:%M:%S')
        report_generation_time = self._get_local_time().strftime('%Y-%m-%d %H:%M:%S')
        
        # Headers
        writer.writerow(['Password Security Analysis Report'])
        writer.writerow(['Report Generated:', report_generation_time])
        if user:
            writer.writerow(['User:', f"{user.username} ({user.email})"])
        writer.writerow([])  # Empty row
        
        # Password Analysis
        writer.writerow(['Analysis Performed:', analysis_time])
        writer.writerow(['Strength Score:', f"{password_check.strength_score}/100"])
        writer.writerow(['Strength Level:', password_check.strength_level])
        writer.writerow([])  # Empty row
        
        # Character Analysis
        writer.writerow(['Character Analysis'])
        writer.writerow(['Character Type', 'Present', 'Recommendation'])
        writer.writerow(['Uppercase Letters', 'Yes' if password_check.has_uppercase else 'No', 'Required for strong passwords'])
        writer.writerow(['Lowercase Letters', 'Yes' if password_check.has_lowercase else 'No', 'Required for strong passwords'])
        writer.writerow(['Numbers', 'Yes' if password_check.has_numbers else 'No', 'Adds complexity'])
        writer.writerow(['Special Characters', 'Yes' if password_check.has_symbols else 'No', 'Significantly increases security'])
        writer.writerow([])  # Empty row
        
        # Security Metrics
        writer.writerow(['Security Metrics'])
        writer.writerow(['Password Entropy', f"{password_check.entropy:.1f} bits"])
        writer.writerow(['Character Diversity', self._get_character_diversity(password_check)])
        writer.writerow([])  # Empty row
        
        # Mistake Description
        if user and password_check.mistake_description:
            writer.writerow(['Password Weaknesses'])
            writer.writerow(['', password_check.mistake_description])
            writer.writerow([])  # Empty row
        
        # Recommendations
        if password_check.recommendations:
            recommendations = json.loads(password_check.recommendations) if isinstance(password_check.recommendations, str) else password_check.recommendations
            if recommendations:
                writer.writerow(['Recommendations'])
                for i, recommendation in enumerate(recommendations, 1):
                    writer.writerow([f"{i}.", recommendation])
        
        buffer.seek(0)
        return buffer
    
    def _get_ssl_description(self, status):
        descriptions = {
            'Valid': 'SSL certificate is valid and properly configured',
            'Expired': 'SSL certificate has expired and needs renewal',
            'No SSL': 'No SSL certificate found - connection is not encrypted',
            'Error': 'Unable to verify SSL certificate status'
        }
        return descriptions.get(status, 'Unknown SSL status')
    
    def _get_phishing_description(self, status):
        descriptions = {
            'Clean': 'No phishing indicators detected',
            'Suspicious': 'Contains patterns commonly associated with phishing attempts',
            'Error': 'Unable to complete phishing analysis'
        }
        return descriptions.get(status, 'Unknown phishing status')
    
    def _get_malware_description(self, status):
        descriptions = {
            'Clean': 'No malware indicators detected',
            'Suspicious': 'Contains keywords or patterns associated with malware',
            'Error': 'Unable to complete malware analysis'
        }
        return descriptions.get(status, 'Unknown malware status')
    
    def _get_age_description(self, age_days):
        if age_days < 30:
            return 'Very new domain - exercise caution'
        elif age_days < 365:
            return 'Relatively new domain'
        elif age_days < 1825:  # 5 years
            return 'Established domain'
        else:
            return 'Well-established domain'
    
    def _get_entropy_assessment(self, entropy):
        if entropy < 25:
            return 'Very Low - Easily crackable'
        elif entropy < 35:
            return 'Low - Vulnerable to attacks'
        elif entropy < 50:
            return 'Moderate - Reasonable security'
        elif entropy < 65:
            return 'Good - Strong security'
        else:
            return 'Excellent - Very strong security'
    
    def _get_character_diversity(self, password_check):
        diversity_score = sum([
            password_check.has_uppercase,
            password_check.has_lowercase,
            password_check.has_numbers,
            password_check.has_symbols
        ])
        
        diversity_levels = {
            1: 'Very Low (1/4 character types)',
            2: 'Low (2/4 character types)',
            3: 'Good (3/4 character types)',
            4: 'Excellent (4/4 character types)'
        }
        
        return diversity_levels.get(diversity_score, 'Unknown')
    
    def generate_personal_password_report(self, personal_passwords, user=None, format='pdf'):
        """Generate a comprehensive personal password generation report"""
        if format == 'pdf':
            return self._generate_personal_password_pdf_report(personal_passwords, user)
        else:
            return self._generate_personal_password_csv_report(personal_passwords, user)
    
    def _generate_personal_password_pdf_report(self, personal_passwords, user=None):
        """Generate PDF report for personal password generation"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        content = []
        
        # Header
        content.append(Paragraph("Personal Password Generation Report", self.styles['CustomTitle']))
        content.append(Spacer(1, 20))
        
        # Report metadata
        if user:
            content.append(Paragraph(f"<b>User:</b> {user.username}", self.styles['Normal']))
        
        local_time = self._get_local_time()
        content.append(Paragraph(f"<b>Report Generated:</b> {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}", self.styles['Normal']))
        
        if personal_passwords:
            first_password = personal_passwords[0]
            analysis_time = self._convert_to_local_time(first_password.created_at)
            content.append(Paragraph(f"<b>Passwords Generated:</b> {analysis_time.strftime('%Y-%m-%d %H:%M:%S %Z')}", self.styles['Normal']))
        
        content.append(Paragraph(f"<b>Total Passwords:</b> {len(personal_passwords)}", self.styles['Normal']))
        content.append(Spacer(1, 20))
        
        # Executive Summary
        content.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
        
        if personal_passwords:
            avg_strength = sum(pwd.strength_score for pwd in personal_passwords) / len(personal_passwords)
            strongest_password = max(personal_passwords, key=lambda x: x.strength_score)
            
            content.append(Paragraph(f"Generated {len(personal_passwords)} personalized passwords based on your information.", self.styles['Normal']))
            content.append(Paragraph(f"Average strength score: {avg_strength:.1f}/100", self.styles['Normal']))
            content.append(Paragraph(f"Strongest password score: {strongest_password.strength_score}/100", self.styles['Normal']))
            content.append(Spacer(1, 15))
        
        # Individual Password Analysis
        content.append(Paragraph("Password Analysis", self.styles['CustomHeading']))
        
        for i, password in enumerate(personal_passwords, 1):
            content.append(Paragraph(f"Password #{i}", self.styles['CustomSubheading']))
            
            # Create password details table
            password_data = [
                ['Property', 'Value'],
                ['Purpose', password.purpose],
                ['Length', f"{password.length} characters"],
                ['Strength Score', f"{password.strength_score}/100"],
                ['Character Types', self._get_personal_password_character_types(password)],
                ['Created', self._convert_to_local_time(password.created_at).strftime('%Y-%m-%d %H:%M:%S')],
                ['Status', 'Active' if password.is_active else 'Inactive']
            ]
            
            password_table = Table(password_data, colWidths=[2*inch, 4*inch])
            password_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6f42c1')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            content.append(password_table)
            content.append(Spacer(1, 15))
        
        # Security Recommendations
        content.append(Paragraph("Security Recommendations", self.styles['CustomHeading']))
        recommendations = [
            "Use the password with the highest strength score for your most important accounts",
            "Never use the exact same password on multiple websites or services",
            "Consider these as base passwords and add site-specific characters",
            "Store your passwords securely using a reputable password manager",
            "Change passwords immediately if you suspect they have been compromised",
            "Enable two-factor authentication (2FA) wherever possible",
            "Regularly update your passwords, especially for critical accounts"
        ]
        
        for i, recommendation in enumerate(recommendations, 1):
            content.append(Paragraph(f"{i}. {recommendation}", self.styles['Normal']))
        
        content.append(Spacer(1, 20))
        
        # Footer
        content.append(Paragraph("Generated by CyberGuard Pro", self.styles['Normal']))
        content.append(Paragraph("Keep your digital life secure", self.styles['Normal']))
        
        doc.build(content)
        buffer.seek(0)
        return buffer
    
    def _generate_personal_password_csv_report(self, personal_passwords, user=None):
        """Generate CSV report for personal password generation"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
        # Header
        writer.writerow(['Personal Password Generation Report'])
        writer.writerow(['Generated by CyberGuard Pro'])
        writer.writerow([])
        
        # Metadata
        if user:
            writer.writerow(['User', user.username])
        
        local_time = self._get_local_time()
        writer.writerow(['Report Generated', local_time.strftime('%Y-%m-%d %H:%M:%S %Z')])
        
        if personal_passwords:
            first_password = personal_passwords[0]
            analysis_time = self._convert_to_local_time(first_password.created_at)
            writer.writerow(['Passwords Generated', analysis_time.strftime('%Y-%m-%d %H:%M:%S %Z')])
        
        writer.writerow(['Total Passwords', len(personal_passwords)])
        writer.writerow([])
        
        # Password details header
        writer.writerow(['Password #', 'Purpose', 'Length', 'Strength Score', 'Uppercase', 'Lowercase', 'Numbers', 'Symbols', 'Created', 'Active'])
        
        # Password details
        for i, password in enumerate(personal_passwords, 1):
            created_time = self._convert_to_local_time(password.created_at).strftime('%Y-%m-%d %H:%M:%S')
            writer.writerow([
                f"Password {i}",
                password.purpose,
                password.length,
                password.strength_score,
                'Yes' if password.include_uppercase else 'No',
                'Yes' if password.include_lowercase else 'No',
                'Yes' if password.include_numbers else 'No',
                'Yes' if password.include_symbols else 'No',
                created_time,
                'Active' if password.is_active else 'Inactive'
            ])
        
        writer.writerow([])
        
        # Summary statistics
        if personal_passwords:
            avg_strength = sum(pwd.strength_score for pwd in personal_passwords) / len(personal_passwords)
            max_strength = max(pwd.strength_score for pwd in personal_passwords)
            min_strength = min(pwd.strength_score for pwd in personal_passwords)
            
            writer.writerow(['Summary Statistics'])
            writer.writerow(['Average Strength Score', f"{avg_strength:.1f}/100"])
            writer.writerow(['Highest Strength Score', f"{max_strength}/100"])
            writer.writerow(['Lowest Strength Score', f"{min_strength}/100"])
        
        buffer.seek(0)
        return io.BytesIO(buffer.getvalue().encode('utf-8'))
    
    def _get_personal_password_character_types(self, password):
        """Get character types used in personal password"""
        types = []
        if password.include_uppercase:
            types.append('Uppercase')
        if password.include_lowercase:
            types.append('Lowercase')
        if password.include_numbers:
            types.append('Numbers')
        if password.include_symbols:
            types.append('Symbols')
        return ', '.join(types) if types else 'None'
    
    def generate_generated_password_report(self, generated_password, user=None, format='pdf'):
        """Generate a comprehensive generated password report"""
        if format == 'pdf':
            return self._generate_generated_password_pdf_report(generated_password, user)
        else:
            return self._generate_generated_password_csv_report(generated_password, user)
    
    def _generate_generated_password_pdf_report(self, generated_password, user=None):
        """Generate PDF report for generated password"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        content = []
        
        # Header
        content.append(Paragraph("Generated Password Report", self.styles['CustomTitle']))
        content.append(Spacer(1, 20))
        
        # Report metadata
        if user:
            content.append(Paragraph(f"<b>User:</b> {user.username}", self.styles['Normal']))
        
        local_time = self._get_local_time()
        content.append(Paragraph(f"<b>Report Generated:</b> {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}", self.styles['Normal']))
        
        generation_time = self._convert_to_local_time(generated_password.generated_at)
        content.append(Paragraph(f"<b>Password Generated:</b> {generation_time.strftime('%Y-%m-%d %H:%M:%S %Z')}", self.styles['Normal']))
        content.append(Spacer(1, 20))
        
        # Password Details
        content.append(Paragraph("Password Configuration", self.styles['CustomHeading']))
        
        password_data = [
            ['Property', 'Value'],
            ['Length', f"{generated_password.length} characters"],
            ['Purpose', generated_password.usage_purpose or 'General use'],
            ['Strength Score', f"{generated_password.strength_score}/100"],
            ['Include Uppercase', 'Yes' if generated_password.include_uppercase else 'No'],
            ['Include Lowercase', 'Yes' if generated_password.include_lowercase else 'No'],
            ['Include Numbers', 'Yes' if generated_password.include_numbers else 'No'],
            ['Include Symbols', 'Yes' if generated_password.include_symbols else 'No'],
            ['Exclude Ambiguous', 'Yes' if generated_password.exclude_ambiguous else 'No'],
            ['Generated', generation_time.strftime('%Y-%m-%d %H:%M:%S')],
        ]
        
        password_table = Table(password_data, colWidths=[2.5*inch, 3.5*inch])
        password_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6f42c1')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        content.append(password_table)
        content.append(Spacer(1, 20))
        
        # Strength Analysis
        content.append(Paragraph("Strength Analysis", self.styles['CustomHeading']))
        
        strength_color = 'green' if generated_password.strength_score >= 70 else 'orange' if generated_password.strength_score >= 50 else 'red'
        strength_level = 'Strong' if generated_password.strength_score >= 70 else 'Moderate' if generated_password.strength_score >= 50 else 'Weak'
        
        content.append(Paragraph(f"<b>Overall Strength:</b> <font color='{strength_color}'>{strength_level} ({generated_password.strength_score}/100)</font>", self.styles['Normal']))
        content.append(Spacer(1, 10))
        
        # Character composition
        char_types = []
        if generated_password.include_uppercase: char_types.append('Uppercase letters')
        if generated_password.include_lowercase: char_types.append('Lowercase letters') 
        if generated_password.include_numbers: char_types.append('Numbers')
        if generated_password.include_symbols: char_types.append('Special characters')
        
        content.append(Paragraph(f"<b>Character Types Used:</b> {', '.join(char_types)}", self.styles['Normal']))
        content.append(Spacer(1, 15))
        
        # Security Recommendations
        content.append(Paragraph("Security Recommendations", self.styles['CustomHeading']))
        recommendations = [
            "Store this password securely using a password manager",
            "Never share this password with others or write it down in plain text",
            "Use unique passwords for each account - never reuse this password",
            "Change this password immediately if you suspect it has been compromised",
            "Enable two-factor authentication (2FA) on accounts using this password",
            "Regularly update your passwords, especially for critical accounts"
        ]
        
        for i, recommendation in enumerate(recommendations, 1):
            content.append(Paragraph(f"{i}. {recommendation}", self.styles['Normal']))
        
        content.append(Spacer(1, 20))
        
        # Footer
        content.append(Paragraph("Generated by CyberGuard Pro", self.styles['Normal']))
        content.append(Paragraph("Keep your digital life secure", self.styles['Normal']))
        
        doc.build(content)
        buffer.seek(0)
        return buffer
    
    def _generate_generated_password_csv_report(self, generated_password, user=None):
        """Generate CSV report for generated password"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
        # Header
        writer.writerow(['Generated Password Report'])
        writer.writerow(['Generated by CyberGuard Pro'])
        writer.writerow([])
        
        # Metadata
        if user:
            writer.writerow(['User', user.username])
        
        local_time = self._get_local_time()
        writer.writerow(['Report Generated', local_time.strftime('%Y-%m-%d %H:%M:%S %Z')])
        
        generation_time = self._convert_to_local_time(generated_password.generated_at)
        writer.writerow(['Password Generated', generation_time.strftime('%Y-%m-%d %H:%M:%S %Z')])
        writer.writerow([])
        
        # Password details
        writer.writerow(['Password Configuration'])
        writer.writerow(['Length', f"{generated_password.length} characters"])
        writer.writerow(['Purpose', generated_password.usage_purpose or 'General use'])
        writer.writerow(['Strength Score', f"{generated_password.strength_score}/100"])
        writer.writerow(['Include Uppercase', 'Yes' if generated_password.include_uppercase else 'No'])
        writer.writerow(['Include Lowercase', 'Yes' if generated_password.include_lowercase else 'No'])
        writer.writerow(['Include Numbers', 'Yes' if generated_password.include_numbers else 'No'])
        writer.writerow(['Include Symbols', 'Yes' if generated_password.include_symbols else 'No'])
        writer.writerow(['Exclude Ambiguous', 'Yes' if generated_password.exclude_ambiguous else 'No'])
        writer.writerow(['Generated', generation_time.strftime('%Y-%m-%d %H:%M:%S')])
        
        buffer.seek(0)
        return io.BytesIO(buffer.getvalue().encode('utf-8'))
    
    def generate_summary_report(self, url_checks, generated_passwords, password_checks, user=None):
        """Generate a comprehensive summary PDF report with all security activities"""
        try:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            
            # Prepare the content
            content = []
            
            # Title
            title = Paragraph("Security Activity Summary Report", self.styles['CustomTitle'])
            content.append(title)
            content.append(Spacer(1, 20))
            
            # User info
            local_time = self._get_local_time()
            user_info = f"""
            <b>User:</b> {user.username if user else 'Anonymous'}<br/>
            <b>Email:</b> {user.email if user else 'N/A'}<br/>
            <b>Report Generated:</b> {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}<br/>
            <b>Total Activities:</b> {len(url_checks) + len(generated_passwords) + len(password_checks)}
            """
            content.append(Paragraph(user_info, self.styles['Normal']))
            content.append(Spacer(1, 20))
            
            # Summary statistics
            content.append(Paragraph("Summary Statistics", self.styles['CustomHeading']))
            
            stats_data = [
                ['Activity Type', 'Count'],
                ['URL Security Checks', str(len(url_checks))],
                ['Generated Passwords', str(len(generated_passwords))],
                ['Password Strength Checks', str(len(password_checks))],
                ['Total Activities', str(len(url_checks) + len(generated_passwords) + len(password_checks))]
            ]
            
            stats_table = Table(stats_data, colWidths=[3*inch, 1*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            content.append(stats_table)
            content.append(Spacer(1, 20))
            
            # URL Checks Section
            if url_checks:
                content.append(Paragraph("URL Security Checks", self.styles['CustomHeading']))
                
                url_data = [['URL', 'Safety Score', 'Status', 'Date']]
                for check in url_checks[:20]:  # Limit to first 20 entries
                    status = 'Safe' if check.is_safe else 'Risk Detected'
                    check_date = self._convert_to_local_time(check.checked_at)
                    url_data.append([
                        check.url[:50] + '...' if len(check.url) > 50 else check.url,
                        f'{check.security_score}%',
                        status,
                        check_date.strftime('%Y-%m-%d %H:%M')
                    ])
                
                url_table = Table(url_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1.5*inch])
                url_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#198754')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                content.append(url_table)
                content.append(Spacer(1, 20))
            
            # Generated Passwords Section
            if generated_passwords:
                content.append(Paragraph("Generated Passwords", self.styles['CustomHeading']))
                
                password_data = [['Length', 'Strength', 'Purpose', 'Date']]
                for pwd in generated_passwords[:20]:  # Limit to first 20 entries
                    pwd_date = self._convert_to_local_time(pwd.generated_at)
                    password_data.append([
                        f'{pwd.length} chars',
                        f'{pwd.strength_score}%' if pwd.strength_score else 'N/A',
                        pwd.usage_purpose[:30] + '...' if pwd.usage_purpose and len(pwd.usage_purpose) > 30 else pwd.usage_purpose or 'General',
                        pwd_date.strftime('%Y-%m-%d %H:%M')
                    ])
                
                password_table = Table(password_data, colWidths=[1*inch, 1*inch, 2*inch, 1.5*inch])
                password_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6f42c1')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                content.append(password_table)
                content.append(Spacer(1, 20))
            
            # Password Checks Section
            if password_checks:
                content.append(Paragraph("Password Strength Checks", self.styles['CustomHeading']))
                
                check_data = [['Strength Score', 'Level', 'Character Types', 'Date']]
                for check in password_checks[:20]:  # Limit to first 20 entries
                    char_types = []
                    if check.has_uppercase: char_types.append('A-Z')
                    if check.has_lowercase: char_types.append('a-z')
                    if check.has_numbers: char_types.append('0-9')
                    if check.has_symbols: char_types.append('!@#')
                    
                    check_date = self._convert_to_local_time(check.checked_at)
                    check_data.append([
                        f'{check.strength_score}%',
                        check.strength_level,
                        ', '.join(char_types),
                        check_date.strftime('%Y-%m-%d %H:%M')
                    ])
                
                check_table = Table(check_data, colWidths=[1*inch, 1.5*inch, 1.5*inch, 1.5*inch])
                check_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fd7e14')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                content.append(check_table)
                content.append(Spacer(1, 20))
            
            # Footer
            footer_text = f"""
            <i>This report was generated by CyberGuard Pro on {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}.<br/>
            For more information, visit our platform for detailed security analysis and recommendations.</i>
            """
            content.append(Paragraph(footer_text, self.styles['Normal']))
            
            # Build the PDF
            doc.build(content)
            
            buffer.seek(0)
            return buffer
            
        except Exception as e:
            logger.error(f"Summary report generation error: {str(e)}")
            raise

    def generate_admin_users_report(self, users, format='pdf'):
        """Generate admin users report in PDF or CSV format"""
        try:
            if format == 'pdf':
                return self._generate_admin_users_pdf_report(users)
            else:
                return self._generate_admin_users_csv_report(users)
        except Exception as e:
            logger.error(f"Admin users report generation error: {str(e)}")
            raise

    def _generate_admin_users_pdf_report(self, users):
        """Generate PDF report for admin users"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        
        content = []
        
        # Title
        title = Paragraph("Admin Users Report", self.styles['CustomTitle'])
        content.append(title)
        content.append(Spacer(1, 20))
        
        # Report info
        local_time = self._get_local_time()
        report_info = f"""
        <b>Report Generated:</b> {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}<br/>
        <b>Total Users:</b> {len(users)}<br/>
        <b>Admin Users:</b> {len([u for u in users if u.is_admin])}<br/>
        <b>Regular Users:</b> {len([u for u in users if not u.is_admin])}
        """
        content.append(Paragraph(report_info, self.styles['Normal']))
        content.append(Spacer(1, 20))
        
        # Users table
        content.append(Paragraph("User Details", self.styles['CustomHeading']))
        
        table_data = [['Username', 'Email', 'Type', 'Joined', 'Last Login', 'URL Checks', 'Password Checks']]
        
        for user in users:
            user_type = 'Admin' if user.is_admin else 'User'
            joined = self._convert_to_local_time(user.created_at)
            last_login = self._convert_to_local_time(user.last_login) if user.last_login else None
            
            table_data.append([
                user.username,
                user.email,
                user_type,
                joined.strftime('%Y-%m-%d'),
                last_login.strftime('%Y-%m-%d %H:%M') if last_login else 'Never',
                str(len(user.url_checks)),
                str(len(user.password_checks))
            ])
        
        table = Table(table_data, colWidths=[1*inch, 2*inch, 0.8*inch, 1*inch, 1.2*inch, 0.8*inch, 0.8*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        content.append(table)
        
        # Footer
        footer_text = f"""
        <i>This admin report was generated by CyberGuard Pro on {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}.</i>
        """
        content.append(Spacer(1, 20))
        content.append(Paragraph(footer_text, self.styles['Normal']))
        
        doc.build(content)
        buffer.seek(0)
        return buffer

    def _generate_admin_users_csv_report(self, users):
        """Generate CSV report for admin users"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
        # Header
        writer.writerow(['Username', 'Email', 'Type', 'Joined', 'Last Login', 'URL Checks', 'Password Checks'])
        
        # Data
        for user in users:
            user_type = 'Admin' if user.is_admin else 'User'
            joined = self._convert_to_local_time(user.created_at)
            last_login = self._convert_to_local_time(user.last_login) if user.last_login else None
            
            writer.writerow([
                user.username,
                user.email,
                user_type,
                joined.strftime('%Y-%m-%d'),
                last_login.strftime('%Y-%m-%d %H:%M') if last_login else 'Never',
                len(user.url_checks),
                len(user.password_checks)
            ])
        
        buffer.seek(0)
        return io.BytesIO(buffer.getvalue().encode('utf-8'))

    def generate_admin_activity_report(self, url_checks, password_checks, generated_passwords, format='pdf'):
        """Generate admin activity report in PDF or CSV format"""
        try:
            if format == 'pdf':
                return self._generate_admin_activity_pdf_report(url_checks, password_checks, generated_passwords)
            else:
                return self._generate_admin_activity_csv_report(url_checks, password_checks, generated_passwords)
        except Exception as e:
            logger.error(f"Admin activity report generation error: {str(e)}")
            raise

    def _generate_admin_activity_pdf_report(self, url_checks, password_checks, generated_passwords):
        """Generate PDF report for admin activity"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        
        content = []
        
        # Title
        title = Paragraph("Admin Activity Report", self.styles['CustomTitle'])
        content.append(title)
        content.append(Spacer(1, 20))
        
        # Report info
        local_time = self._get_local_time()
        report_info = f"""
        <b>Report Generated:</b> {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}<br/>
        <b>Total URL Checks:</b> {len(url_checks)}<br/>
        <b>Total Password Checks:</b> {len(password_checks)}<br/>
        <b>Total Generated Passwords:</b> {len(generated_passwords)}
        """
        content.append(Paragraph(report_info, self.styles['Normal']))
        content.append(Spacer(1, 20))
        
        # URL Checks Section
        if url_checks:
            content.append(Paragraph("URL Security Checks", self.styles['CustomHeading']))
            
            safe_count = len([u for u in url_checks if u.security_score >= 70])
            suspicious_count = len([u for u in url_checks if 40 <= u.security_score < 70])
            dangerous_count = len([u for u in url_checks if u.security_score < 40])
            
            stats_text = f"""
            <b>Safe URLs:</b> {safe_count} ({safe_count/len(url_checks)*100:.1f}%)<br/>
            <b>Suspicious URLs:</b> {suspicious_count} ({suspicious_count/len(url_checks)*100:.1f}%)<br/>
            <b>Dangerous URLs:</b> {dangerous_count} ({dangerous_count/len(url_checks)*100:.1f}%)
            """
            content.append(Paragraph(stats_text, self.styles['Normal']))
            content.append(Spacer(1, 10))
            
            # Recent URL checks table
            url_data = [['User', 'URL', 'Score', 'Status', 'Date']]
            for check in url_checks[:50]:  # Limit to first 50
                status = 'Safe' if check.security_score >= 70 else 'Suspicious' if check.security_score >= 40 else 'Dangerous'
                check_date = self._convert_to_local_time(check.checked_at)
                url_data.append([
                    check.user.username if check.user else 'Anonymous',
                    check.url[:40] + '...' if len(check.url) > 40 else check.url,
                    f'{check.security_score}%',
                    status,
                    check_date.strftime('%Y-%m-%d %H:%M')
                ])
            
            url_table = Table(url_data, colWidths=[1*inch, 2.5*inch, 0.8*inch, 1*inch, 1.2*inch])
            url_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#198754')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            content.append(url_table)
            content.append(Spacer(1, 20))
        
        # Footer
        footer_text = f"""
        <i>This admin activity report was generated by CyberGuard Pro on {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}.</i>
        """
        content.append(Paragraph(footer_text, self.styles['Normal']))
        
        doc.build(content)
        buffer.seek(0)
        return buffer

    def _generate_admin_activity_csv_report(self, url_checks, password_checks, generated_passwords):
        """Generate CSV report for admin activity"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
        # Header
        writer.writerow(['Type', 'User', 'Details', 'Result', 'Date'])
        
        # URL Checks
        for check in url_checks:
            status = 'Safe' if check.security_score >= 70 else 'Suspicious' if check.security_score >= 40 else 'Dangerous'
            check_date = self._convert_to_local_time(check.checked_at)
            writer.writerow([
                'URL Check',
                check.user.username if check.user else 'Anonymous',
                check.url,
                f'{check.security_score}% - {status}',
                check_date.strftime('%Y-%m-%d %H:%M')
            ])
        
        # Password Checks
        for check in password_checks:
            check_date = self._convert_to_local_time(check.checked_at)
            writer.writerow([
                'Password Check',
                check.user.username if check.user else 'Anonymous',
                'Password Analysis',
                f'{check.strength_score}% - {check.strength_level}',
                check_date.strftime('%Y-%m-%d %H:%M')
            ])
        
        # Generated Passwords
        for pwd in generated_passwords:
            pwd_date = self._convert_to_local_time(pwd.generated_at)
            writer.writerow([
                'Generated Password',
                pwd.user.username if pwd.user else 'Anonymous',
                f'Length: {pwd.length}',
                f'{pwd.strength_score}%' if pwd.strength_score else 'N/A',
                pwd_date.strftime('%Y-%m-%d %H:%M')
            ])
        
        buffer.seek(0)
        return io.BytesIO(buffer.getvalue().encode('utf-8'))

    def generate_admin_feedback_report(self, feedback_responses, format="pdf"):
        """Generate admin feedback report in PDF or CSV format"""
        try:
            if format == "pdf":
                return self._generate_admin_feedback_pdf_report(feedback_responses)
            else:
                return self._generate_admin_feedback_csv_report(feedback_responses)
        except Exception as e:
            logger.error(f"Admin feedback report generation error: {str(e)}")
            raise

    def _generate_admin_feedback_pdf_report(self, feedback_responses):
        """Generate PDF report for admin feedback"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        
        content = []
        
        # Title
        title = Paragraph("Admin Feedback Report", self.styles["CustomTitle"])
        content.append(title)
        content.append(Spacer(1, 20))
        
        # Report info
        local_time = self._get_local_time()
        reviewed_count = len([f for f in feedback_responses if f.is_reviewed])
        pending_count = len([f for f in feedback_responses if not f.is_reviewed])
        
        # Calculate average rating
        ratings = [f.satisfaction_rating for f in feedback_responses if f.satisfaction_rating]
        avg_rating = sum(ratings) / len(ratings) if ratings else 0
        
        report_info = f"""
        <b>Report Generated:</b> {local_time.strftime("%Y-%m-%d %H:%M:%S %Z")}<br/>
        <b>Total Feedback:</b> {len(feedback_responses)}<br/>
        <b>Reviewed:</b> {reviewed_count}<br/>
        <b>Pending:</b> {pending_count}<br/>
        <b>Average Rating:</b> {avg_rating:.1f}/5.0
        """
        content.append(Paragraph(report_info, self.styles["Normal"]))
        content.append(Spacer(1, 20))
        
        # Feedback table
        content.append(Paragraph("Feedback Details", self.styles["CustomHeading"]))
        
        table_data = [["Name", "Email", "Experience", "Rating", "Status", "Submitted"]]
        
        for feedback in feedback_responses:
            status = "Reviewed" if feedback.is_reviewed else "Pending"
            submitted = self._convert_to_local_time(feedback.submitted_at)
            
            table_data.append([
                feedback.name,
                feedback.email,
                feedback.experience_level or "N/A",
                f"{feedback.satisfaction_rating or 0}/5",
                status,
                submitted.strftime("%Y-%m-%d %H:%M")
            ])
        
        table = Table(table_data, colWidths=[1.2*inch, 1.5*inch, 1*inch, 0.8*inch, 0.8*inch, 1.2*inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6f42c1")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black)
        ]))
        content.append(table)
        content.append(Spacer(1, 20))
        
        # Footer
        footer_text = f"""
        <i>This admin feedback report was generated by CyberGuard Pro on {local_time.strftime("%Y-%m-%d %H:%M:%S %Z")}.</i>
        """
        content.append(Paragraph(footer_text, self.styles["Normal"]))
        
        doc.build(content)
        buffer.seek(0)
        return buffer

    def _generate_admin_feedback_csv_report(self, feedback_responses):
        """Generate CSV report for admin feedback"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
        # Header
        writer.writerow(["Name", "Email", "Experience", "Primary Concern", "Rating", "Tools Used", 
                        "Improvement Suggestions", "Feature Requests", "Status", "Submitted", "Reviewer Notes"])
        
        # Data
        for feedback in feedback_responses:
            status = "Reviewed" if feedback.is_reviewed else "Pending"
            submitted = self._convert_to_local_time(feedback.submitted_at)
            
            writer.writerow([
                feedback.name,
                feedback.email,
                feedback.experience_level or "N/A",
                feedback.primary_concern or "N/A",
                f"{feedback.satisfaction_rating or 0}/5",
                feedback.tools_used or "N/A",
                feedback.improvement_suggestions or "N/A",
                feedback.feature_requests or "N/A",
                status,
                submitted.strftime("%Y-%m-%d %H:%M"),
                feedback.reviewer_notes or "N/A"
            ])
        
        buffer.seek(0)
        return io.BytesIO(buffer.getvalue().encode("utf-8"))

