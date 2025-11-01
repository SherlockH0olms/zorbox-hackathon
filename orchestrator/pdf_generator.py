#!/usr/bin/env python3
"""
PDF hesabat generator
"""
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from datetime import datetime
import json

class PDFReportGenerator:
    def __init__(self, output_path):
        self.doc = SimpleDocTemplate(output_path, pagesize=A4)
        self.styles = getSampleStyleSheet()
        self.story = []
        
        # Custom styles
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#333333'),
            spaceAfter=12
        )
    
    def add_header(self, report_data):
        """
        PDF header
        """
        # Titlel;
        title = Paragraph("🛡️ ZORBOX Analysis Report", self.title_style)
        self.story.append(title)
        self.story.append(Spacer(1, 0.2*inch))
        
        # Metadata cedveli
        metadata = [
            ['File Name:', report_data.get('file_name', 'N/A')],
            ['SHA-256 Hash:', report_data.get('file_hash', 'N/A')],
            ['File Type:', report_data.get('file_type', 'N/A')],
            ['Analysis Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ]
        
        t = Table(metadata, colWidths=[2*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        
        self.story.append(t)
        self.story.append(Spacer(1, 0.3*inch))
    
    def add_risk_assessment(self, report_data):
        """
        Risk qiymətləndirməsi bölməsi
        """
        heading = Paragraph("Risk Assessment", self.heading_style)
        self.story.append(heading)
        
        risk_score = report_data.get('final_risk_score', 0)
        risk_level = report_data.get('final_risk_level', 'UNKNOWN')
        
        # Risk level reng
        risk_colors = {
            'LOW': colors.green,
            'MEDIUM': colors.orange,
            'HIGH': colors.orangered,
            'CRITICAL': colors.red
        }
        risk_color = risk_colors.get(risk_level, colors.grey)
        
        risk_data = [
            ['Risk Score:', f"{risk_score}/100"],
            ['Risk Level:', risk_level]
        ]
        
        t = Table(risk_data, colWidths=[2*inch, 2*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (1, 1), (1, 1), risk_color),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        
        self.story.append(t)
        self.story.append(Spacer(1, 0.2*inch))
    
    def add_static_analysis(self, static_data):
        """
        Statik analiz bölməsi
        """
        heading = Paragraph("Static Analysis", self.heading_style)
        self.story.append(heading)
        
        # YARA match
        yara_matches = static_data.get('yara_matches', [])
        if yara_matches:
            yara_text = Paragraph(f"<b>YARA Signatures:</b> {', '.join(yara_matches)}", self.styles['Normal'])
            self.story.append(yara_text)
        
        # Entropy
        entropy = static_data.get('entropy', 0)
        entropy_text = Paragraph(f"<b>Entropy:</b> {entropy:.2f}", self.styles['Normal'])
        self.story.append(entropy_text)
        
        # Suspicious imports
        imports = static_data.get('imports', [])
        if imports:
            imports_text = Paragraph(f"<b>Suspicious Imports:</b> {', '.join(imports[:10])}", self.styles['Normal'])
            self.story.append(imports_text)
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def add_sandbox_analysis(self, sandbox_data):
        """
        Sandbox analiz bölməsi
        """
        heading = Paragraph("Sandbox Analysis", self.heading_style)
        self.story.append(heading)
        
        # Network activty
        network = "Yes" if sandbox_data.get('network_activity', False) else "No"
        network_text = Paragraph(f"<b>Network Activity:</b> {network}", self.styles['Normal'])
        self.story.append(network_text)
        
        # File modifications
        file_mods = sandbox_data.get('file_modifications', 0)
        file_text = Paragraph(f"<b>File Modifications:</b> {file_mods}", self.styles['Normal'])
        self.story.append(file_text)
        
        # Suspicious behavours
        behaviors = sandbox_data.get('suspicious_behaviors', [])
        if behaviors:
            self.story.append(Paragraph("<b>Suspicious Behaviors:</b>", self.styles['Normal']))
            for behavior in behaviors[:5]:
                behavior_text = f"• {behavior.get('type')}: {behavior.get('value', 'N/A')}"
                self.story.append(Paragraph(behavior_text, self.styles['Normal']))
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def add_ai_analysis(self, ai_data):
        """
        AI analiz bölməsi
        """
        heading = Paragraph("AI Risk Assessment", self.heading_style)
        self.story.append(heading)
        
        ai_score = ai_data.get('ai_score', 0)
        confidence = ai_data.get('confidence', 0)
        
        ai_text = Paragraph(f"<b>AI Score:</b> {ai_score}/100 (Confidence: {confidence:.1f}%)", self.styles['Normal'])
        self.story.append(ai_text)
        
        # Explanatins
        explanation = ai_data.get('explanation', [])
        if explanation:
            self.story.append(Paragraph("<b>Analysis Explanation:</b>", self.styles['Normal']))
            for line in explanation:
                self.story.append(Paragraph(f"• {line}", self.styles['Normal']))
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def generate(self, report_data):
        """
        PDF-i yarat
        """
        self.add_header(report_data)
        self.add_risk_assessment(report_data)
        
        # Static analysis
        if 'static_analysis' in report_data:
            self.add_static_analysis(report_data['static_analysis'])
        
        # Sandbox analysis
        if 'sandbox_analysis' in report_data:
            self.add_sandbox_analysis(report_data['sandbox_analysis'])
        
        # AI analysis
        if 'ai_scoring' in report_data:
            self.add_ai_analysis(report_data['ai_scoring'])
        
        # Build pdf
        self.doc.build(self.story)

def generate_pdf_report(report_json, output_path):
    """
    JSON report-dan PDF yarat
    """
    generator = PDFReportGenerator(output_path)
    generator.generate(report_json)
    print(f"PDF report generated: {output_path}")