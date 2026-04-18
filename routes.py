from flask import render_template, request, redirect, url_for, flash, session, make_response, jsonify, send_file
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import app, db
from models import User, URLCheck, PasswordCheck, GeneratedPassword, SurveyResponse, PersonalPasswordGeneration, SecurityReport
from security_analysis import SecurityAnalyzer
from report_generator import ReportGenerator
from datetime import datetime, timedelta
from models import get_current_time
from flask_bcrypt import Bcrypt

import io
import csv
import json
import logging
import tempfile
import os

# Set up logging
logger = logging.getLogger(__name__)

security_analyzer = SecurityAnalyzer()
report_generator = ReportGenerator()

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.route('/')
def index():
    try:
        if current_user.is_authenticated and current_user.is_admin:
            # Get statistics for admin users
            stats = {
                'total_users': User.query.count(),
                'total_url_checks': URLCheck.query.count(),
                'total_password_checks': PasswordCheck.query.count(),
                'total_generated_passwords': GeneratedPassword.query.count(),
                'total_personal_passwords': PersonalPasswordGeneration.query.count(),
                'total_surveys': SurveyResponse.query.count(),
                'unreviewed_surveys': SurveyResponse.query.filter_by(is_reviewed=False).count()
            }
            return render_template('index.html', stats=stats)
    except Exception as e:
        logger.error(f"Error getting admin stats on index: {str(e)}")
    
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/cyber-threats')
def cyber_threats():
    return render_template('cyber_threats.html')

@app.route('/common-measures')
def common_measures():
    return render_template('common_measures.html')

@app.route('/url-checker', methods=['GET', 'POST'])
def url_checker():
    if request.method == 'POST':
        try:
            url = request.form.get('url', '').strip()
            
            if not url:
                flash('Please enter a URL to check.', 'error')
                return render_template('url_checker.html')
            
            # Perform security analysis
            analysis_result = security_analyzer.analyze_url_comprehensive(url)
            
            # Save to database
            url_check = URLCheck()
            url_check.url = url
            url_check.is_safe = analysis_result['is_safe']
            url_check.security_score = analysis_result['security_score']
            url_check.threat_types = json.dumps(analysis_result['threat_types'])
            url_check.phishing_status = analysis_result['phishing_status']
            url_check.ssl_status = analysis_result['ssl_status']
            url_check.malware_status = analysis_result['malware_status']
            url_check.domain_age = analysis_result.get('domain_age')
            url_check.detailed_analysis = json.dumps(analysis_result.get('detailed_analysis', {}))
            url_check.mistake_description = analysis_result.get('mistake_description', '')
            url_check.recommendations = json.dumps(analysis_result.get('recommendations', []))
            url_check.checked_at = get_current_time()
            url_check.ip_address = request.remote_addr
            
            if current_user.is_authenticated:
                url_check.user_id = current_user.id
            
            db.session.add(url_check)
            db.session.commit()
            
            return render_template('url_checker.html', result=analysis_result, url_check=url_check)
            
        except Exception as e:
            logger.error(f"URL checking error: {str(e)}")
            flash('An error occurred while analyzing the URL. Please try again.', 'error')
    
    return render_template('url_checker.html')

@app.route('/password-checker', methods=['GET', 'POST'])
def password_checker():
    if request.method == 'POST':
        try:
            password = request.form.get('password', '')
            
            if not password:
                flash('Please enter a password to check.', 'error')
                return render_template('password_checker.html')
            
            # Perform password analysis
            analysis_result = security_analyzer.analyze_password_strength(password)
            
            # Save to database
            password_check = PasswordCheck()
            password_check.password_hash = generate_password_hash(password)
            password_check.strength_score = analysis_result['strength_score']
            password_check.strength_level = analysis_result['strength_level']
            password_check.has_uppercase = analysis_result['has_uppercase']
            password_check.has_lowercase = analysis_result['has_lowercase']
            password_check.has_numbers = analysis_result['has_numbers']
            password_check.has_symbols = analysis_result['has_symbols']
            password_check.entropy = analysis_result['entropy']
            password_check.feedback = json.dumps(analysis_result['feedback'])
            password_check.detailed_analysis = json.dumps(analysis_result.get('detailed_analysis', {}))
            password_check.mistake_description = analysis_result.get('mistake_description', '')
            password_check.recommendations = json.dumps(analysis_result.get('recommendations', []))
            password_check.checked_at = get_current_time()
            password_check.ip_address = request.remote_addr
            
            if current_user.is_authenticated:
                password_check.user_id = current_user.id
            
            db.session.add(password_check)
            db.session.commit()
            
            return render_template('password_checker.html', result=analysis_result, password_check=password_check)
            
        except Exception as e:
            logger.error(f"Password checking error: {str(e)}")
            flash('An error occurred while analyzing the password. Please try again.', 'error')
    
    return render_template('password_checker.html')

# ...existing code...
@app.route('/password-generator', methods=['GET', 'POST'])
def password_generator():
    generated_password = None
    strength_analysis = None
    generation_record = None
    error = None

    def _fallback_generate(length=12, upper=True, lower=True, nums=True, syms=True, exclude_ambiguous=False):
        import secrets, string
        ambiguous = "Il1O0"
        pools = []
        if lower: pools.append(string.ascii_lowercase)
        if upper: pools.append(string.ascii_uppercase)
        if nums: pools.append(string.digits)
        if syms: pools.append("!@#$%^&*()-_=+[]{};:,.<>?")
        alphabet = "".join(pools)
        if exclude_ambiguous:
            alphabet = "".join([c for c in alphabet if c not in ambiguous])
        if not alphabet:
            raise ValueError("No character pools available for password generation.")
        # ensure at least one char from each enabled pool
        pwd = []
        for p in pools:
            pwd.append(secrets.choice(p))
        while len(pwd) < max(4, length):
            pwd.append(secrets.choice(alphabet))
        secrets.SystemRandom().shuffle(pwd)
        return ''.join(pwd)[:length]

    if request.method == 'POST':
        try:
            # Safe parsing
            try:
                length = int(request.form.get('length', 12))
            except (TypeError, ValueError):
                length = 12

            include_uppercase = 'include_uppercase' in request.form
            include_lowercase = 'include_lowercase' in request.form
            include_numbers = 'include_numbers' in request.form
            include_symbols = 'include_symbols' in request.form
            exclude_ambiguous = 'exclude_ambiguous' in request.form
            usage_purpose = request.form.get('usage_purpose', '').strip()

            if length < 4 or length > 128:
                flash('Password length must be between 4 and 128 characters.', 'error')
                return render_template('password_generator.html')

            if not any([include_uppercase, include_lowercase, include_numbers, include_symbols]):
                flash('Please select at least one character type.', 'error')
                return render_template('password_generator.html')

            # Generate password using security_analyzer if available, otherwise fallback
            if hasattr(security_analyzer, 'generate_secure_password'):
                try:
                    generated_password = security_analyzer.generate_secure_password(
                        length=length,
                        include_uppercase=include_uppercase,
                        include_lowercase=include_lowercase,
                        include_numbers=include_numbers,
                        include_symbols=include_symbols,
                        exclude_ambiguous=exclude_ambiguous
                    )
                except Exception:
                    logger.exception("security_analyzer.generate_secure_password failed, using fallback generator")
                    generated_password = _fallback_generate(length, include_uppercase, include_lowercase, include_numbers, include_symbols, exclude_ambiguous)
            else:
                generated_password = _fallback_generate(length, include_uppercase, include_lowercase, include_numbers, include_symbols, exclude_ambiguous)

            # Strength analysis (safe)
            try:
                strength_analysis = security_analyzer.analyze_password_strength(generated_password) if hasattr(security_analyzer, 'analyze_password_strength') else {}
            except Exception:
                logger.exception("Password strength analysis failed")
                strength_analysis = {}

            # Save to database (set only attributes that exist on model)
            try:
                gen_rec = GeneratedPassword()
                if hasattr(gen_rec, 'password_hash'):
                    gen_rec.password_hash = generate_password_hash(generated_password)
                if hasattr(gen_rec, 'length'):
                    gen_rec.length = length
                if hasattr(gen_rec, 'include_uppercase'):
                    gen_rec.include_uppercase = include_uppercase
                if hasattr(gen_rec, 'include_lowercase'):
                    gen_rec.include_lowercase = include_lowercase
                if hasattr(gen_rec, 'include_numbers'):
                    gen_rec.include_numbers = include_numbers
                if hasattr(gen_rec, 'include_symbols'):
                    gen_rec.include_symbols = include_symbols
                if hasattr(gen_rec, 'exclude_ambiguous'):
                    gen_rec.exclude_ambiguous = exclude_ambiguous
                if 'strength_score' in (strength_analysis or {} ) and hasattr(gen_rec, 'strength_score'):
                    gen_rec.strength_score = strength_analysis.get('strength_score')
                if hasattr(gen_rec, 'usage_purpose'):
                    gen_rec.usage_purpose = usage_purpose
                if hasattr(gen_rec, 'generated_at'):
                    gen_rec.generated_at = get_current_time()
                if hasattr(gen_rec, 'ip_address'):
                    gen_rec.ip_address = request.remote_addr
                if current_user.is_authenticated and hasattr(gen_rec, 'user_id'):
                    gen_rec.user_id = current_user.id

                db.session.add(gen_rec)
                db.session.commit()
                generation_record = gen_rec
            except Exception:
                logger.exception("Failed to save generated password record; continuing without DB save")
                db.session.rollback()
                generation_record = None

            return render_template('password_generator.html',
                                   generated_password=generated_password,
                                   strength_analysis=strength_analysis,
                                   generation_record=generation_record)

        except Exception as e:
            logger.exception("Password generation error")
            error = str(e)
            flash('An error occurred while generating the password. Please try again.', 'error')

    return render_template('password_generator.html',
                           generated_password=generated_password,
                           strength_analysis=strength_analysis,
                           generation_record=generation_record,
                           error=error)
# ...existing code...

@app.route('/personal-password', methods=['GET', 'POST'])
def personal_password():
    if request.method == 'POST':
        try:
            # Get personal information
            personal_info = {
                'name': request.form.get('name', '').strip(),
                'age': request.form.get('age', '').strip(),
                'dob': request.form.get('dob', '').strip(),
                'school': request.form.get('school', '').strip(),
                'pet': request.form.get('pet', '').strip(),
                'color': request.form.get('color', '').strip()
            }
            
            # Validate at least some info is provided
            if not any(personal_info.values()):
                flash('Please provide at least some personal information to generate passwords.', 'error')
                return render_template('personal_password.html')
            
            # Generate personal passwords
            generated_passwords = security_analyzer.generate_personal_passwords(personal_info)
            
            # Save to database for logged-in users
            saved_passwords = []
            if current_user.is_authenticated:
                current_local_time = get_current_time()
                for i, pwd_info in enumerate(generated_passwords):
                    personal_password_record = PersonalPasswordGeneration()
                    personal_password_record.user_id = current_user.id
                    personal_password_record.password_hash = generate_password_hash(pwd_info['password'])
                    personal_password_record.purpose = f"Personal Password {i+1} ({pwd_info['pattern']})"
                    personal_password_record.length = len(pwd_info['password'])
                    personal_password_record.include_uppercase = any(c.isupper() for c in pwd_info['password'])
                    personal_password_record.include_lowercase = any(c.islower() for c in pwd_info['password'])
                    personal_password_record.include_numbers = any(c.isdigit() for c in pwd_info['password'])
                    personal_password_record.include_symbols = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in pwd_info['password'])
                    personal_password_record.strength_score = pwd_info['strength_score']
                    personal_password_record.created_at = current_local_time
                    personal_password_record.last_updated = current_local_time
                    
                    db.session.add(personal_password_record)
                    saved_passwords.append(personal_password_record)
                
                db.session.commit()
            
            return render_template('personal_password.html', 
                                 generated_passwords=generated_passwords,
                                 saved_passwords=saved_passwords,
                                 personal_info=personal_info)
            
        except Exception as e:
            logger.error(f"Personal password generation error: {str(e)}")
            flash('An error occurred while generating personal passwords. Please try again.', 'error')
    
    return render_template('personal_password.html')

@app.route('/download-report/<report_type>/<int:check_id>')
@app.route('/download-report/<report_type>/<int:check_id>/<format>')
def download_report(report_type, check_id, format='pdf'):
    try:
        if format not in ['pdf', 'csv']:
            flash('Invalid report format requested.', 'error')
            return redirect(url_for('index'))
        
        user = current_user if current_user.is_authenticated else None
        
        if report_type == 'url':
            url_check = URLCheck.query.get_or_404(check_id)
            
            # Check if user owns this check (for registered users)
            if user and url_check.user_id and url_check.user_id != user.id:
                flash('You can only download reports for your own checks.', 'error')
                return redirect(url_for('dashboard'))
            
            # Generate report
            report_buffer = report_generator.generate_url_report(url_check, user, format)
            
            # Create security report record
            if user:
                security_report = SecurityReport()
                security_report.user_id = user.id
                security_report.report_type = 'url_check'
                security_report.related_check_id = check_id
                security_report.file_format = format
                security_report.generated_at = get_current_time()
                db.session.add(security_report)
                db.session.commit()
            
            # Prepare download
            if format == 'pdf':
                mimetype = 'application/pdf'
                filename = f'url_security_report_{check_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            else:
                mimetype = 'text/csv'
                filename = f'url_security_report_{check_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            
            return send_file(
                report_buffer,
                mimetype=mimetype,
                as_attachment=True,
                download_name=filename
            )
            
        elif report_type == 'password':
            password_check = PasswordCheck.query.get_or_404(check_id)
            
            # Check if user owns this check (for registered users)
            if user and password_check.user_id and password_check.user_id != user.id:
                flash('You can only download reports for your own checks.', 'error')
                return redirect(url_for('dashboard'))
            
            # Generate report
            report_buffer = report_generator.generate_password_report(password_check, user, format)
            
            # Create security report record
            if user:
                security_report = SecurityReport()
                security_report.user_id = user.id
                security_report.report_type = 'password_check'
                security_report.related_check_id = check_id
                security_report.file_format = format
                security_report.generated_at = get_current_time()
                db.session.add(security_report)
                db.session.commit()
            
            # Prepare download
            if format == 'pdf':
                mimetype = 'application/pdf'
                filename = f'password_security_report_{check_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            else:
                mimetype = 'text/csv'
                filename = f'password_security_report_{check_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            
            return send_file(
                report_buffer,
                mimetype=mimetype,
                as_attachment=True,
                download_name=filename
            )
            
        elif report_type == 'personal_password':
            personal_password = PersonalPasswordGeneration.query.get_or_404(check_id)
            
            # Check if user owns this check
            if not user or personal_password.user_id != user.id:
                flash('You can only download reports for your own personal passwords.', 'error')
                return redirect(url_for('dashboard'))
            
            # Get all personal passwords from the same generation session
            session_passwords = PersonalPasswordGeneration.query.filter_by(
                user_id=user.id,
                created_at=personal_password.created_at
            ).all()
            
            # Generate report
            report_buffer = report_generator.generate_personal_password_report(session_passwords, user, format)
            
            # Create security report record
            security_report = SecurityReport()
            security_report.user_id = user.id
            security_report.report_type = 'personal_password_generation'
            security_report.related_check_id = check_id
            security_report.file_format = format
            security_report.generated_at = get_current_time()
            db.session.add(security_report)
            db.session.commit()
            
            # Prepare download
            if format == 'pdf':
                mimetype = 'application/pdf'
                filename = f'personal_password_report_{check_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            else:
                mimetype = 'text/csv'
                filename = f'personal_password_report_{check_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            
            return send_file(
                report_buffer,
                mimetype=mimetype,
                as_attachment=True,
                download_name=filename
            )
            
        elif report_type == 'generated_password':
            generated_password = GeneratedPassword.query.get_or_404(check_id)
            
            # Check if user owns this generated password
            if not user or generated_password.user_id != user.id:
                flash('You can only download reports for your own generated passwords.', 'error')
                return redirect(url_for('dashboard'))
            
            # Generate report
            report_buffer = report_generator.generate_generated_password_report(generated_password, user, format)
            
            # Create security report record
            security_report = SecurityReport()
            security_report.user_id = user.id
            security_report.report_type = 'generated_password'
            security_report.related_check_id = check_id
            security_report.file_format = format
            security_report.generated_at = get_current_time()
            db.session.add(security_report)
            db.session.commit()
            
            # Prepare download
            if format == 'pdf':
                mimetype = 'application/pdf'
                filename = f'generated_password_report_{check_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            else:
                mimetype = 'text/csv'
                filename = f'generated_password_report_{check_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            
            return send_file(
                report_buffer,
                mimetype=mimetype,
                as_attachment=True,
                download_name=filename
            )
            
        else:
            flash('Invalid report type requested.', 'error')
            return redirect(url_for('index'))
            
    except Exception as e:
        logger.error(f"Report download error: {str(e)}")
        flash('An error occurred while generating the report. Please try again.', 'error')
        return redirect(url_for('index'))

@app.route('/download-summary')
@login_required
def download_summary():
    """Download summary PDF with URLs and their safety percentages, and generated passwords status"""
    try:
        # Get all user's URL checks
        url_checks = URLCheck.query.filter_by(user_id=current_user.id).order_by(URLCheck.checked_at.desc()).all()
        
        # Get all user's generated passwords
        generated_passwords = GeneratedPassword.query.filter_by(user_id=current_user.id).order_by(GeneratedPassword.generated_at.desc()).all()
        
        # Get all user's password checks
        password_checks = PasswordCheck.query.filter_by(user_id=current_user.id).order_by(PasswordCheck.checked_at.desc()).all()
        
        # Generate PDF using ReportGenerator
        report_buffer = report_generator.generate_summary_report(
            url_checks=url_checks,
            generated_passwords=generated_passwords,
            password_checks=password_checks,
            user=current_user
        )
        
        # Create security report record
        security_report = SecurityReport()
        security_report.user_id = current_user.id
        security_report.report_type = 'summary'
        security_report.file_format = 'pdf'
        security_report.generated_at = get_current_time()
        db.session.add(security_report)
        db.session.commit()
        
        # Generate filename
        filename = f'security_summary_{current_user.username}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        
        return send_file(
            report_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Summary download error: {str(e)}")
        flash('An error occurred while generating the summary. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/download-users')
@app.route('/admin/download-users/<format>')
@login_required
def admin_download_users(format='pdf'):
    """Admin download users report"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get all users
        users = User.query.order_by(User.created_at.desc()).all()
        
        # Generate report
        report_buffer = report_generator.generate_admin_users_report(users, format)
        
        # Create security report record
        security_report = SecurityReport()
        security_report.user_id = current_user.id
        security_report.report_type = 'admin_users'
        security_report.file_format = format
        security_report.generated_at = get_current_time()
        db.session.add(security_report)
        db.session.commit()
        
        # Generate filename and return
        filename = f'admin_users_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{format}'
        mimetype = 'application/pdf' if format == 'pdf' else 'text/csv'
        
        return send_file(
            report_buffer,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Admin users download error: {str(e)}")
        flash('An error occurred while generating the users report. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/download-activity')
@app.route('/admin/download-activity/<format>')
@login_required
def admin_download_activity(format='pdf'):
    """Admin download activity report"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get all activity data
        url_checks = URLCheck.query.order_by(URLCheck.checked_at.desc()).all()
        password_checks = PasswordCheck.query.order_by(PasswordCheck.checked_at.desc()).all()
        generated_passwords = GeneratedPassword.query.order_by(GeneratedPassword.generated_at.desc()).all()
        
        # Generate report
        report_buffer = report_generator.generate_admin_activity_report(
            url_checks, password_checks, generated_passwords, format
        )
        
        # Create security report record
        security_report = SecurityReport()
        security_report.user_id = current_user.id
        security_report.report_type = 'admin_activity'
        security_report.file_format = format
        security_report.generated_at = get_current_time()
        db.session.add(security_report)
        db.session.commit()
        
        # Generate filename and return
        filename = f'admin_activity_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{format}'
        mimetype = 'application/pdf' if format == 'pdf' else 'text/csv'
        
        return send_file(
            report_buffer,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Admin activity download error: {str(e)}")
        flash('An error occurred while generating the activity report. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/user-activity/<int:user_id>')
@login_required
def admin_user_activity(user_id):
    """View detailed user activity"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        user = User.query.get_or_404(user_id)
        
        # Get user's activity
        url_checks = URLCheck.query.filter_by(user_id=user_id).order_by(URLCheck.checked_at.desc()).all()
        password_checks = PasswordCheck.query.filter_by(user_id=user_id).order_by(PasswordCheck.checked_at.desc()).all()
        generated_passwords = GeneratedPassword.query.filter_by(user_id=user_id).order_by(GeneratedPassword.generated_at.desc()).all()
        
        return render_template('admin_user_activity.html',
                             user=user,
                             url_checks=url_checks,
                             password_checks=password_checks,
                             generated_passwords=generated_passwords)
        
    except Exception as e:
        logger.error(f"Admin user activity error: {str(e)}")
        flash('An error occurred while loading user activity.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/toggle-user-status/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_user_status(user_id):
    """Toggle user blocked status"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'})
    
    try:
        user = User.query.get_or_404(user_id)
        
        # Don't allow blocking admin users
        if user.is_admin:
            return jsonify({'success': False, 'message': 'Cannot block admin users.'})
        
        # Toggle blocked status
        user.is_blocked = not user.is_blocked
        db.session.commit()
        
        status = 'blocked' if user.is_blocked else 'unblocked'
        return jsonify({'success': True, 'message': f'User {user.username} has been {status}.'})
        
    except Exception as e:
        logger.error(f"Admin toggle user status error: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while updating user status.'})

@app.route('/admin/feedback/<int:feedback_id>')
@login_required
def admin_get_feedback(feedback_id):
    """Get feedback details for admin"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'})
    
    try:
        feedback = SurveyResponse.query.get_or_404(feedback_id)
        
        feedback_data = {
            'id': feedback.id,
            'name': feedback.name,
            'email': feedback.email,
            'experience_level': feedback.experience_level,
            'primary_concern': feedback.primary_concern,
            'tools_used': feedback.tools_used,
            'satisfaction_rating': feedback.satisfaction_rating,
            'improvement_suggestions': feedback.improvement_suggestions,
            'feature_requests': feedback.feature_requests,
            'submitted_at': feedback.submitted_at.strftime('%Y-%m-%d %H:%M'),
            'is_reviewed': feedback.is_reviewed,
            'reviewer_notes': feedback.reviewer_notes
        }
        
        return jsonify({'success': True, 'feedback': feedback_data})
        
    except Exception as e:
        logger.error(f"Admin get feedback error: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while loading feedback details.'})

@app.route('/admin/feedback/<int:feedback_id>/mark-reviewed', methods=['POST'])
@login_required
def admin_mark_feedback_reviewed(feedback_id):
    """Mark feedback as reviewed"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'})
    
    try:
        feedback = SurveyResponse.query.get_or_404(feedback_id)
        
        # Get reviewer notes from request
        data = request.get_json()
        reviewer_notes = data.get('reviewer_notes', '') if data else ''
        
        feedback.is_reviewed = True
        feedback.reviewer_notes = reviewer_notes
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Feedback marked as reviewed successfully.'})
        
    except Exception as e:
        logger.error(f"Admin mark feedback reviewed error: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while marking feedback as reviewed.'})

@app.route('/admin/download-feedback')
@app.route('/admin/download-feedback/<format>')
@login_required
def admin_download_feedback(format='pdf'):
    """Admin download feedback report"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get all feedback
        feedback_responses = SurveyResponse.query.order_by(SurveyResponse.submitted_at.desc()).all()
        
        # Generate report
        report_buffer = report_generator.generate_admin_feedback_report(feedback_responses, format)
        
        # Create security report record
        security_report = SecurityReport()
        security_report.user_id = current_user.id
        security_report.report_type = 'admin_feedback'
        security_report.file_format = format
        security_report.generated_at = get_current_time()
        db.session.add(security_report)
        db.session.commit()
        
        # Generate filename and return
        filename = f'admin_feedback_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{format}'
        mimetype = 'application/pdf' if format == 'pdf' else 'text/csv'
        
        return send_file(
            report_buffer,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Admin feedback download error: {str(e)}")
        flash('An error occurred while generating the feedback report. Please try again.', 'error')
        return redirect(url_for('dashboard'))
# ...existing code...
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            if not username or not password:
                flash('Please enter both username and password.', 'error')
                return render_template('login.html')
            
            user = User.query.filter_by(username=username).first()

            if not user:
                flash('Invalid username or password.', 'error')
                return render_template('login.html')

            # Blocked user check (prevent blocked users from logging in)
            if getattr(user, 'is_blocked', False):
                flash('Your account has been blocked by the admin. Please contact support.', 'error')
                return render_template('login.html')

            # Password verification (use werkzeug.check_password_hash and stored password_hash)
            if not check_password_hash(user.password_hash, password):
                flash('Invalid username or password.', 'error')
                return render_template('login.html')

            login_user(user)
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.', 'error')
            return render_template('login.html')

    return render_template('login.html')
# ...existing code...

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            if not username or not password:
                flash('Please enter both username and password.', 'error')
                return render_template('admin_login.html')
            
            user = User.query.filter_by(username=username).first()
            
            if user and user.is_admin:
                # Prevent blocked admin (or admin marked blocked) from logging in
                if getattr(user, 'is_blocked', False):
                    flash('Your account has been blocked by the system. Please contact support.', 'error')
                    return render_template('admin_login.html')

                if check_password_hash(user.password_hash, password):
                    login_user(user)
                    user.last_login = get_current_time()
                    db.session.commit()
                    flash('Admin login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid password.', 'error')
            else:
                flash('Admin user not found or not authorized.', 'error')
                
        except Exception as e:
            logger.error(f"Admin login error: {str(e)}")
            flash('An error occurred during admin login. Please try again.', 'error')
    
    return render_template('admin_login.html')
# ...existing code...

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Validation
            if not username or not email or not password or not confirm_password:
                flash('Please fill in all fields.', 'error')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('register.html')
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long.', 'error')
                return render_template('register.html')
            
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
                return render_template('register.html')
            
            if User.query.filter_by(email=email).first():
                flash('Email already exists.', 'error')
                return render_template('register.html')
            
            # Create user
            user = User()
            user.username = username
            user.email = email
            user.password_hash = generate_password_hash(password)
            user.created_at = get_current_time()
            
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/admin-create', methods=['GET', 'POST'])
def admin_create():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Validation
            if not username or not email or not password or not confirm_password:
                flash('Please fill in all fields.', 'error')
                return render_template('admin_create.html')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('admin_create.html')
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long.', 'error')
                return render_template('admin_create.html')
            
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
                return render_template('admin_create.html')
            
            if User.query.filter_by(email=email).first():
                flash('Email already exists.', 'error')
                return render_template('admin_create.html')
            
            # Create admin user
            user = User()
            user.username = username
            user.email = email
            user.password_hash = generate_password_hash(password)
            user.is_admin = True
            user.created_at = get_current_time()
            
            db.session.add(user)
            db.session.commit()
            
            flash('Admin account created successfully! Please log in.', 'success')
            return redirect(url_for('admin_login'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Admin creation error: {str(e)}")
            flash('An error occurred during admin account creation. Please try again.', 'error')
    
    return render_template('admin_create.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        if current_user.is_admin:
            # Admin dashboard with enhanced analytics
            total_urls = URLCheck.query.count()
            safe_urls = URLCheck.query.filter(URLCheck.security_score >= 70).count()
            suspicious_urls = URLCheck.query.filter(URLCheck.security_score.between(40, 69)).count()
            dangerous_urls = URLCheck.query.filter(URLCheck.security_score < 40).count()
            
            stats = {
                'total_users': User.query.count(),
                'total_url_checks': total_urls,
                'total_password_checks': PasswordCheck.query.count(),
                'total_generated_passwords': GeneratedPassword.query.count(),
                'total_personal_passwords': PersonalPasswordGeneration.query.count(),
                'total_surveys': SurveyResponse.query.count(),
                'unreviewed_surveys': SurveyResponse.query.filter_by(is_reviewed=False).count(),
                'safe_urls': safe_urls,
                'suspicious_urls': suspicious_urls,
                'dangerous_urls': dangerous_urls
            }
            
            all_users = User.query.order_by(User.created_at.desc()).all()
            survey_responses = SurveyResponse.query.order_by(SurveyResponse.submitted_at.desc()).all()
            recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
            recent_url_checks = URLCheck.query.order_by(URLCheck.checked_at.desc()).limit(10).all()
            
            return render_template('dashboard.html', 
                                 stats=stats, 
                                 all_users=all_users, 
                                 survey_responses=survey_responses,
                                 recent_users=recent_users,
                                 recent_url_checks=recent_url_checks,
                                 recent_feedback=survey_responses[:20])
        else:
            # User dashboard with history
            url_checks = URLCheck.query.filter_by(user_id=current_user.id).order_by(URLCheck.checked_at.desc()).all()
            password_checks = PasswordCheck.query.filter_by(user_id=current_user.id).order_by(PasswordCheck.checked_at.desc()).all()
            generated_passwords = GeneratedPassword.query.filter_by(user_id=current_user.id).order_by(GeneratedPassword.generated_at.desc()).all()
            security_reports = SecurityReport.query.filter_by(user_id=current_user.id).order_by(SecurityReport.generated_at.desc()).all()
            
            stats = {
                'total_url_checks': len(url_checks),
                'total_password_checks': len(password_checks),
                'total_generated_passwords': len(generated_passwords),
                'total_reports': len(security_reports)
            }
            
            return render_template('dashboard.html',
                                 url_checks=url_checks,
                                 password_checks=password_checks,
                                 generated_passwords=generated_passwords,
                                 security_reports=security_reports,
                                 stats=stats)
            
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('An error occurred while loading the dashboard.', 'error')
        return redirect(url_for('index'))

@app.route('/survey', methods=['GET', 'POST'])
def survey():
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip()
            experience_level = request.form.get('experience_level', '')
            primary_concern = request.form.get('primary_concern', '')
            tools_used = ', '.join(request.form.getlist('tools_used'))
            satisfaction_rating = request.form.get('satisfaction_rating')
            improvement_suggestions = request.form.get('improvement_suggestions', '').strip()
            feature_requests = request.form.get('feature_requests', '').strip()
            
            # Validate required fields
            if not name or not email or not satisfaction_rating:
                flash('Please fill in all required fields.', 'error')
                return render_template('survey.html')
            
            # Create survey response
            survey_response = SurveyResponse()
            survey_response.name = name
            survey_response.email = email
            survey_response.experience_level = experience_level
            survey_response.primary_concern = primary_concern
            survey_response.tools_used = tools_used
            survey_response.satisfaction_rating = int(satisfaction_rating)
            survey_response.improvement_suggestions = improvement_suggestions
            survey_response.feature_requests = feature_requests
            survey_response.submitted_at = get_current_time()
            survey_response.user_id = current_user.id if current_user.is_authenticated else None
            survey_response.ip_address = request.remote_addr
            
            db.session.add(survey_response)
            db.session.commit()
            
            flash('Thank you for your feedback! Your survey response has been submitted successfully.', 'success')
            return redirect(url_for('survey'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting your survey. Please try again.', 'error')
            logger.error(f"Survey submission error: {str(e)}")
            
    return render_template('survey.html')
