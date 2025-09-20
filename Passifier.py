#!/usr/bin/env python3
"""
PASSIFIER ;)
CLI Password Strength Auditor
A modern, interactive tool for analyzing password strength with entropy metrics
Author: NightmareLynx
Purpose: Educational cybersecurity tool for password auditing
"""

import math
import re
import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path
import json
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import time

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class PasswordAnalyzer:
    def __init__(self):
        # Common passwords and patterns (sample set)
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123', 
            'password123', 'admin', 'letmein', 'welcome', '1234567890',
            'iloveyou', 'princess', 'rockyou', 'michael', 'jessica'
        }
        
        # Character sets for entropy calculation
        self.char_sets = {
            'lowercase': set('abcdefghijklmnopqrstuvwxyz'),
            'uppercase': set('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            'digits': set('0123456789'),
            'special': set('!@#$%^&*()_+-=[]{}|;:,.<>?'),
            'extended': set('`~"\'\\/')
        }
        
        # Weak patterns
        self.weak_patterns = [
            r'(.)\1{2,}',  # Repeated characters
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
            r'(qwer|asdf|zxcv|hjkl)',  # Keyboard patterns
        ]
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy using Shannon entropy formula"""
        if not password:
            return 0.0
        
        # Determine character space
        char_space = 0
        password_chars = set(password)
        
        if any(c in self.char_sets['lowercase'] for c in password_chars):
            char_space += len(self.char_sets['lowercase'])
        if any(c in self.char_sets['uppercase'] for c in password_chars):
            char_space += len(self.char_sets['uppercase'])
        if any(c in self.char_sets['digits'] for c in password_chars):
            char_space += len(self.char_sets['digits'])
        if any(c in self.char_sets['special'] for c in password_chars):
            char_space += len(self.char_sets['special'])
        if any(c in self.char_sets['extended'] for c in password_chars):
            char_space += len(self.char_sets['extended'])
        
        # Calculate entropy: log2(character_space) * length
        if char_space > 0:
            return math.log2(char_space) * len(password)
        return 0.0
    
    def calculate_shannon_entropy(self, password: str) -> float:
        """Calculate Shannon entropy based on character frequency"""
        if not password:
            return 0.0
        
        frequency = Counter(password)
        length = len(password)
        
        entropy = 0.0
        for count in frequency.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy * length
    
    def analyze_password(self, password: str) -> Dict:
        """Comprehensive password analysis"""
        analysis = {
            'password': password,
            'length': len(password),
            'entropy': self.calculate_entropy(password),
            'shannon_entropy': self.calculate_shannon_entropy(password),
            'character_sets': [],
            'strength_score': 0,
            'strength_level': '',
            'vulnerabilities': [],
            'time_to_crack': '',
            'recommendations': []
        }
        
        # Character set analysis
        if any(c in self.char_sets['lowercase'] for c in password):
            analysis['character_sets'].append('lowercase')
        if any(c in self.char_sets['uppercase'] for c in password):
            analysis['character_sets'].append('uppercase')
        if any(c in self.char_sets['digits'] for c in password):
            analysis['character_sets'].append('digits')
        if any(c in self.char_sets['special'] for c in password):
            analysis['character_sets'].append('special')
        
        # Vulnerability checks
        if password.lower() in self.common_passwords:
            analysis['vulnerabilities'].append('Common password')
        
        if len(password) < 8:
            analysis['vulnerabilities'].append('Too short')
        
        for pattern in self.weak_patterns:
            if re.search(pattern, password.lower()):
                analysis['vulnerabilities'].append('Contains weak patterns')
                break
        
        if len(set(password)) < len(password) * 0.6:
            analysis['vulnerabilities'].append('High character repetition')
        
        # Calculate strength score
        score = 0
        score += min(len(password) * 2, 20)  # Length score (max 20)
        score += len(analysis['character_sets']) * 5  # Character diversity (max 20)
        score += min(analysis['entropy'] / 5, 30)  # Entropy score (max 30)
        score -= len(analysis['vulnerabilities']) * 10  # Vulnerability penalty
        
        analysis['strength_score'] = max(0, min(100, int(score)))
        
        # Strength level
        if analysis['strength_score'] >= 80:
            analysis['strength_level'] = 'Very Strong'
        elif analysis['strength_score'] >= 60:
            analysis['strength_level'] = 'Strong'
        elif analysis['strength_score'] >= 40:
            analysis['strength_level'] = 'Medium'
        elif analysis['strength_score'] >= 20:
            analysis['strength_level'] = 'Weak'
        else:
            analysis['strength_level'] = 'Very Weak'
        
        # Time to crack estimation (simplified)
        possible_combinations = 2 ** analysis['entropy']
        attempts_per_second = 1e9  # 1 billion attempts per second (modern GPU)
        seconds_to_crack = possible_combinations / (2 * attempts_per_second)  # Average case
        
        analysis['time_to_crack'] = self.format_time(seconds_to_crack)
        
        # Recommendations
        if len(password) < 12:
            analysis['recommendations'].append('Increase length to at least 12 characters')
        if 'uppercase' not in analysis['character_sets']:
            analysis['recommendations'].append('Add uppercase letters')
        if 'special' not in analysis['character_sets']:
            analysis['recommendations'].append('Add special characters')
        if analysis['vulnerabilities']:
            analysis['recommendations'].append('Avoid common passwords and patterns')
        
        return analysis
    
    def format_time(self, seconds: float) -> str:
        """Format time duration in human-readable format"""
        if seconds < 1:
            return "< 1 second"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000000:
            return f"{seconds/31536000:.1f} years"
        else:
            return f"{seconds/31536000:.2e} years"

class PasswordAuditor:
    def __init__(self):
        self.analyzer = PasswordAnalyzer()
        self.results = []
    
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                   PASSIFIER                                      ║
║                         CLI PASSWORD STRENGTH AUDITOR                            ║
║                      Advanced Entropy & Security Analysis                        ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}Purpose: Educational cybersecurity tool for password strength assessment{Colors.END}
{Colors.YELLOW}Warning: Use only on passwords you own or have permission to audit{Colors.END}
"""
        print(banner)
    
    def load_passwords(self, file_path: str) -> List[str]:
        """Load passwords from file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(f"{Colors.GREEN}✓ Loaded {len(passwords)} passwords from {file_path}{Colors.END}")
            return passwords
        except FileNotFoundError:
            print(f"{Colors.RED}✗ File not found: {file_path}{Colors.END}")
            return []
        except Exception as e:
            print(f"{Colors.RED}✗ Error reading file: {e}{Colors.END}")
            return []
    
    def analyze_passwords(self, passwords: List[str], show_progress: bool = True) -> List[Dict]:
        """Analyze a list of passwords"""
        results = []
        total = len(passwords)
        
        print(f"\n{Colors.BLUE}Analyzing {total} passwords...{Colors.END}")
        
        for i, password in enumerate(passwords):
            if show_progress and i % max(1, total // 100) == 0:
                progress = (i / total) * 100
                print(f"\r{Colors.CYAN}Progress: {progress:.1f}% ({i}/{total}){Colors.END}", end='', flush=True)
            
            analysis = self.analyzer.analyze_password(password)
            results.append(analysis)
        
        if show_progress:
            print(f"\r{Colors.GREEN}✓ Analysis complete: 100.0% ({total}/{total}){Colors.END}")
        
        return results
    
    def display_summary(self, results: List[Dict]):
        """Display analysis summary"""
        if not results:
            return
        
        # Calculate statistics
        total_passwords = len(results)
        strength_distribution = defaultdict(int)
        avg_entropy = sum(r['entropy'] for r in results) / total_passwords
        avg_length = sum(r['length'] for r in results) / total_passwords
        vulnerable_count = sum(1 for r in results if r['vulnerabilities'])
        
        for result in results:
            strength_distribution[result['strength_level']] += 1
        
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}AUDIT SUMMARY{Colors.END}")
        print(f"{'═' * 80}")
        
        print(f"{Colors.WHITE}Total Passwords Analyzed: {Colors.BOLD}{total_passwords}{Colors.END}")
        print(f"{Colors.WHITE}Average Entropy: {Colors.BOLD}{avg_entropy:.2f} bits{Colors.END}")
        print(f"{Colors.WHITE}Average Length: {Colors.BOLD}{avg_length:.1f} characters{Colors.END}")
        print(f"{Colors.WHITE}Passwords with Vulnerabilities: {Colors.BOLD}{vulnerable_count} ({vulnerable_count/total_passwords*100:.1f}%){Colors.END}")
        
        print(f"\n{Colors.BOLD}Strength Distribution:{Colors.END}")
        strength_colors = {
            'Very Strong': Colors.GREEN,
            'Strong': Colors.CYAN,
            'Medium': Colors.YELLOW,
            'Weak': Colors.MAGENTA,
            'Very Weak': Colors.RED
        }
        
        for strength, count in strength_distribution.items():
            percentage = (count / total_passwords) * 100
            color = strength_colors.get(strength, Colors.WHITE)
            bar = '█' * min(50, int(percentage))
            print(f"{color}{strength:12}: {count:6} ({percentage:5.1f}%) {bar}{Colors.END}")
    
    def display_detailed_results(self, results: List[Dict], limit: int = 10):
        """Display detailed analysis results"""
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}DETAILED ANALYSIS (Top {min(limit, len(results))} results){Colors.END}")
        print(f"{'═' * 120}")
        
        # Sort by strength score (weakest first for security focus)
        sorted_results = sorted(results, key=lambda x: x['strength_score'])
        
        for i, result in enumerate(sorted_results[:limit]):
            strength_color = {
                'Very Strong': Colors.GREEN,
                'Strong': Colors.CYAN,
                'Medium': Colors.YELLOW,
                'Weak': Colors.MAGENTA,
                'Very Weak': Colors.RED
            }.get(result['strength_level'], Colors.WHITE)
            
            print(f"\n{Colors.BOLD}[{i+1}] Password Analysis:{Colors.END}")
            print(f"Password: {Colors.CYAN}{'*' * len(result['password'])}{Colors.END} (length: {result['length']})")
            print(f"Strength: {strength_color}{result['strength_level']} ({result['strength_score']}/100){Colors.END}")
            print(f"Entropy: {Colors.WHITE}{result['entropy']:.2f} bits{Colors.END}")
            print(f"Shannon Entropy: {Colors.WHITE}{result['shannon_entropy']:.2f} bits{Colors.END}")
            print(f"Character Sets: {Colors.WHITE}{', '.join(result['character_sets'])}{Colors.END}")
            print(f"Time to Crack: {Colors.WHITE}{result['time_to_crack']}{Colors.END}")
            
            if result['vulnerabilities']:
                print(f"Vulnerabilities: {Colors.RED}{', '.join(result['vulnerabilities'])}{Colors.END}")
            
            if result['recommendations']:
                print(f"Recommendations: {Colors.YELLOW}{'; '.join(result['recommendations'])}{Colors.END}")
    
    def export_results(self, results: List[Dict], output_file: str):
        """Export results to JSON file"""
        try:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'total_passwords': len(results),
                'results': results
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            print(f"{Colors.GREEN}✓ Results exported to {output_file}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}✗ Export failed: {e}{Colors.END}")
    
    def interactive_mode(self):
        """Interactive password analysis mode"""
        print(f"\n{Colors.BOLD}INTERACTIVE MODE{Colors.END}")
        print(f"Enter passwords to analyze (type 'quit' to exit):")
        
        while True:
            try:
                password = input(f"{Colors.CYAN}Enter password: {Colors.END}")
                if password.lower() in ['quit', 'exit', 'q']:
                    break
                
                if not password.strip():
                    continue
                
                analysis = self.analyzer.analyze_password(password)
                self.display_detailed_results([analysis], limit=1)
                
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Exiting interactive mode...{Colors.END}")
                break

def main():
    parser = argparse.ArgumentParser(
        description="CLI Password Strength Auditor - Analyze password security with entropy metrics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_auditor.py -f passwords.txt
  python password_auditor.py -f rockyou.txt -o report.json -l 20
  python password_auditor.py -i
        """
    )
    
    parser.add_argument('-f', '--file', type=str, help='Password list file path')
    parser.add_argument('-o', '--output', type=str, help='Output JSON file for results')
    parser.add_argument('-l', '--limit', type=int, default=10, help='Limit detailed results display (default: 10)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode for single password analysis')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress indicator')
    
    args = parser.parse_args()
    
    auditor = PasswordAuditor()
    auditor.print_banner()
    
    if args.interactive:
        auditor.interactive_mode()
        return
    
    if not args.file:
        print(f"{Colors.RED}Error: Please specify a password file with -f or use -i for interactive mode{Colors.END}")
        parser.print_help()
        return
    
    # Load and analyze passwords
    passwords = auditor.load_passwords(args.file)
    if not passwords:
        return
    
    results = auditor.analyze_passwords(passwords, show_progress=not args.no_progress)
    
    # Display results
    auditor.display_summary(results)
    auditor.display_detailed_results(results, limit=args.limit)
    
    # Export if requested
    if args.output:
        auditor.export_results(results, args.output)
    
    print(f"\n{Colors.GREEN}Audit completed successfully!{Colors.END}")
    print(f"{Colors.YELLOW}Remember: Use strong, unique passwords for all accounts!{Colors.END}")

if __name__ == "__main__":
    main()