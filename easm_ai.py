import ollama
import os
from pathlib import Path
import json
from datetime import datetime

class TargetedCodeReviewer:
    """Reviews project files ONE AT A TIME for accuracy"""
    
    def __init__(self, model='qwen2.5:3b'):
        self.model = model
        self.project_path = None
        self.reviews = {}
        self.current_file_index = 0
        self.files_to_review = []
        print(f" Targeted Code Reviewer initialized\n")
    
    def set_project(self, project_path):
        """Set project and collect files to review"""
        self.project_path = Path(project_path)
        
        if not self.project_path.exists():
            print(f" Path doesn't exist: {project_path}")
            return False
        
        print(f" Project: {self.project_path}\n")
        
        # Collect reviewable files
        self.files_to_review = self._collect_files()
        print(f" Found {len(self.files_to_review)} files to review\n")
        
        return True
    
    def _collect_files(self):
        """Collect Python, HTML, CSS, JS files"""
        files = []
        extensions = ['.py', '.html', '.css', '.js', '.json']
        
        for ext in extensions:
            for file in self.project_path.rglob(f'*{ext}'):
                # Skip virtual env and common ignore folders
                if any(ignore in str(file) for ignore in ['venv', 'node_modules', '__pycache__', '.git']):
                    continue
                
                # Skip this review script itself
                if file.name == 'complete_code_reviewer.py':
                    continue
                    
                files.append(file)
        
        return sorted(files)
    
    def _read_file(self, filepath):
        """Read file content safely"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            return f"[ERROR: Could not read file - {e}]"
    
    def _get_file_type_context(self, filepath):
        """Get context based on file type"""
        ext = filepath.suffix.lower()
        
        contexts = {
            '.py': {
                'type': 'Python Backend',
                'focus': 'Security (SQL injection, XSS), Logic errors, Performance, Flask best practices'
            },
            '.html': {
                'type': 'HTML Template',
                'focus': 'XSS vulnerabilities, Accessibility, SEO, Semantic HTML, Form validation'
            },
            '.css': {
                'type': 'CSS Stylesheet',
                'focus': 'Performance, Responsiveness, Browser compatibility, Organization'
            },
            '.js': {
                'type': 'JavaScript',
                'focus': 'Security (XSS, DOM manipulation), Event handling, Memory leaks, ES6+ practices'
            },
            '.json': {
                'type': 'JSON Configuration',
                'focus': 'Structure, Security (secrets exposure), Validity'
            }
        }
        
        return contexts.get(ext, {'type': 'Unknown', 'focus': 'General code quality'})
    
    def review_file(self, filepath):
        """Review a single file in detail"""
        
        relative_path = filepath.relative_to(self.project_path)
        code = self._read_file(filepath)
        file_info = self._get_file_type_context(filepath)
        
        # Check if file is too large
        line_count = len(code.split('\n'))
        if line_count > 500:
            code_preview = '\n'.join(code.split('\n')[:500])
            code = f"{code_preview}\n\n[... File truncated - {line_count} total lines]"
        
        prompt = f"""
You are reviewing ONE specific file from an EASM (External Attack Surface Management) Flask web application.

================================================================================
FILE INFORMATION
================================================================================
Path: {relative_path}
Type: {file_info['type']}
Lines: {line_count}
Focus Areas: {file_info['focus']}

================================================================================
COMPLETE FILE CONTENT
================================================================================
{code}

================================================================================
REVIEW REQUIREMENTS
================================================================================

Analyze ONLY this file. Do NOT make assumptions about other files.

Provide a detailed review covering:

1. **SECURITY ISSUES** (Critical for EASM tool)
   - Input validation vulnerabilities
   - SQL/NoSQL injection risks
   - XSS vulnerabilities
   - Authentication/authorization flaws
   - Sensitive data exposure
   - CSRF protection
   - Session handling issues
   - API security problems
   
   For EACH issue found:
   - Line number(s)
   - Severity (Critical/High/Medium/Low)
   - Specific description
   - How to exploit it
   - How to fix it

2. **BUGS & LOGIC ERRORS**
   - Exception handling problems
   - Edge cases not handled
   - Null/None reference errors
   - Type errors
   - Logic flaws
   
   For EACH bug:
   - Line number(s)
   - What breaks
   - How to fix it

3. **CODE QUALITY**
   - Readability issues
   - Naming conventions
   - Code duplication
   - Function complexity
   - Missing docstrings
   - Type hints missing (Python)
   
   For EACH issue:
   - Line number(s)
   - Current problem
   - Suggested improvement

4. **PERFORMANCE ISSUES**
   - Inefficient algorithms
   - Database query problems
   - Resource leaks
   - Blocking operations
   - Unnecessary computations
   
   For EACH issue:
   - Line number(s)
   - Performance impact
   - Optimization suggestion

5. **BEST PRACTICES VIOLATIONS**
   - Framework-specific anti-patterns
   - Modern practices not followed
   - Missing error handling
   - Hardcoded values
   - Configuration issues

6. **SPECIFIC IMPROVEMENTS**
   - What to add
   - What to remove
   - What to refactor
   - Better approaches

7. **OVERALL FILE RATING**
   - Security: [A/B/C/D/F]
   - Code Quality: [A/B/C/D/F]
   - Performance: [A/B/C/D/F]
   - Maintainability: [A/B/C/D/F]
   
   Overall Grade: [A/B/C/D/F]

================================================================================
IMPORTANT RULES
================================================================================
- Be SPECIFIC with line numbers
- Only report issues you can SEE in this file
- Do NOT invent files or code that doesn't exist
- Do NOT make generic statements
- Provide ACTIONABLE recommendations
- If something is good, say so!

================================================================================
"""

        print(f"\n Reviewing: {relative_path}")
        print(f"   Type: {file_info['type']}")
        print(f"   Lines: {line_count}")
        print("   Analyzing with AI...\n")
        
        response = ollama.chat(
            model=self.model,
            messages=[
                {
                    'role': 'system',
                    'content': 'You are an expert code reviewer specializing in security, performance, and best practices. You provide specific, actionable feedback with line numbers. You only report what you can actually see in the code.'
                },
                {'role': 'user', 'content': prompt}
            ]
        )
        
        review = response['message']['content']
        
        # Store review
        self.reviews[str(relative_path)] = {
            'filepath': str(relative_path),
            'type': file_info['type'],
            'lines': line_count,
            'review': review,
            'timestamp': datetime.now().isoformat()
        }
        
        return review
    
    def review_all_files(self, pause_between=True):
        """Review all files one by one"""
        
        total_files = len(self.files_to_review)
        
        print("="*80)
        print(f" Starting review of {total_files} files")
        print("="*80 + "\n")
        
        for index, filepath in enumerate(self.files_to_review, 1):
            print(f"\n{'='*80}")
            print(f" File {index}/{total_files}")
            print(f"{'='*80}")
            
            review = self.review_file(filepath)
            
            # Display review
            print("\n" + "─"*80)
            print(" REVIEW RESULTS")
            print("─"*80)
            print(review)
            print("─"*80)
            
            if pause_between and index < total_files:
                print(f"\n Review {index}/{total_files} complete")
                
                user_input = input("\n[Enter] Continue to next file | [s] Save & Exit | [q] Quit: ").strip().lower()
                
                if user_input == 's':
                    self.save_progress()
                    print("\n Progress saved. Run again to continue from here.")
                    return False
                elif user_input == 'q':
                    print("\n Exiting without saving.")
                    return False
        
        print("\n" + "="*80)
        print(" ALL FILES REVIEWED!")
        print("="*80)
        
        return True
    
    def save_progress(self):
        """Save all reviews to a file"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.project_path / f"code_review_{timestamp}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.reviews, f, indent=2, ensure_ascii=False)
        
        print(f"\n Reviews saved to: {output_file}")
        
        # Also create readable text version
        text_file = self.project_path / f"code_review_{timestamp}.txt"
        self.generate_text_report(text_file)
        
        return output_file
    
    def generate_text_report(self, output_file):
        """Generate human-readable report"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("TARGETED CODE REVIEW REPORT\n")
            f.write("="*80 + "\n")
            f.write(f"Project: {self.project_path}\n")
            f.write(f"Total Files Reviewed: {len(self.reviews)}\n")
            f.write(f"Review Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            for filepath, review_data in self.reviews.items():
                f.write("\n" + "="*80 + "\n")
                f.write(f"FILE: {filepath}\n")
                f.write(f"Type: {review_data['type']}\n")
                f.write(f"Lines: {review_data['lines']}\n")
                f.write("="*80 + "\n\n")
                f.write(review_data['review'])
                f.write("\n\n")
            
            # Summary
            f.write("\n" + "="*80 + "\n")
            f.write("REVIEW SUMMARY\n")
            f.write("="*80 + "\n")
            f.write(f"Total files reviewed: {len(self.reviews)}\n")
            
            types = {}
            for review_data in self.reviews.values():
                file_type = review_data['type']
                types[file_type] = types.get(file_type, 0) + 1
            
            f.write("\nFiles by type:\n")
            for file_type, count in types.items():
                f.write(f"  - {file_type}: {count}\n")
        
        print(f" Text report saved to: {output_file}")
    
    def generate_summary(self):
        """Generate executive summary of all reviews"""
        
        if not self.reviews:
            print(" No reviews to summarize")
            return
        
        all_reviews = "\n\n".join([
            f"File: {data['filepath']}\nReview:\n{data['review'][:500]}..."
            for data in list(self.reviews.values())[:10]  # First 10 files
        ])
        
        prompt = f"""
Based on these code reviews from an EASM Flask application:

{all_reviews}

Provide an EXECUTIVE SUMMARY:

1. **CRITICAL SECURITY ISSUES** (Top 5)
   - Issue
   - File(s) affected
   - Priority

2. **COMMON PATTERNS** (Good and Bad)
   - What's done well across files
   - What's consistently problematic

3. **HIGH-PRIORITY FIXES** (Top 10)
   - Ordered by importance
   - Estimated effort

4. **ARCHITECTURE OBSERVATIONS**
   - Overall code organization
   - Consistency issues
   - Structural improvements

5. **QUICK WINS** (Easy improvements with high impact)

6. **LONG-TERM RECOMMENDATIONS**

Keep it concise and actionable.
"""
        
        print("\n Generating executive summary...\n")
        
        response = ollama.chat(
            model=self.model,
            messages=[
                {
                    'role': 'system',
                    'content': 'You are a technical lead providing executive summary of code reviews.'
                },
                {'role': 'user', 'content': prompt}
            ]
        )
        
        summary = response['message']['content']
        
        # Save summary
        summary_file = self.project_path / f"review_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("EXECUTIVE SUMMARY - CODE REVIEW\n")
            f.write("="*80 + "\n\n")
            f.write(summary)
        
        print("="*80)
        print(" EXECUTIVE SUMMARY")
        print("="*80)
        print(summary)
        print("="*80)
        print(f"\n Summary saved to: {summary_file}\n")
        
        return summary


def main():
    """Main entry point"""
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║           TARGETED CODE REVIEWER                                 ║
║           Reviews Each File ONE AT A TIME                        ║
║                                                                  ║
║   Accurate file-by-file analysis                              ║
║   Specific line numbers                                       ║
║   No hallucinations                                           ║
║   Actionable recommendations                                  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Get project path
    print("\n Enter your project path:")
    print("   (Press Enter for current directory)\n")
    
    project_path = input("Path: ").strip()
    
    if not project_path:
        project_path = os.getcwd()
    
    # Initialize reviewer
    reviewer = TargetedCodeReviewer()
    
    if not reviewer.set_project(project_path):
        return
    
    # Show files to review
    print("Files to be reviewed:")
    print("-" * 80)
    for i, file in enumerate(reviewer.files_to_review, 1):
        relative = file.relative_to(reviewer.project_path)
        print(f"  {i:3d}. {relative}")
    print("-" * 80)
    
    # Confirm
    print(f"\n Total: {len(reviewer.files_to_review)} files")
    confirm = input("\nStart review? (y/n): ").strip().lower()
    
    if confirm != 'y':
        print(" Review cancelled")
        return
    
    # Ask for pause mode
    pause_mode = input("\nPause after each file? (y/n, default=y): ").strip().lower()
    pause = pause_mode != 'n'
    
    print("\n" + "="*80)
    print(" STARTING FILE-BY-FILE REVIEW")
    print("="*80)
    
    # Run reviews
    completed = reviewer.review_all_files(pause_between=pause)
    
    # Save results
    print("\n" + "="*80)
    print(" Saving results...")
    reviewer.save_progress()
    
    # Generate summary
    generate_summary = input("\nGenerate executive summary? (y/n): ").strip().lower()
    
    if generate_summary == 'y':
        reviewer.generate_summary()
    
    print("\n" + "="*80)
    print(" REVIEW COMPLETE!")
    print("="*80)
    print(f"\n Results saved in: {reviewer.project_path}")
    print("\nFiles generated:")
    print("  - code_review_[timestamp].json (machine-readable)")
    print("  - code_review_[timestamp].txt (human-readable)")
    if generate_summary == 'y':
        print("  - review_summary_[timestamp].txt (executive summary)")
    
    print("\n All done! Review the reports and start fixing issues.\n")


if __name__ == "__main__":
    main()