import ollama
import os
from pathlib import Path

class ComprehensiveProjectAnalyzer:
    """AI-Powered Complete Project Analysis - Single File Solution"""

    def __init__(self, model='qwen2.5:3b'):
        self.model = model
        self.project_path = None
        print(f"✅ Project Analyzer initialized with {model}\n")

    def analyze_entire_project(self, project_path):
        """Main function - Analyzes everything"""
        self.project_path = Path(project_path)

        if not self.project_path.exists():
            print(f"❌ Error: Path does not exist: {project_path}")
            return None

        print("="*80)
        print("🔍 COMPREHENSIVE PROJECT ANALYSIS STARTING...")
        print("="*80)
        print(f"📁 Project: {self.project_path}\n")

        # Collect all project data
        print("📊 Step 1: Scanning project structure...")
        structure = self._get_project_structure()

        print("📊 Step 2: Reading code files...")
        backend_code = self._collect_backend_files()
        frontend_code = self._collect_frontend_files()

        print("📊 Step 3: Analyzing with AI (this may take a few minutes)...\n")

        # Create comprehensive prompt
        full_analysis = self._analyze_everything(structure, backend_code, frontend_code)

        return full_analysis

    def _get_project_structure(self):
        """Get project directory tree"""
        structure = []
        for root, dirs, files in os.walk(self.project_path):
            # Skip common ignore folders
            dirs[:] = [d for d in dirs if d not in ['venv', 'node_modules', '__pycache__', '.git', '.vscode']]

            level = root.replace(str(self.project_path), '').count(os.sep)
            indent = '  ' * level
            structure.append(f'{indent}{os.path.basename(root)}/')

            sub_indent = '  ' * (level + 1)
            for file in files:
                structure.append(f'{sub_indent}{file}')

        return '\n'.join(structure)

    def _read_file_safe(self, file_path, max_lines=200):
        """Safely read file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                return ''.join(lines[:max_lines])
        except:
            return "[Could not read file]"

    def _collect_backend_files(self):
        """Collect all Python backend files"""
        backend_files = {}

        for file in self.project_path.rglob('*.py'):
            if 'venv' not in str(file) and '__pycache__' not in str(file):
                relative_path = file.relative_to(self.project_path)
                content = self._read_file_safe(file)
                backend_files[str(relative_path)] = content

        print(f"   Found {len(backend_files)} Python files")
        return backend_files

    def _collect_frontend_files(self):
        """Collect all frontend files"""
        frontend_files = {'html': {}, 'css': {}, 'js': {}}

        # HTML files
        for file in self.project_path.rglob('*.html'):
            relative_path = file.relative_to(self.project_path)
            frontend_files['html'][str(relative_path)] = self._read_file_safe(file)

        # CSS files
        for file in self.project_path.rglob('*.css'):
            relative_path = file.relative_to(self.project_path)
            frontend_files['css'][str(relative_path)] = self._read_file_safe(file)

        # JavaScript files
        for file in self.project_path.rglob('*.js'):
            if 'node_modules' not in str(file):
                relative_path = file.relative_to(self.project_path)
                frontend_files['js'][str(relative_path)] = self._read_file_safe(file)

        total = len(frontend_files['html']) + len(frontend_files['css']) + len(frontend_files['js'])
        print(f"   Found {total} frontend files (HTML: {len(frontend_files['html'])}, CSS: {len(frontend_files['css'])}, JS: {len(frontend_files['js'])})")

        return frontend_files

    def _analyze_everything(self, structure, backend_code, frontend_code):
        """Send everything to AI for comprehensive analysis"""

        # Build backend code section
        backend_section = "=== BACKEND CODE (Python) ===\n\n"
        for filepath, code in list(backend_code.items())[:10]:  # Limit to 10 files
            backend_section += f"\n--- FILE: {filepath} ---\n{code}\n"

        # Build frontend code section
        frontend_section = "=== FRONTEND CODE ===\n\n"

        for filepath, code in frontend_code['html'].items():
            frontend_section += f"\n--- HTML: {filepath} ---\n{code}\n"

        for filepath, code in list(frontend_code['css'].items())[:5]:
            frontend_section += f"\n--- CSS: {filepath} ---\n{code}\n"

        for filepath, code in list(frontend_code['js'].items())[:5]:
            frontend_section += f"\n--- JavaScript: {filepath} ---\n{code}\n"

        # Create mega-prompt
        mega_prompt = f"""
You are analyzing a complete software project. Provide a COMPREHENSIVE analysis covering EVERY aspect.

==============================================================================
PROJECT STRUCTURE:
==============================================================================
{structure}

==============================================================================
{backend_section}

==============================================================================
{frontend_section}

==============================================================================
COMPREHENSIVE ANALYSIS REQUIRED:
==============================================================================

Analyze EVERY sector and EVERY function of this project. Provide detailed findings for:

---
1. 🏗️ PROJECT STRUCTURE & ORGANIZATION
---
- Is the folder structure logical and maintainable?
- Are files properly organized?
- Missing critical files (README, .gitignore, requirements.txt, etc.)?
- Configuration management issues?
- Best practices violations?

RATING: [Excellent / Good / Needs Improvement / Poor]
CRITICAL ISSUES:
RECOMMENDATIONS:

---
2. ⚙️ BACKEND CODE ANALYSIS
---
For EACH Python file, analyze:

**CODE QUALITY:**
- Structure and readability
- Functions/classes design
- Code duplication
- Naming conventions
- Comments and documentation

**SECURITY VULNERABILITIES:**
- SQL Injection risks
- XSS vulnerabilities
- Authentication/Authorization flaws
- Input validation missing
- Sensitive data exposure
- CSRF protection
- Session management issues
- Password storage
- API security

**BUGS & LOGIC ERRORS:**
- Exception handling problems
- Edge cases not handled
- Resource leaks
- Race conditions
- Null/None reference errors

**PERFORMANCE ISSUES:**
- Database query optimization
- N+1 query problems
- Inefficient loops/algorithms
- Memory leaks
- Blocking operations
- Caching opportunities

**ARCHITECTURE:**
- Separation of concerns
- Design patterns used/needed
- Code coupling
- Scalability concerns
- Database design

RATING: [Excellent / Good / Needs Improvement / Poor]
CRITICAL ISSUES (with line numbers if possible):
HIGH PRIORITY FIXES:
MEDIUM PRIORITY IMPROVEMENTS:

---
3. 🎨 FRONTEND ANALYSIS
---

**HTML ANALYSIS:**
- Semantic HTML usage
- Accessibility (WCAG compliance)
- SEO optimization
- Form validation
- Meta tags
- Structure issues

**CSS ANALYSIS:**
- Code organization
- Responsive design
- Browser compatibility
- Performance (render-blocking)
- Modern CSS practices
- Design consistency

**JAVASCRIPT ANALYSIS:**
- Code quality and structure
- Security issues (XSS, DOM manipulation)
- Error handling
- Event handling
- Memory leaks
- Modern JS practices (ES6+)
- Performance optimizations

**UI/UX EVALUATION:**
- User interface design quality
- Navigation clarity
- Visual hierarchy
- Color scheme effectiveness
- Typography
- Layout responsiveness
- User experience flow
- Loading states
- Error messages

**SPECIFIC FRONTEND RECOMMENDATIONS:**
What should be ADDED:
What should be REMOVED:
What should be CHANGED:
Modern frameworks to consider (React, Vue, Tailwind, etc.):

RATING: [Excellent / Good / Needs Improvement / Poor]
CRITICAL ISSUES:
DESIGN IMPROVEMENTS:

---
4. 🔒 SECURITY AUDIT
---
List ALL security vulnerabilities found:

CRITICAL SEVERITY:
- [List with file names and details]

HIGH SEVERITY:
- [List with file names and details]

MEDIUM SEVERITY:
- [List with file names and details]

LOW SEVERITY:
- [List with file names and details]

OWASP Top 10 Coverage:
- A01:2021 – Broken Access Control: [Found/Not Found]
- A02:2021 – Cryptographic Failures: [Found/Not Found]
- A03:2021 – Injection: [Found/Not Found]
- A04:2021 – Insecure Design: [Found/Not Found]
- A05:2021 – Security Misconfiguration: [Found/Not Found]
- A06:2021 – Vulnerable Components: [Found/Not Found]
- A07:2021 – Authentication Failures: [Found/Not Found]
- A08:2021 – Data Integrity Failures: [Found/Not Found]
- A09:2021 – Logging Failures: [Found/Not Found]
- A10:2021 – SSRF: [Found/Not Found]

---
5. 📊 OVERALL PROJECT HEALTH
---

**STRENGTHS:**
- What is done well?

**WEAKNESSES:**
- What are the major problems?

**TECHNICAL DEBT:**
- What needs refactoring?

**MISSING FEATURES:**
- What's lacking?

---
6. 🎯 ACTIONABLE RECOMMENDATIONS
---

**IMMEDIATE FIXES (Do Today):**
1.
2.
3.

**HIGH PRIORITY (This Week):**
1.
2.
3.

**MEDIUM PRIORITY (This Month):**
1.
2.
3.

**LONG-TERM IMPROVEMENTS:**
1.
2.
3.

---
7. 🚀 MODERNIZATION & BEST PRACTICES
---

**Technologies to Adopt:**
-

**Frameworks/Libraries to Consider:**
-

**Development Practices to Implement:**
-

**Tools to Add:**
-

---
8. 📈 IMPROVEMENT ROADMAP
---

**Phase 1 (Week 1-2): Critical Fixes**
-

**Phase 2 (Week 3-4): Security & Performance**
-

**Phase 3 (Month 2): Refactoring**
-

**Phase 4 (Month 3): Modernization**
-

---
FINAL OVERALL RATING: [Score out of 10]
---

Be extremely detailed, specific, and actionable. Reference actual code, file names, and line numbers where possible.
"""

        # Send to AI
        print("🤖 Analyzing with AI...")
        response = ollama.chat(
            model=self.model,
            messages=[
                {
                    'role': 'system',
                    'content': 'You are a senior software architect, security expert, and code reviewer with 15+ years of experience. Provide comprehensive, detailed, and actionable analysis.'
                },
                {'role': 'user', 'content': mega_prompt}
            ]
        )

        return response['message']['content']

    def save_report(self, analysis, filename='comprehensive_analysis.txt'):
        """Save analysis to file"""
        output_path = self.project_path / filename

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("COMPREHENSIVE PROJECT ANALYSIS REPORT\n")
            f.write("="*80 + "\n")
            f.write(f"Project: {self.project_path}\n")
            f.write(f"Analyzed by: AI-Powered Project Analyzer\n")
            f.write("="*80 + "\n\n")
            f.write(analysis)

        print(f"\n💾 Report saved to: {output_path}")
        return output_path


def main():
    """Main entry point"""

    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        COMPREHENSIVE PROJECT ANALYZER                            ║
║        AI-Powered Deep Code & Architecture Review                ║
║                                                                  ║
║  Analyzes: Structure | Backend | Frontend | Security | UX       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)

    # Get project path
    print("📁 Enter the path to your project folder:")
    print("   (Press Enter to use current directory)\n")

    project_path = input("Project Path: ").strip()

    if not project_path:
        project_path = os.getcwd()

    print(f"\n📂 Selected: {project_path}\n")

    # Confirm
    confirm = input("Start analysis? (y/n): ").strip().lower()

    if confirm != 'y':
        print("❌ Analysis cancelled.")
        return

    # Initialize analyzer
    analyzer = ComprehensiveProjectAnalyzer()

    # Run analysis
    print("\n⏳ This will take several minutes depending on project size...")
    print("🔄 Please wait...\n")

    try:
        analysis_result = analyzer.analyze_entire_project(project_path)

        if not analysis_result:
            print("❌ Analysis failed.")
            return

        print("\n" + "="*80)
        print("✅ ANALYSIS COMPLETE!")
        print("="*80)

        # Show results
        print("\n📊 ANALYSIS RESULTS:\n")
        print(analysis_result)

        # Save to file
        print("\n" + "="*80)
        save = input("\n💾 Save report to file? (y/n): ").strip().lower()

        if save == 'y':
            filename = input("Filename (default: comprehensive_analysis.txt): ").strip()
            if not filename:
                filename = 'comprehensive_analysis.txt'

            saved_path = analyzer.save_report(analysis_result, filename)
            print(f"✅ Report saved successfully!")
            print(f"📄 Location: {saved_path}")

        print("\n🎉 All done! Review the analysis and start improving your project.\n")

    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()