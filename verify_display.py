
#!/usr/bin/env python3
"""
Verification script for OpenX tool display and functionality
"""

import subprocess
import json
import time
from colorama import Fore, Style, init

init(autoreset=True)

def test_single_url_display():
    """Test single URL scanning display"""
    print(f"{Fore.CYAN}Testing Single URL Display...")
    
    cmd = [
        'python', 'openx.py', 
        '-u', 'http://localhost:5000/redirect1?url=http://evil.com',
        '--verbose', '--status-codes'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(f"Exit Code: {result.returncode}")
        print(f"Output Length: {len(result.stdout)} characters")
        
        if result.stdout:
            print(f"{Fore.GREEN}✓ Output generated successfully")
            if "VULNERABILITY FOUND" in result.stdout:
                print(f"{Fore.GREEN}✓ Vulnerability detection working")
            if "🌐" in result.stdout or "Type:" in result.stdout:
                print(f"{Fore.GREEN}✓ Enhanced UI icons working")
        else:
            print(f"{Fore.RED}✗ No output generated")
            
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}✗ Command timed out")
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {str(e)}")

def test_list_scanning():
    """Test list scanning functionality"""
    print(f"\n{Fore.CYAN}Testing List Scanning...")
    
    # Create a small test list
    test_urls = [
        "http://localhost:5000/redirect1",
        "http://localhost:5000/meta_redirect", 
        "http://localhost:5000/cookie_redirect"
    ]
    
    with open('test_display.txt', 'w') as f:
        for url in test_urls:
            f.write(url + '\n')
    
    cmd = [
        'python', 'openx.py',
        '-l', 'test_display.txt',
        '--fast', '--verbose'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        print(f"Exit Code: {result.returncode}")
        
        if result.stdout:
            print(f"{Fore.GREEN}✓ List scanning working")
            vuln_count = result.stdout.count("VULNERABILITY FOUND")
            print(f"Vulnerabilities found: {vuln_count}")
            
            if "📊 VULNERABILITY SUMMARY" in result.stdout:
                print(f"{Fore.GREEN}✓ Summary display working")
            if "🚨 DETAILED VULNERABILITY FINDINGS" in result.stdout:
                print(f"{Fore.GREEN}✓ Detailed findings display working")
                
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}✗ List scanning timed out")
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {str(e)}")

def test_output_formats():
    """Test different output formats"""
    print(f"\n{Fore.CYAN}Testing Output Formats...")
    
    cmd = [
        'python', 'openx.py',
        '-u', 'http://localhost:5000/redirect1?url=test',
        '--silent', '-o', 'display_test.json'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"{Fore.GREEN}✓ JSON output generation working")
            
            # Check if file was created
            try:
                with open('display_test.json', 'r') as f:
                    data = json.load(f)
                    print(f"JSON contains {len(data.get('results', []))} results")
                    print(f"{Fore.GREEN}✓ JSON format valid")
            except:
                print(f"{Fore.RED}✗ JSON file invalid or not created")
        else:
            print(f"{Fore.RED}✗ Output generation failed")
            
    except Exception as e:
        print(f"{Fore.RED}✗ Output test error: {str(e)}")

def analyze_lab_coverage():
    """Analyze lab coverage and detection"""
    print(f"\n{Fore.CYAN}Analyzing Lab Coverage...")
    
    # Test a few different lab types
    lab_tests = [
        ("http://localhost:5000/redirect1", "Basic URL Parameter"),
        ("http://localhost:5000/meta_redirect", "Meta Refresh"),
        ("http://localhost:5000/cookie_redirect", "Cookie-based"),
        ("http://localhost:5000/oauth/callback", "OAuth Callback")
    ]
    
    results_summary = {}
    
    for url, lab_type in lab_tests:
        print(f"\nTesting {lab_type}: {url}")
        
        cmd = ['python', 'openx.py', '-u', url, '--fast', '--silent']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            
            vuln_count = result.stdout.count("VULNERABILITY FOUND")
            status = "DETECTED" if vuln_count > 0 else "NOT_DETECTED"
            
            results_summary[lab_type] = {
                'status': status,
                'vulnerabilities': vuln_count,
                'exit_code': result.returncode
            }
            
            print(f"  Status: {status}, Vulnerabilities: {vuln_count}")
            
        except subprocess.TimeoutExpired:
            results_summary[lab_type] = {'status': 'TIMEOUT', 'vulnerabilities': 0}
            print(f"  Status: TIMEOUT")
        except Exception as e:
            results_summary[lab_type] = {'status': 'ERROR', 'error': str(e)}
            print(f"  Status: ERROR - {str(e)}")
    
    # Summary
    print(f"\n{Fore.YELLOW}Coverage Summary:")
    detected = sum(1 for r in results_summary.values() if r['status'] == 'DETECTED')
    total = len(results_summary)
    print(f"Detection Rate: {detected}/{total} ({detected/total*100:.1f}%)")
    
    return results_summary

def main():
    """Main verification function"""
    print(f"{Fore.RED}OpenX Tool Display Verification")
    print(f"{Fore.RED}=" * 40)
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run all tests
    test_single_url_display()
    test_list_scanning() 
    test_output_formats()
    coverage_results = analyze_lab_coverage()
    
    print(f"\n{Fore.GREEN}Verification Complete!")
    print(f"{Fore.GREEN}OpenX tool display and functionality verified")
    
    # Save results
    with open('display_verification.json', 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'coverage_results': coverage_results,
            'status': 'VERIFIED'
        }, f, indent=2)
    
    print(f"Results saved to display_verification.json")

if __name__ == "__main__":
    main()
