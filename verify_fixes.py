#!/usr/bin/env python3
"""
Verification Tests for ASE Fixes
Run this to verify all fixes are working correctly
"""

import sys
sys.path.insert(0, '/path/to/ase_app/rmd/core')

from scanner import (
    validate_target_url, 
    validate_ip_address,
    full_safe_scan,
    ScanUserInfo
)
from session_manager import (
    init_session_state,
    clear_scan_results,
    get_last_error
)
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# TEST 1: INPUT VALIDATION
# ============================================================================

def test_url_validation():
    """Test URL validation layer"""
    print("\n" + "="*70)
    print("TEST 1: URL VALIDATION")
    print("="*70)
    
    test_cases = [
        # (input, should_be_valid, description)
        ("example.com", True, "Valid domain"),
        ("https://example.com", True, "Valid HTTPS URL"),
        ("google.com", False, "Blocked domain"),
        ("www.google.com", False, "Blocked domain (www)"),
        ("chatgpt.com", False, "Blocked domain"),
        ("", False, "Empty URL"),
        ("x" * 3000, False, "URL too long"),
        ("192.168.1.1", False, "Private IP"),
        ("127.0.0.1", False, "Loopback IP"),
        ("8.8.8.8", True, "Public IP (Google DNS)"),
        ("invalid!!!domain", False, "Invalid format"),
    ]
    
    passed = 0
    failed = 0
    
    for url, should_be_valid, description in test_cases:
        is_valid, result = validate_target_url(url)
        
        if is_valid == should_be_valid:
            print(f"✅ PASS: {description}")
            print(f"   Input: {url}")
            print(f"   Result: {'Valid' if is_valid else 'Invalid'}")
            if not is_valid:
                print(f"   Error: {result}")
            passed += 1
        else:
            print(f"❌ FAIL: {description}")
            print(f"   Input: {url}")
            print(f"   Expected: {'Valid' if should_be_valid else 'Invalid'}")
            print(f"   Got: {'Valid' if is_valid else 'Invalid'}")
            print(f"   Result: {result}")
            failed += 1
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def test_ip_validation():
    """Test IP address validation"""
    print("\n" + "="*70)
    print("TEST 2: IP ADDRESS VALIDATION")
    print("="*70)
    
    test_cases = [
        ("8.8.8.8", True, "Public IP (Google DNS)"),
        ("1.1.1.1", True, "Public IP (Cloudflare DNS)"),
        ("127.0.0.1", False, "Loopback"),
        ("192.168.1.1", False, "Private range"),
        ("10.0.0.1", False, "Private range"),
        ("172.16.0.1", False, "Private range"),
        ("256.1.1.1", False, "Invalid IP"),
        ("", False, "Empty IP"),
        ("not.an.ip", False, "Not an IP"),
    ]
    
    passed = 0
    failed = 0
    
    for ip, should_be_valid, description in test_cases:
        is_valid, result = validate_ip_address(ip)
        
        if is_valid == should_be_valid:
            print(f"✅ PASS: {description}")
            passed += 1
        else:
            print(f"❌ FAIL: {description}")
            print(f"   Expected: {'Valid' if should_be_valid else 'Invalid'}")
            print(f"   Got: {'Valid' if is_valid else 'Invalid'}")
            failed += 1
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


# ============================================================================
# TEST 2: SCAN RESULT ERROR HANDLING
# ============================================================================

def test_scan_error_handling():
    """Test that scan returns proper error on validation failure"""
    print("\n" + "="*70)
    print("TEST 3: SCAN ERROR HANDLING")
    print("="*70)
    
    user = ScanUserInfo(
        name="Test User",
        email="test@example.com",
        organization="Test Org",
        purpose="Testing"
    )
    
    test_cases = [
        ("google.com", False, "Should reject blocked domain"),
        ("192.168.1.1", False, "Should reject private IP"),
        ("example.com", True, "Should accept valid domain"),
    ]
    
    passed = 0
    failed = 0
    
    for target, should_succeed, description in test_cases:
        print(f"\nTesting: {description}")
        print(f"Target: {target}")
        
        result = full_safe_scan(
            user=user,
            target_url=target,
            ownership_confirmed=True,
            include_nmap=False
        )
        
        has_error = result.error is not None
        
        if has_error != should_succeed:
            # Logic: should_succeed=True means NO error expected
            # has_error=True means error found
            print(f"✅ PASS")
            print(f"   Error: {result.error}")
            passed += 1
        else:
            print(f"❌ FAIL")
            print(f"   Expected: {'Error' if has_error else 'Success'}")
            print(f"   Got: {result.error if has_error else 'Success'}")
            failed += 1
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


# ============================================================================
# TEST 3: RESULT STRUCTURE
# ============================================================================

def test_result_structure():
    """Test that FullScanResult has all required fields"""
    print("\n" + "="*70)
    print("TEST 4: RESULT STRUCTURE")
    print("="*70)
    
    user = ScanUserInfo(
        name="Test User",
        email="test@example.com",
        organization="Test Org",
        purpose="Testing"
    )
    
    result = full_safe_scan(
        user=user,
        target_url="google.com",  # Invalid - will have error
        ownership_confirmed=True,
        include_nmap=False
    )
    
    required_fields = [
        'user', 'target_url', 'ownership_confirmed',
        'timestamp_utc', 'url_scan', 'findings',
        'risk_summary', 'nmap_raw', 'error'
    ]
    
    passed = 0
    failed = 0
    
    for field in required_fields:
        if hasattr(result, field):
            print(f"✅ PASS: Field '{field}' exists")
            passed += 1
        else:
            print(f"❌ FAIL: Field '{field}' missing")
            failed += 1
    
    # Check error field is populated
    if result.error is not None:
        print(f"✅ PASS: Error field populated correctly: {result.error}")
        passed += 1
    else:
        print(f"❌ FAIL: Error field should be populated for invalid target")
        failed += 1
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


# ============================================================================
# TEST 4: SESSION MANAGEMENT
# ============================================================================

def test_session_management():
    """Test session state management"""
    print("\n" + "="*70)
    print("TEST 5: SESSION MANAGEMENT")
    print("="*70)
    
    # Mock st object
    class MockSessionState:
        def __init__(self):
            self.state = {}
        
        def __setitem__(self, key, value):
            self.state[key] = value
        
        def __getitem__(self, key):
            return self.state.get(key)
        
        def __contains__(self, key):
            return key in self.state
        
        def get(self, key, default=None):
            return self.state.get(key, default)
    
    class MockSt:
        def __init__(self):
            self.session_state = MockSessionState()
    
    st = MockSt()
    
    # Test initialization
    print("\nTesting session initialization...")
    init_session_state(st)
    
    expected_keys = [
        'current_user', 'registered_users', 'auth_mode',
        'url_result', 'url_findings', 'combined_findings',
        'risk_summary', 'light_mode', 'chat_history'
    ]
    
    passed = 0
    failed = 0
    
    for key in expected_keys:
        if key in st.session_state:
            print(f"✅ PASS: Key '{key}' initialized")
            passed += 1
        else:
            print(f"❌ FAIL: Key '{key}' not initialized")
            failed += 1
    
    # Test clearing
    print("\nTesting session clearing...")
    st.session_state['combined_findings'] = ['old', 'findings']
    clear_scan_results(st)
    
    if st.session_state['combined_findings'] == []:
        print(f"✅ PASS: Findings cleared correctly")
        passed += 1
    else:
        print(f"❌ FAIL: Findings not cleared")
        failed += 1
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def run_all_tests():
    """Run all verification tests"""
    print("\n" + "="*70)
    print("ASE APPLICATION VERIFICATION TESTS")
    print("="*70)
    
    results = []
    
    try:
        results.append(("URL Validation", test_url_validation()))
        results.append(("IP Validation", test_ip_validation()))
        results.append(("Scan Error Handling", test_scan_error_handling()))
        results.append(("Result Structure", test_result_structure()))
        results.append(("Session Management", test_session_management()))
    except Exception as e:
        logger.error(f"Test execution error: {e}", exc_info=True)
        print(f"\n❌ FATAL ERROR: {e}")
        return False
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed_tests = sum(1 for _, result in results if result)
    total_tests = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nOverall: {passed_tests}/{total_tests} test groups passed")
    
    if passed_tests == total_tests:
        print("\n🎉 ALL TESTS PASSED!")
        return True
    else:
        print(f"\n⚠️ {total_tests - passed_tests} test group(s) failed")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
