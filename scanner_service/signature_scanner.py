import os
import re
import logging

class SignatureScanner:
    """Simple replacement for YARA using regex patterns"""
    
    def __init__(self, rules_file=None):
        self.rules = []
        self.logger = logging.getLogger("SignatureScanner")
        
        if rules_file and os.path.exists(rules_file):
            self.load_rules_from_file(rules_file)
        else:
            self.load_default_rules()
    
    def load_rules_from_file(self, rules_file):
        """Load rules from a simplified rule file"""
        try:
            with open(rules_file, 'r') as f:
                rule_text = f.read()
                
            # Extract rule patterns
            rule_blocks = re.findall(r'rule\s+(\w+)\s*{[^}]+?strings:([^}]+)condition:([^}]+)}', 
                                    rule_text, re.DOTALL)
            
            for name, strings_block, condition in rule_blocks:
                patterns = {}
                # Extract string definitions
                string_defs = re.findall(r'\$(\w+)\s*=\s*"([^"]+)"', strings_block)
                for var_name, pattern in string_defs:
                    patterns[var_name] = pattern
                
                # Extract metadata if available
                meta = {}
                meta_block = re.search(r'meta:([^}]+?)(strings:|condition:)', rule_text, re.DOTALL)
                if meta_block:
                    meta_text = meta_block.group(1)
                    meta_items = re.findall(r'(\w+)\s*=\s*"([^"]+)"', meta_text)
                    for key, value in meta_items:
                        meta[key] = value
                
                # Store rule
                self.rules.append({
                    'name': name,
                    'patterns': patterns,
                    'condition': condition.strip(),
                    'meta': meta
                })
                
            self.logger.info(f"Loaded {len(self.rules)} rules from {rules_file}")
        except Exception as e:
            self.logger.error(f"Error loading rules from {rules_file}: {str(e)}")
            self.load_default_rules()
    
    def load_default_rules(self):
        """Load some default detection rules"""
        self.rules = [
            {
                'name': 'SuspiciousFile',
                'patterns': {
                    's1': 'CreateRemoteThread',
                    's2': 'VirtualAlloc',
                    's3': 'WriteProcessMemory',
                    's4': 'ShellExecute',
                    's5': 'cmd.exe /c',
                    's6': 'powershell.exe -e',
                    's7': 'eval\\(base64_decode',
                    's8': 'WScript.Shell'
                },
                'condition': '2 of them',
                'meta': {
                    'description': 'Detects suspicious file characteristics',
                    'author': 'ProtectIT',
                    'score': '70'
                }
            },
            {
                'name': 'MalwarePattern',
                'patterns': {
                    'a1': 'botnet',
                    'a2': 'backdoor',
                    'a3': 'trojan',
                    'a4': 'keylogger',
                    'a5': 'ransomware'
                },
                'condition': 'any of them',
                'meta': {
                    'description': 'Common malware patterns',
                    'author': 'ProtectIT',
                    'score': '85'
                }
            },
            {
                'name': 'SuspiciousPacker',
                'patterns': {
                    'upx': 'UPX!',
                    'mpress': 'MPRESS',
                    'aspack': 'ASPack',
                    'fsg': 'FSG!',
                    'pecompact': 'PECompact'
                },
                'condition': 'any of them',
                'meta': {
                    'description': 'Detects common packer signatures',
                    'author': 'ProtectIT',
                    'score': '60'
                }
            }
        ]
        self.logger.info(f"Loaded {len(self.rules)} default rules")
    
    def scan_data(self, data, filename=None):
        """Scan binary data for matches against all rules"""
        if not isinstance(data, str):
            try:
                data = data.decode('utf-8', errors='ignore')
            except:
                data = str(data)
        
        results = []
        
        for rule in self.rules:
            matches = {}
            
            # Check each pattern
            for var_name, pattern in rule['patterns'].items():
                try:
                    if re.search(pattern, data, re.IGNORECASE):
                        matches[var_name] = True
                except Exception as e:
                    self.logger.error(f"Error with pattern '{pattern}': {str(e)}")
            
            # Evaluate condition
            condition = rule['condition'].lower()
            match = False
            
            if condition == 'any of them':
                match = len(matches) > 0
            elif 'all of them' in condition:
                match = len(matches) == len(rule['patterns'])
            elif 'of them' in condition:
                # Parse "X of them" condition
                count_match = re.match(r'(\d+)\s+of\s+them', condition)
                if count_match:
                    required = int(count_match.group(1))
                    match = len(matches) >= required
            
            if match:
                score = int(rule['meta'].get('score', 50))
                results.append({
                    'rule': rule['name'],
                    'meta': rule['meta'],
                    'matches': list(matches.keys()),
                    'score': score,
                    'description': rule['meta'].get('description', 'No description')
                })
        
        return results
    
    def scan_file(self, file_path):
        """Scan a file for matches against all rules"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            return self.scan_data(data, filename=os.path.basename(file_path))
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {str(e)}")
            return []


# Simple test function
def test_signature_scanner():
    scanner = SignatureScanner()
    test_data = "This is a test with some malicious content like botnet and VirtualAlloc and WriteProcessMemory"
    results = scanner.scan_data(test_data)
    
    print(f"Scan Results: {len(results)} matches")
    for result in results:
        print(f" - Rule: {result['rule']}")
        print(f"   Score: {result['score']}")
        print(f"   Description: {result['description']}")
        print(f"   Matches: {', '.join(result['matches'])}")
    
    return results


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    # Run test
    test_signature_scanner()
