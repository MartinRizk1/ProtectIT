import os
import numpy as np
import pandas as pd
import pickle
import logging
import hashlib
import pefile
import math
try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False
    print("Warning: ssdeep not available, fuzzy hashing disabled")

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False
    print("Warning: lief not available, some binary analysis features disabled")

import time
import joblib
import re
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset, random_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("Warning: XGBoost not available")

try:
    from lightgbm import LGBMClassifier
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    print("Warning: LightGBM not available")

from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='ml_detector.log'
)
logger = logging.getLogger('ml-detector')

# PyTorch Neural Network for malware detection
class MalwareNN(nn.Module):
    def __init__(self, input_size):
        """Initialize the PyTorch neural network for malware detection"""
        super(MalwareNN, self).__init__()
        self.layer1 = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3)
        )
        self.layer2 = nn.Sequential(
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.3)
        )
        self.layer3 = nn.Sequential(
            nn.Linear(64, 16),
            nn.BatchNorm1d(16),
            nn.ReLU()
        )
        self.output = nn.Linear(16, 1)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        """Forward pass through the neural network"""
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.layer3(x)
        x = self.output(x)
        x = self.sigmoid(x)
        return x
        
class MalwareDataset(Dataset):
    """Dataset class for PyTorch data loading"""
    def __init__(self, X, y=None, transform=None):
        self.X = X
        self.y = y
        self.transform = transform
        
    def __len__(self):
        return len(self.X)
        
    def __getitem__(self, idx):
        x = self.X[idx]
        if self.transform:
            x = self.transform(x)
        
        if self.y is not None:
            return x, self.y[idx]
        return x

class MalwareDetector:
    def __init__(self):
        """Initialize the ML-based malware detector"""
        self.model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
        self.model_path = os.path.join(self.model_dir, 'malware_model.pkl')
        self.scaler_path = os.path.join(self.model_dir, 'feature_scaler.pkl')
        self.feature_importances_path = os.path.join(self.model_dir, 'feature_importances.csv')
        self.pytorch_model_path = os.path.join(self.model_dir, 'malware_nn_model.pth')
        
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Load pre-trained models if they exist
        self.model = None
        self.scaler = None
        self.nn_model = None
        self.input_size = None
        self.load_model()
        
        # List of supported file types for analysis
        self.supported_types = [
            'application/x-dosexec',      # Windows PE files
            'application/x-executable',    # Linux ELF
            'text/x-python',               # Python scripts
            'text/x-shellscript',          # Shell scripts
            'text/javascript',             # JavaScript
            'text/x-php',                  # PHP
            'text/plain',                  # Text files that could contain malicious scripts
            'application/x-msdownload',    # Windows DLLs
            'application/vnd.microsoft.portable-executable'  # Another PE file MIME
        ]
        
        # Initialize benchmark stats
        self.scan_count = 0
        self.detection_count = 0
        self.total_scan_time = 0
        self.last_benchmark = time.time()
    def calculate_entropy(self, data):
        """Calculate entropy for given byte data."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log(p, 2)
        return entropy
        
    def load_model(self):
        """Load the pre-trained ML models and scaler"""
        models_loaded = False
        
        # Load scikit-learn model
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                logger.info("Pre-trained scikit-learn model loaded successfully")
                models_loaded = True
            else:
                logger.warning("Pre-trained scikit-learn model not found. Model training required.")
        except Exception as e:
            logger.error(f"Error loading scikit-learn model: {e}")
        
        # Load PyTorch model if it exists
        try:
            if os.path.exists(self.pytorch_model_path):
                checkpoint = torch.load(self.pytorch_model_path, map_location=torch.device('cpu'))
                self.input_size = checkpoint['input_size']
                self.nn_model = MalwareNN(self.input_size)
                self.nn_model.load_state_dict(checkpoint['model_state_dict'])
                self.nn_model.eval()  # Set to evaluation mode
                logger.info("Pre-trained PyTorch model loaded successfully")
                models_loaded = True
            else:
                logger.warning("Pre-trained PyTorch model not found.")
        except Exception as e:
            logger.error(f"Error loading PyTorch model: {e}")
        
        return models_loaded
            
    def extract_features_pe(self, file_path):
        """Extract features from PE files"""
        try:
            features = {}
            pe = pefile.PE(file_path)
            binary = lief.parse(file_path)
            
            # File size and structure features
            features['file_size'] = os.path.getsize(file_path)
            features['has_debug'] = 1 if hasattr(pe, 'DEBUG_DIRECTORY') else 0
            features['has_tls'] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0
            features['has_resources'] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
            
            # Header features
            features['num_sections'] = len(pe.sections)
            features['timestamp'] = pe.FILE_HEADER.TimeDateStamp
            features['pointer_symbol_table'] = pe.FILE_HEADER.PointerToSymbolTable
            features['num_symbols'] = pe.FILE_HEADER.NumberOfSymbols
            features['size_optional_header'] = pe.FILE_HEADER.SizeOfOptionalHeader
            features['characteristics'] = pe.FILE_HEADER.Characteristics
            
            # Optional header features
            features['major_linker_version'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
            features['minor_linker_version'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
            features['size_of_code'] = pe.OPTIONAL_HEADER.SizeOfCode
            features['size_of_initialized_data'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
            features['size_of_uninitialized_data'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
            features['address_of_entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            features['base_of_code'] = pe.OPTIONAL_HEADER.BaseOfCode
            
            # Section features
            entropy_values = []
            virtual_size_ratio = []
            for section in pe.sections:
                entropy_values.append(section.get_entropy())
                if section.Misc_VirtualSize > 0:
                    virtual_size_ratio.append(section.SizeOfRawData / section.Misc_VirtualSize)
                    
            features['avg_entropy'] = sum(entropy_values) / len(entropy_values) if entropy_values else 0
            features['max_entropy'] = max(entropy_values) if entropy_values else 0
            features['min_entropy'] = min(entropy_values) if entropy_values else 0
            features['avg_virtual_size_ratio'] = sum(virtual_size_ratio) / len(virtual_size_ratio) if virtual_size_ratio else 0
            
            # Import features
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                imports = []
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode('utf-8', errors='ignore').lower()
                                imports.append(f"{dll_name}.{func_name}")
                    except:
                        continue
                
                # Count suspicious imports
                suspicious_imports = [
                    'kernel32.createprocess', 'kernel32.createfile', 'kernel32.writeprocessmemory',
                    'kernel32.virtualallocex', 'kernel32.createremotethread', 'advapi32.regopen',
                    'wininet.internetopen', 'urlmon.urldownloadtofile', 'shell32.shellexecute',
                    'user32.findwindow', 'user32.showwindow'
                ]
                
                features['num_imports'] = len(imports)
                features['num_suspicious_imports'] = sum(1 for imp in imports if any(s in imp for s in suspicious_imports))
            else:
                features['num_imports'] = 0
                features['num_suspicious_imports'] = 0
            
            # Export features
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                features['num_exports'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            else:
                features['num_exports'] = 0
            
            # Generate fuzzy hash
            try:
                features['ssdeep_hash'] = ssdeep.hash_from_file(file_path)
            except:
                features['ssdeep_hash'] = ''
                
            # Parse binary with LIEF
            try:
                if binary:
                    features['has_signature'] = 1 if binary.has_signature else 0
                    features['has_resources'] = 1 if binary.has_resources else 0
                    features['has_tls'] = 1 if binary.has_tls else 0
                    features['has_imports'] = 1 if binary.has_imports else 0
                    features['has_exports'] = 1 if binary.has_exports else 0
                    features['has_debug'] = 1 if binary.has_debug else 0
                    features['has_relocations'] = 1 if binary.has_relocations else 0
                    features['has_exceptions'] = 1 if binary.has_exceptions else 0
                    features['has_overlay'] = 1 if binary.has_overlay else 0
                    
                    # Number of imported functions
                    features['nb_imported_functions'] = sum(len(library.entries) for library in binary.imports)
                    
                    # Number of exported functions
                    features['nb_exported_functions'] = len(binary.exported_functions) if binary.has_exports else 0
            except:
                features['has_signature'] = 0
                features['has_resources'] = features.get('has_resources', 0)
                features['has_tls'] = features.get('has_tls', 0)
                features['has_imports'] = 1 if features.get('num_imports', 0) > 0 else 0
                features['has_exports'] = 1 if features.get('num_exports', 0) > 0 else 0
                features['has_debug'] = features.get('has_debug', 0)
                features['has_relocations'] = 0
                features['has_exceptions'] = 0
                features['has_overlay'] = 0
                features['nb_imported_functions'] = features.get('num_imports', 0)
                features['nb_exported_functions'] = features.get('num_exports', 0)
            
            return features
        
        except Exception as e:
            logger.error(f"Error extracting PE features: {e}")
            return None
    
    def extract_features_script(self, file_path):
        """Extract features from script files (Python, JavaScript, etc.)"""
        try:
            features = {}
            
            # Basic file metrics
            features['file_size'] = os.path.getsize(file_path)
            
            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Try to decode as text
            try:
                text_content = content.decode('utf-8', errors='ignore').lower()
                
                # Calculate script entropy
                features['entropy'] = self.calculate_entropy(content)
                
                # Count lines
                features['num_lines'] = text_content.count('\n') + 1
                
                # Check for suspicious keywords
                suspicious_keywords = [
                    'exec', 'eval', 'system(', 'shell', 'subprocess', 'powershell', 
                    'cmd.exe', 'download', 'http://', 'https://', 'socket', 'connect',
                    'base64', 'encode', 'decode', 'encrypt', 'decrypt', 'registry',
                    'reg', 'hidden', 'wscript', 'cscript', 'installutil', 'regsvr32',
                    'bitsadmin', 'certutil', 'payload'
                ]
                
                features['num_suspicious_keywords'] = sum(text_content.count(kw) for kw in suspicious_keywords)
                
                # Check for obfuscation techniques
                obfuscation_patterns = [
                    'chr(', 'fromcharcode', '\\x', '\\u', '\\0', 'atob(', 'btoa(',
                    'charcodeat', 'unescape(', 'escape(', 'encodeuricomponent'
                ]
                features['obfuscation_score'] = sum(text_content.count(pattern) for pattern in obfuscation_patterns)
                
                # Calculate code density (ratio of code to whitespace)
                code_chars = sum(1 for c in text_content if not c.isspace())
                features['code_density'] = code_chars / len(text_content) if len(text_content) > 0 else 0
                
                # Generate fuzzy hash
                features['ssdeep_hash'] = ssdeep.hash(content)
                
                # Check for long strings (potential encoded content)
                long_strings = re.findall(r'"[^"]{100,}"|\'[^\']{100,}\'', text_content)
                features['num_long_strings'] = len(long_strings)
                
                # Calculate average line length
                lines = text_content.split('\n')
                features['avg_line_length'] = sum(len(line) for line in lines) / len(lines) if lines else 0
                
                # Count special characters
                special_chars = sum(1 for c in text_content if not c.isalnum() and not c.isspace())
                features['special_chars_ratio'] = special_chars / len(text_content) if len(text_content) > 0 else 0
                
            except Exception as e:
                logger.error(f"Error processing script content: {e}")
                # Provide defaults for text-based features
                features['entropy'] = 0
                features['num_lines'] = 0
                features['num_suspicious_keywords'] = 0
                features['obfuscation_score'] = 0
                features['code_density'] = 0
                features['ssdeep_hash'] = ''
                features['num_long_strings'] = 0
                features['avg_line_length'] = 0
                features['special_chars_ratio'] = 0
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting script features: {e}")
            return None
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy
    
    def extract_features(self, file_path, file_type):
        """Extract features from a file based on its type"""
        try:
            if 'x-dosexec' in file_type or 'x-msdownload' in file_type or 'portable-executable' in file_type:
                return self.extract_features_pe(file_path)
            elif any(script_type in file_type for script_type in ['python', 'javascript', 'shellscript', 'php', 'plain']):
                return self.extract_features_script(file_path)
            else:
                logger.warning(f"Unsupported file type for feature extraction: {file_type}")
                return None
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def predict(self, file_path, file_type):
        """Predict if a file is malicious"""
        start_time = time.time()
        
        # Check if file type is supported
        if not any(supported in file_type for supported in self.supported_types):
            return {
                'is_supported': False,
                'message': f"File type {file_type} not supported for ML analysis"
            }
            
        # Check if model is loaded
        if not self.model and not self.nn_model:
            return {
                'is_supported': True,
                'is_analyzed': False,
                'message': "No ML models initialized. Please train the models first."
            }
             
        try:
            # Extract features
            features = self.extract_features(file_path, file_type)
            if not features:
                return {
                    'is_supported': True,
                    'is_analyzed': False,
                    'message': "Failed to extract features from the file"
                }
                
            # Convert features dictionary to DataFrame
            features_df = pd.DataFrame([features])
            
            # Handle the ssdeep_hash column (non-numeric)
            if 'ssdeep_hash' in features_df.columns:
                features_df = features_df.drop(columns=['ssdeep_hash'])
                
            # Scale features
            try:
                features_scaled = self.scaler.transform(features_df)
            except Exception as e:
                logger.error(f"Error scaling features: {e}")
                # Try with only common features
                common_features = [col for col in features_df.columns if col in self.scaler.feature_names_in_]
                if not common_features:
                    return {
                        'is_supported': True,
                        'is_analyzed': False,
                        'message': f"Feature mismatch with trained model: {e}"
                    }
                    
                features_df = features_df[common_features]
                features_scaled = self.scaler.transform(features_df)
                
            # Make prediction with scikit-learn model
            sklearn_prediction = None
            sklearn_probability = None
            if self.model:
                sklearn_prediction = self.model.predict(features_scaled)[0]
                sklearn_probability = self.model.predict_proba(features_scaled)[0][1]  # Probability of malicious class
            
            # Make prediction with PyTorch model if available
            pytorch_prediction = None
            pytorch_probability = None
            if self.nn_model:
                try:
                    # Convert numpy array to PyTorch tensor
                    features_tensor = torch.FloatTensor(features_scaled)
                    
                    # Get prediction
                    with torch.no_grad():
                        pytorch_probability = self.nn_model(features_tensor).item()
                    pytorch_prediction = 1 if pytorch_probability > 0.5 else 0
                except Exception as e:
                    logger.error(f"Error in PyTorch prediction: {e}")
            
            # Combine predictions (if both models are available)
            if sklearn_prediction is not None and pytorch_prediction is not None:
                # Ensemble prediction (simple averaging)
                ensemble_prob = (sklearn_probability + pytorch_probability) / 2
                prediction = 1 if ensemble_prob > 0.5 else 0
                confidence = ensemble_prob if prediction == 1 else 1 - ensemble_prob
            elif sklearn_prediction is not None:
                prediction = sklearn_prediction
                confidence = sklearn_probability if prediction == 1 else 1 - sklearn_probability
            elif pytorch_prediction is not None:
                prediction = pytorch_prediction
                confidence = pytorch_probability if prediction == 1 else 1 - pytorch_probability
            else:
                # No models available
                return {
                    'is_supported': True,
                    'is_analyzed': False,
                    'message': "No ML models available for prediction"
                }
            
            # Update benchmark stats
            scan_time = time.time() - start_time
            self.scan_count += 1
            self.total_scan_time += scan_time
            if prediction == 1:
                self.detection_count += 1
            
            result = {
                'is_supported': True,
                'is_analyzed': True,
                'prediction': int(prediction),
                'confidence_pct': round(confidence * 100, 2),
                'sklearn_prediction': int(sklearn_prediction) if sklearn_prediction is not None else None,
                'pytorch_prediction': int(pytorch_prediction) if pytorch_prediction is not None else None,
            }
            return result
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            return {
                'is_supported': True,
                'is_analyzed': False,
                'message': f"Error during analysis: {str(e)}"
            }
    
    def train_model(self, benign_dir, malicious_dir, test_size=0.2):
        """Train the ML model with benign and malicious samples"""
        try:
            # Extract features from benign files
            benign_features = []
            benign_files = [os.path.join(benign_dir, f) for f in os.listdir(benign_dir) 
                            if os.path.isfile(os.path.join(benign_dir, f))]
            
            # Extract features from malicious files
            malicious_features = []
            malicious_files = [os.path.join(malicious_dir, f) for f in os.listdir(malicious_dir) 
                              if os.path.isfile(os.path.join(malicious_dir, f))]
            
            logger.info(f"Found {len(benign_files)} benign and {len(malicious_files)} malicious samples")
            
            # Use ThreadPoolExecutor for parallel processing
            with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
                # Process benign files
                for file_path in benign_files:
                    try:
                        file_type = os.popen(f"file --mime-type -b '{file_path}'").read().strip()
                        if any(supported in file_type for supported in self.supported_types):
                            features = self.extract_features(file_path, file_type)
                            if features:
                                features['malicious'] = 0  # Label as benign
                                benign_features.append(features)
                    except Exception as e:
                        logger.error(f"Error processing benign file {file_path}: {e}")
                
                # Process malicious files
                for file_path in malicious_files:
                    try:
                        file_type = os.popen(f"file --mime-type -b '{file_path}'").read().strip()
                        if any(supported in file_type for supported in self.supported_types):
                            features = self.extract_features(file_path, file_type)
                            if features:
                                features['malicious'] = 1  # Label as malicious
                                malicious_features.append(features)
                    except Exception as e:
                        logger.error(f"Error processing malicious file {file_path}: {e}")
            
            # Combine features
            all_features = benign_features + malicious_features
            
            if not all_features:
                logger.error("No features extracted from the provided samples")
                return {
                    'success': False,
                    'message': "No features could be extracted from the provided samples"
                }
            
            # Convert to DataFrame
            features_df = pd.DataFrame(all_features)
            
            # Handle non-numeric columns
            if 'ssdeep_hash' in features_df.columns:
                features_df = features_df.drop(columns=['ssdeep_hash'])
            
            # Split data
            X = features_df.drop('malicious', axis=1)
            y = features_df['malicious']
            
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)
            
            # Scale features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model (XGBoost)
            logger.info("Training XGBoost model...")
            self.model = XGBClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                random_state=42,
                use_label_encoder=False,
                eval_metric='logloss'
            )
            
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            cm = confusion_matrix(y_test, y_pred)
            
            # Save scikit-learn model and scaler
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            
            # Save feature importances
            feature_importances = pd.DataFrame({
                'feature': X.columns,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            feature_importances.to_csv(self.feature_importances_path, index=False)
            
            # Train PyTorch neural network model
            logger.info("Training PyTorch neural network model...")
            try:
                # Initialize the neural network model
                input_size = X_train_scaled.shape[1]
                self.nn_model = MalwareNN(input_size)
                
                # Create PyTorch dataset and dataloader
                train_dataset = MalwareDataset(
                    X=torch.FloatTensor(X_train_scaled),
                    y=torch.FloatTensor(y_train.values.reshape(-1, 1))
                )
                
                test_dataset = MalwareDataset(
                    X=torch.FloatTensor(X_test_scaled),
                    y=torch.FloatTensor(y_test.values.reshape(-1, 1))
                )
                
                train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
                test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)
                
                # Define loss function and optimizer
                criterion = nn.BCELoss()
                optimizer = optim.Adam(self.nn_model.parameters(), lr=0.001)
                
                # Train the model
                num_epochs = 30
                for epoch in range(num_epochs):
                    self.nn_model.train()
                    train_loss = 0
                    for X_batch, y_batch in train_loader:
                        # Forward pass
                        y_pred = self.nn_model(X_batch)
                        loss = criterion(y_pred, y_batch)
                        
                        # Backward pass and optimize
                        optimizer.zero_grad()
                        loss.backward()
                        optimizer.step()
                        
                        train_loss += loss.item()
                    
                    # Validate
                    if (epoch + 1) % 5 == 0:
                        self.nn_model.eval()
                        valid_loss = 0
                        correct = 0
                        total = 0
                        with torch.no_grad():
                            for X_batch, y_batch in test_loader:
                                y_pred = self.nn_model(X_batch)
                                loss = criterion(y_pred, y_batch)
                                valid_loss += loss.item()
                                
                                # Calculate accuracy
                                predicted = (y_pred > 0.5).float()
                                total += y_batch.size(0)
                                correct += (predicted == y_batch).sum().item()
                        
                        logger.info(f"Epoch {epoch+1}/{num_epochs}, Train Loss: {train_loss/len(train_loader):.4f}, "
                                   f"Valid Loss: {valid_loss/len(test_loader):.4f}, Accuracy: {100*correct/total:.2f}%")
                
                # Save the PyTorch model
                torch.save({
                    'input_size': input_size,
                    'model_state_dict': self.nn_model.state_dict(),
                }, self.pytorch_model_path)
                
                # Evaluate the PyTorch model
                self.nn_model.eval()
                nn_preds = []
                with torch.no_grad():
                    for X_batch, _ in test_loader:
                        y_pred = self.nn_model(X_batch)
                        nn_preds.extend((y_pred > 0.5).float().numpy().flatten())
                
                nn_accuracy = accuracy_score(y_test, nn_preds)
                nn_precision = precision_score(y_test, nn_preds)
                nn_recall = recall_score(y_test, nn_preds)
                nn_f1 = f1_score(y_test, nn_preds)
                
                logger.info(f"PyTorch model training completed. Accuracy: {nn_accuracy:.4f}, "
                           f"Precision: {nn_precision:.4f}, Recall: {nn_recall:.4f}, F1: {nn_f1:.4f}")
                
            except Exception as e:
                logger.error(f"Error training PyTorch model: {e}")
            
            logger.info(f"Model training completed. Scikit-learn Accuracy: {accuracy:.4f}, "
                       f"Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
            
            return {
                'success': True,
                'message': 'Model training completed',
                'sklearn_accuracy': accuracy,
                'pytorch_accuracy': nn_accuracy if 'nn_accuracy' in locals() else None
            }
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return {
                'success': False,
                'message': f"Error training model: {str(e)}"
            }
    
    def get_benchmark_stats(self):
        """Return benchmark statistics for ML detector"""
        current_time = time.time()
        elapsed = current_time - self.last_benchmark if self.last_benchmark else 0
        scans_per_minute = (self.scan_count / elapsed * 60) if elapsed > 0 else 0
        detection_rate = (self.detection_count / self.scan_count * 100) if self.scan_count > 0 else 0
        return {
            'scan_count': self.scan_count,
            'detection_count': self.detection_count,
            'total_scan_time': self.total_scan_time,
            'avg_scan_time': (self.total_scan_time / self.scan_count) if self.scan_count > 0 else 0,
            'scans_per_minute': scans_per_minute,
            'detection_rate_pct': round(detection_rate, 2)
        }
