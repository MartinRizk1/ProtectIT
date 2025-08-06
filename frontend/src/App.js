import React, { useState, useEffect, useCallback } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  Box,
  Button,
  LinearProgress,
  Alert,
  Snackbar,
  CircularProgress,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Divider
} from '@mui/material';
import {
  Security,
  Computer,
  Warning,
  CheckCircle,
  ErrorOutline,
  ReportProblem
} from '@mui/icons-material';
import io from 'socket.io-client';
import axios from 'axios';
import './App.css';

function App() {
  const [socket, setSocket] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [currentItem, setCurrentItem] = useState('');
  const [scanStatus, setScanStatus] = useState('idle'); // idle, scanning, completed, error
  const [threatCount, setThreatCount] = useState(0);
  const [alertOpen, setAlertOpen] = useState(false);
  const [alertMessage, setAlertMessage] = useState('');
  const [alertSeverity, setAlertSeverity] = useState('info');
  const [scanResults, setScanResults] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');

  // Show alert message helper function
  const showAlert = useCallback((message, severity = 'info') => {
    setAlertMessage(message);
    setAlertSeverity(severity);
    setAlertOpen(true);
  }, []);

  // Handle socket reconnection
  const connectSocket = useCallback(() => {
    try {
      // Close existing socket if any
      if (socket) {
        socket.disconnect();
      }
      
      // Initialize new socket connection using environment variable
      const socketUrl = process.env.REACT_APP_WEBSOCKET_URL || 'ws://localhost:5000';
      const socketBaseUrl = socketUrl.replace('ws://', 'http://').replace('wss://', 'https://');
      const newSocket = io(socketBaseUrl, {
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        timeout: 20000
      });
      
      setSocket(newSocket);
      
      // Socket connection events
      newSocket.on('connect', () => {
        console.log('Connected to scanner backend');
        setConnectionStatus('connected');
        showAlert('Connected to scanner service', 'success');
      });
      
      newSocket.on('disconnect', () => {
        console.log('Disconnected from scanner backend');
        setConnectionStatus('disconnected');
        showAlert('Connection to scanner service lost. Attempting to reconnect...', 'warning');
      });
      
      newSocket.on('connect_error', (err) => {
        console.error('Connection error:', err);
        setConnectionStatus('error');
        showAlert('Error connecting to scanner service. Check if backend is running.', 'error');
      });

      // Socket event listeners
      newSocket.on('connected', (data) => {
        console.log('Socket event - connected:', data);
      });

      newSocket.on('scan_started', (data) => {
        console.log('Scan started:', data);
        setIsScanning(true);
        setScanStatus('scanning');
        setScanProgress(0);
        setScanId(data.scan_id);
        setCurrentItem(data.target || data.file || 'Initializing scan...');
        setScanResults(null);
      });

      newSocket.on('scan_progress', (data) => {
        setScanProgress(data.progress || 0);
        if (data.current_item) {
          setCurrentItem(data.current_item);
        }
      });

      newSocket.on('scan_complete', (data) => {
        console.log('Scan completed:', data);
        setIsScanning(false);
        setScanStatus('completed');
        setScanProgress(100);
        
        // Process results
        const threats = data.result?.threats || [];
        setThreatCount(threats.length);
        setScanResults(data.result);
        
        // Show alert with threat information
        const message = data.summary || 
          `Scan completed! Found ${threats.length} potential threat${threats.length !== 1 ? 's' : ''}`;
        showAlert(message, threats.length > 0 ? 'warning' : 'success');
      });

      newSocket.on('scan_error', (data) => {
        console.error('Scan error:', data);
        setIsScanning(false);
        setScanStatus('error');
        showAlert(`Scan error: ${data.error || 'Unknown error occurred'}`, 'error');
      });
      
      return newSocket;
    } catch (err) {
      console.error('Error setting up socket:', err);
      showAlert('Failed to connect to scanner service', 'error');
      return null;
    }
  }, [socket, showAlert]);
  
  useEffect(() => {
    const newSocket = connectSocket();
    
    // Check backend health
    const checkHealth = async () => {
      try {
        const response = await axios.get('/api/health');
        console.log('Backend health:', response.data);
      } catch (error) {
        console.error('Health check failed:', error);
        showAlert('Cannot reach backend service', 'error');
      }
    };
    
    checkHealth();
    
    // Clean up on unmount
    return () => {
      if (newSocket) {
        newSocket.disconnect();
      }
    };
  }, [connectSocket, showAlert]);

  const startSystemScan = async () => {
    try {
      setIsScanning(true);
      setScanProgress(0);
      setScanStatus('scanning');
      setCurrentItem('Initializing scan...');
      setScanResults(null);
      
      const response = await axios.post('/api/scan/system');
      console.log('Scan initiated:', response.data);
      
      // Store the scan ID
      if (response.data && response.data.scan_id) {
        setScanId(response.data.scan_id);
      }
      
      showAlert('Full system scan started', 'info');
    } catch (error) {
      setIsScanning(false);
      setScanStatus('error');
      showAlert(`Error starting scan: ${error.message}`, 'error');
    }
  };
  
  const handleAlertClose = () => {
    setAlertOpen(false);
  };

  // Get the appropriate icon and color based on scan status
  const getScanStatusInfo = () => {
    switch(scanStatus) {
      case 'completed':
        return {
          icon: threatCount > 0 ? <ReportProblem fontSize="large" /> : <CheckCircle fontSize="large" />,
          color: threatCount > 0 ? '#FF9800' : '#4CAF50',
          text: threatCount > 0 
            ? `Scan complete: ${threatCount} threat${threatCount !== 1 ? 's' : ''} found`
            : 'Scan complete: No threats found'
        };
      case 'error':
        return {
          icon: <ErrorOutline fontSize="large" />,
          color: '#F44336',
          text: 'Scan failed. Please try again.'
        };
      case 'scanning':
        return {
          icon: <CircularProgress size={30} />,
          color: '#2196F3',
          text: `Scanning: ${currentItem || 'Initializing...'}`
        };
      default:
        return {
          icon: <Computer fontSize="large" />,
          color: '#757575',
          text: 'Click to scan your computer'
        };
    }
  };

  const renderThreatList = () => {
    if (!scanResults || !scanResults.threats || scanResults.threats.length === 0) {
      return null;
    }
    
    return (
      <Paper sx={{ mt: 3, p: 2, maxHeight: '300px', overflow: 'auto' }}>
        <Typography variant="h6" gutterBottom>
          Detected Threats
        </Typography>
        <List dense>
          {scanResults.threats.map((threat, index) => {
            const riskColor = 
              threat.risk_level === 'HIGH' ? '#d32f2f' :
              threat.risk_level === 'MEDIUM' ? '#f57c00' : 
              threat.risk_level === 'LOW' ? '#ffb74d' : '#757575';
              
            return (
              <React.Fragment key={index}>
                <ListItem>
                  <ListItemIcon>
                    <Warning style={{ color: riskColor }} />
                  </ListItemIcon>
                  <ListItemText 
                    primary={threat.name || 'Unknown threat'} 
                    secondary={`${threat.file_path || 'Unknown location'}`} 
                  />
                  <Chip 
                    label={threat.risk_level || 'UNKNOWN'} 
                    size="small" 
                    style={{ 
                      backgroundColor: riskColor,
                      color: 'white' 
                    }} 
                  />
                </ListItem>
                {index < scanResults.threats.length - 1 && <Divider />}
              </React.Fragment>
            );
          })}
        </List>
      </Paper>
    );
  };

  const statusInfo = getScanStatusInfo();

  return (
    <div className="App">
      <AppBar position="static">
        <Toolbar>
          <Security style={{ marginRight: '10px' }} />
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            ProtectIT Malware Scanner
          </Typography>
          <Chip 
            label={connectionStatus === 'connected' ? 'Connected' : 'Disconnected'} 
            color={connectionStatus === 'connected' ? 'success' : 'error'}
            size="small"
            sx={{ mr: 2 }}
          />
        </Toolbar>
      </AppBar>

      <Container maxWidth="sm" style={{ marginTop: '50px', textAlign: 'center' }}>
        <Box 
          sx={{
            p: 5,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            bgcolor: 'background.paper',
            borderRadius: 2,
            boxShadow: 3,
          }}
        >
          <Box sx={{ color: statusInfo.color, mb: 2 }}>
            {statusInfo.icon}
          </Box>
          
          <Typography variant="h5" gutterBottom>
            {statusInfo.text}
          </Typography>
          
          {isScanning && (
            <Box sx={{ width: '100%', mt: 3 }}>
              <LinearProgress 
                variant="determinate" 
                value={scanProgress} 
                sx={{ height: 10, borderRadius: 5 }} 
              />
              <Typography variant="body2" align="right" sx={{ mt: 1 }}>
                {Math.round(scanProgress)}%
              </Typography>
              {currentItem && (
                <Typography variant="body2" align="center" sx={{ mt: 1, color: 'text.secondary' }}>
                  {currentItem}
                </Typography>
              )}
            </Box>
          )}
          
          {scanStatus === 'completed' && threatCount > 0 && renderThreatList()}
          
          <Button
            variant="contained"
            size="large"
            color="primary"
            onClick={startSystemScan}
            disabled={isScanning}
            sx={{ 
              mt: 4, 
              py: 2, 
              px: 4, 
              borderRadius: 3,
              fontSize: '1.2rem',
              fontWeight: 'bold',
              width: '240px'
            }}
          >
            {isScanning ? 'SCANNING...' : 'SCAN COMPUTER'}
          </Button>
        </Box>
      </Container>

      <Snackbar 
        open={alertOpen} 
        autoHideDuration={6000} 
        onClose={handleAlertClose}
      >
        <Alert 
          onClose={handleAlertClose} 
          severity={alertSeverity}
          sx={{ width: '100%' }}
        >
          {alertMessage}
        </Alert>
      </Snackbar>
    </div>
  );
}

export default App;
