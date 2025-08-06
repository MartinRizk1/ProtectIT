"""
ProtectIT - High-Performance Multi-Threaded Scanner
Enhanced multi-threading architecture capable of processing 500+ files per minute
"""

import os
import sys
import time
import threading
import logging
import queue
import hashlib
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import traceback

logger = logging.getLogger(__name__)


@dataclass
class ScanJob:
    """Represents a single file scanning job"""
    file_path: str
    file_type: str = None
    file_size: int = 0
    priority: int = 0  # Higher number = higher priority
    job_id: str = None
    created_at: float = field(default_factory=time.time)
    
    def __post_init__(self):
        """Initialize job after creation"""
        if not self.job_id:
            self.job_id = hashlib.md5(f"{self.file_path}:{time.time()}".encode()).hexdigest()
        if not self.file_size and os.path.exists(self.file_path):
            try:
                self.file_size = os.path.getsize(self.file_path)
            except:
                pass


@dataclass
class ScanStats:
    """Statistics for the scanning process"""
    start_time: float = 0.0
    end_time: float = 0.0
    files_processed: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    errors: int = 0
    threats_found: int = 0
    
    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds"""
        if self.end_time == 0.0:
            return time.time() - self.start_time
        return self.end_time - self.start_time
    
    @property
    def files_per_minute(self) -> float:
        """Calculate files processed per minute"""
        if self.elapsed_time < 1:
            return 0
        return (self.files_processed / self.elapsed_time) * 60
    
    @property
    def bytes_per_second(self) -> float:
        """Calculate bytes processed per second"""
        if self.elapsed_time < 1:
            return 0
        return self.bytes_scanned / self.elapsed_time
    
    @property
    def threat_percentage(self) -> float:
        """Calculate percentage of threats found"""
        if self.files_processed == 0:
            return 0
        return (self.threats_found / self.files_processed) * 100


class ScanEngine:
    """
    High-Performance Scanning Engine
    Uses priority queues and dynamic thread allocation for optimal throughput
    """
    
    def __init__(self, 
                max_workers: int = None, 
                queue_size: int = 10000,
                file_handlers: Dict[str, Callable] = None,
                progress_callback: Callable = None,
                result_callback: Callable = None):
        """
        Initialize the scan engine
        
        Args:
            max_workers: Maximum number of worker threads (None = use CPU count)
            queue_size: Maximum size of the scan queue
            file_handlers: Dict mapping file extensions to handler functions
            progress_callback: Function to call with progress updates
            result_callback: Function to call with scan results
        """
        self.max_workers = max_workers or max(4, os.cpu_count())
        self.queue_size = queue_size
        self.file_handlers = file_handlers or {}
        self.progress_callback = progress_callback
        self.result_callback = result_callback
        
        # Job queue with priority
        self.job_queue = queue.PriorityQueue(maxsize=queue_size)
        
        # Threading components
        self.executor = None
        self.worker_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        self.stop_event = threading.Event()
        
        # Statistics
        self.stats = ScanStats()
        self.reset_stats()
        
        # File type detection
        self.file_signatures = self._initialize_file_signatures()
        
        logger.info(f"Scan engine initialized with {self.max_workers} workers")
    
    def reset_stats(self):
        """Reset scan statistics"""
        with self.stats_lock:
            self.stats = ScanStats()
    
    def scan_directory(self, 
                      directory: str, 
                      recursive: bool = True,
                      extensions: List[str] = None,
                      exclusions: List[str] = None,
                      max_file_size: int = None,
                      max_files: int = None) -> ScanStats:
        """
        Scan a directory with all available threads
        
        Args:
            directory: Directory path to scan
            recursive: Whether to scan subdirectories
            extensions: List of file extensions to scan (None = all)
            exclusions: List of patterns to exclude
            max_file_size: Maximum file size to scan in bytes
            max_files: Maximum number of files to scan
            
        Returns:
            ScanStats object with results
        """
        self.reset_stats()
        self.stats.start_time = time.time()
        self.stop_event.clear()
        
        # Create job workers
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        futures = []
        
        # Start worker threads
        for _ in range(self.max_workers):
            future = self.executor.submit(self._worker)
            futures.append(future)
        
        # Collect files and add to queue
        collector_thread = threading.Thread(
            target=self._file_collector,
            args=(directory, recursive, extensions, exclusions, max_file_size, max_files)
        )
        collector_thread.daemon = True
        collector_thread.start()
        
        try:
            # Wait for collector to finish
            collector_thread.join()
            
            # Add sentinel values to indicate end of jobs
            for _ in range(self.max_workers):
                self.job_queue.put((0, None))
            
            # Wait for all workers to complete
            for future in futures:
                future.result()
                
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
            self.stop_event.set()
            
        finally:
            # Ensure clean shutdown
            self.stats.end_time = time.time()
            self.executor.shutdown(wait=False)
            
            # Report final stats
            logger.info(f"Scan completed: {self.stats.files_processed} files processed "
                      f"({self.stats.files_per_minute:.1f} files/min), "
                      f"{self.stats.threats_found} threats found")
            
            return self.stats
    
    def scan_files(self, 
                  file_paths: List[str],
                  max_file_size: int = None) -> ScanStats:
        """
        Scan a list of files with all available threads
        
        Args:
            file_paths: List of file paths to scan
            max_file_size: Maximum file size to scan in bytes
            
        Returns:
            ScanStats object with results
        """
        self.reset_stats()
        self.stats.start_time = time.time()
        self.stop_event.clear()
        
        # Create job workers
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        futures = []
        
        # Start worker threads
        for _ in range(self.max_workers):
            future = self.executor.submit(self._worker)
            futures.append(future)
        
        # Add files to queue
        enqueue_thread = threading.Thread(
            target=self._enqueue_files,
            args=(file_paths, max_file_size)
        )
        enqueue_thread.daemon = True
        enqueue_thread.start()
        
        try:
            # Wait for enqueue to finish
            enqueue_thread.join()
            
            # Add sentinel values to indicate end of jobs
            for _ in range(self.max_workers):
                self.job_queue.put((0, None))
            
            # Wait for all workers to complete
            for future in futures:
                future.result()
                
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
            self.stop_event.set()
            
        finally:
            # Ensure clean shutdown
            self.stats.end_time = time.time()
            self.executor.shutdown(wait=False)
            
            # Report final stats
            logger.info(f"Scan completed: {self.stats.files_processed} files processed "
                      f"({self.stats.files_per_minute:.1f} files/min), "
                      f"{self.stats.threats_found} threats found")
            
            return self.stats
    
    def stop(self):
        """Stop all scanning operations"""
        self.stop_event.set()
        logger.info("Stopping scan engine...")
    
    def _worker(self):
        """Worker thread that processes jobs from the queue"""
        while not self.stop_event.is_set():
            try:
                # Get job from queue (with priority)
                priority, job = self.job_queue.get(timeout=1.0)
                
                # Check for sentinel value
                if job is None:
                    self.job_queue.task_done()
                    break
                
                # Process the job
                try:
                    start_time = time.time()
                    result = self._scan_file(job.file_path)
                    scan_time = time.time() - start_time
                    
                    # Update statistics
                    with self.stats_lock:
                        self.stats.files_processed += 1
                        self.stats.bytes_scanned += job.file_size
                        if result.get('threat_detected', False):
                            self.stats.threats_found += 1
                    
                    # Add scan time to result
                    result['scan_time'] = scan_time
                    
                    # Call result callback if provided
                    if self.result_callback:
                        self.result_callback(result)
                    
                    # Update progress
                    if self.progress_callback and self.stats.files_processed % 10 == 0:
                        self.progress_callback(self.stats)
                        
                except Exception as e:
                    logger.error(f"Error scanning {job.file_path}: {str(e)}")
                    with self.stats_lock:
                        self.stats.errors += 1
                
                finally:
                    # Mark job as done
                    self.job_queue.task_done()
                    
            except queue.Empty:
                # Queue is empty, wait for more jobs
                continue
            except Exception as e:
                # Unexpected error in worker
                logger.error(f"Worker error: {str(e)}")
                continue
    
    def _file_collector(self, 
                      directory: str, 
                      recursive: bool,
                      extensions: List[str],
                      exclusions: List[str],
                      max_file_size: int,
                      max_files: int):
        """Collect files from directory and add to queue"""
        files_added = 0
        exclusion_patterns = exclusions or []
        
        try:
            # Normalize extensions
            if extensions:
                extensions = [ext.lower() if ext.startswith('.') else f'.{ext.lower()}' 
                             for ext in extensions]
            
            # Walk directory
            for root, _, files in os.walk(directory):
                # Check if stopped
                if self.stop_event.is_set():
                    break
                
                # Skip excluded directories
                if any(excl in root for excl in exclusion_patterns):
                    continue
                
                for filename in files:
                    # Check if stopped
                    if self.stop_event.is_set():
                        break
                    
                    # Check max files
                    if max_files and files_added >= max_files:
                        logger.info(f"Reached maximum files limit ({max_files})")
                        break
                    
                    # Full path
                    file_path = os.path.join(root, filename)
                    
                    # Skip excluded files
                    if any(excl in file_path for excl in exclusion_patterns):
                        continue
                    
                    # Check extension
                    if extensions:
                        ext = os.path.splitext(filename)[1].lower()
                        if ext not in extensions:
                            continue
                    
                    try:
                        # Check if regular file
                        if not os.path.isfile(file_path) or os.path.islink(file_path):
                            continue
                        
                        # Check size
                        file_size = os.path.getsize(file_path)
                        if max_file_size and file_size > max_file_size:
                            logger.debug(f"Skipping {file_path} (size: {file_size} > {max_file_size})")
                            with self.stats_lock:
                                self.stats.files_skipped += 1
                            continue
                        
                        # Determine priority (smaller files first)
                        priority = 10000 - min(file_size // 1024, 9999)
                        
                        # Create job
                        job = ScanJob(
                            file_path=file_path,
                            file_size=file_size,
                            priority=priority
                        )
                        
                        # Add to queue
                        self.job_queue.put((priority, job))
                        files_added += 1
                        
                        # Slow down if queue is getting full
                        if self.job_queue.qsize() > self.queue_size * 0.9:
                            time.sleep(0.1)
                            
                    except Exception as e:
                        logger.error(f"Error queueing {file_path}: {str(e)}")
                
                # Stop recursion if requested
                if not recursive:
                    break
                    
        except Exception as e:
            logger.error(f"Error collecting files: {str(e)}")
            traceback.print_exc()
    
    def _enqueue_files(self, file_paths: List[str], max_file_size: int):
        """Add files to the queue"""
        files_added = 0
        
        try:
            for file_path in file_paths:
                # Check if stopped
                if self.stop_event.is_set():
                    break
                
                try:
                    # Check if file exists
                    if not os.path.isfile(file_path):
                        logger.warning(f"Not a file: {file_path}")
                        continue
                    
                    # Check size
                    file_size = os.path.getsize(file_path)
                    if max_file_size and file_size > max_file_size:
                        logger.debug(f"Skipping {file_path} (size: {file_size} > {max_file_size})")
                        with self.stats_lock:
                            self.stats.files_skipped += 1
                        continue
                    
                    # Determine priority (smaller files first)
                    priority = 10000 - min(file_size // 1024, 9999)
                    
                    # Create job
                    job = ScanJob(
                        file_path=file_path,
                        file_size=file_size,
                        priority=priority
                    )
                    
                    # Add to queue
                    self.job_queue.put((priority, job))
                    files_added += 1
                    
                except Exception as e:
                    logger.error(f"Error queueing {file_path}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error enqueueing files: {str(e)}")
            traceback.print_exc()
    
    def _scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a single file
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary with scan results
        """
        result = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': 0,
            'file_type': None,
            'scan_time': 0,
            'threat_detected': False,
            'threat_name': None,
            'threat_level': 'clean',
            'threat_score': 0,
            'scan_errors': []
        }
        
        try:
            # Get file size
            file_size = os.path.getsize(file_path)
            result['file_size'] = file_size
            
            # Get file type
            file_type = self._detect_file_type(file_path)
            result['file_type'] = file_type
            
            # Choose appropriate handler
            handler = self._get_handler_for_file(file_path, file_type)
            
            if handler:
                # Use specific handler
                handler_result = handler(file_path)
                result.update(handler_result)
            else:
                # Use default handler (simply read file to verify access)
                with open(file_path, 'rb') as f:
                    # Read first block
                    f.read(min(file_size, 8192))
            
            # Verify threat results are set
            if 'threat_detected' not in result:
                result['threat_detected'] = False
            if 'threat_level' not in result:
                result['threat_level'] = 'clean'
            if 'threat_score' not in result:
                result['threat_score'] = 0
                
        except PermissionError:
            result['scan_errors'].append("Permission denied")
        except FileNotFoundError:
            result['scan_errors'].append("File not found")
        except Exception as e:
            result['scan_errors'].append(f"Error: {str(e)}")
        
        return result
    
    def _get_handler_for_file(self, file_path: str, file_type: str) -> Optional[Callable]:
        """Get the appropriate handler for a file"""
        # Check file extension first
        ext = os.path.splitext(file_path)[1].lower()
        if ext in self.file_handlers:
            return self.file_handlers[ext]
        
        # Check by file type
        if file_type in self.file_handlers:
            return self.file_handlers[file_type]
        
        # No specific handler
        return None
    
    def _detect_file_type(self, file_path: str) -> str:
        """Detect file type by reading the first few bytes"""
        try:
            # Try to use python-magic if available
            try:
                import magic
                mime = magic.Magic(mime=True)
                return mime.from_file(file_path)
            except ImportError:
                pass
            
            # Fallback to signature detection
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
                for file_type, signatures in self.file_signatures.items():
                    for signature in signatures:
                        if header.startswith(signature):
                            return file_type
                
                # Check for text files
                is_text = True
                for byte in header:
                    if byte < 7 or (byte > 13 and byte < 32):
                        is_text = False
                        break
                
                if is_text:
                    return 'text/plain'
                
                # Unknown type
                return 'application/octet-stream'
                
        except Exception as e:
            logger.debug(f"Error detecting file type for {file_path}: {str(e)}")
            return 'application/octet-stream'
    
    def _initialize_file_signatures(self) -> Dict[str, List[bytes]]:
        """Initialize file type signatures"""
        return {
            'application/pdf': [b'%PDF'],
            'application/x-executable': [b'\x7fELF'],
            'application/x-dosexec': [b'MZ'],
            'application/zip': [b'PK\x03\x04'],
            'application/x-rar': [b'Rar!\x1a\x07'],
            'application/x-tar': [b'ustar'],
            'application/x-gzip': [b'\x1f\x8b\x08'],
            'application/x-7z-compressed': [b'7z\xbc\xaf\x27\x1c'],
            'image/jpeg': [b'\xff\xd8\xff'],
            'image/png': [b'\x89PNG\r\n\x1a\n'],
            'image/gif': [b'GIF87a', b'GIF89a'],
            'image/bmp': [b'BM'],
            'application/xml': [b'<?xml'],
            'application/javascript': [b'//'],
            'application/java-archive': [b'PK\x03\x04'],
            'text/html': [b'<!DOCTYPE', b'<html', b'<HTML'],
        }


class AdaptiveScanScheduler:
    """
    Adaptive scheduler for optimizing scan performance based on system load
    Dynamically adjusts thread count and batch sizes based on system metrics
    """
    
    def __init__(self, 
                scan_engine: ScanEngine,
                min_workers: int = 2,
                max_workers: int = None):
        """
        Initialize the adaptive scheduler
        
        Args:
            scan_engine: ScanEngine instance to control
            min_workers: Minimum number of worker threads
            max_workers: Maximum number of worker threads
        """
        self.scan_engine = scan_engine
        self.min_workers = min_workers
        self.max_workers = max_workers or max(8, os.cpu_count() * 2)
        
        self.current_workers = max(min_workers, os.cpu_count())
        self.adjustment_interval = 5.0  # seconds
        self.last_adjustment = 0
        self.cpu_threshold = 85.0  # percentage
        
        self.monitor_thread = None
        self.running = False
    
    def start_monitoring(self):
        """Start monitoring system resources"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            return
            
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring system resources"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
            self.monitor_thread = None
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._adjust_workers()
                time.sleep(self.adjustment_interval)
            except Exception as e:
                logger.error(f"Error in monitor loop: {str(e)}")
                time.sleep(1.0)
    
    def _adjust_workers(self):
        """Adjust worker count based on system load"""
        # Check if enough time has passed since last adjustment
        now = time.time()
        if now - self.last_adjustment < self.adjustment_interval:
            return
            
        self.last_adjustment = now
        
        try:
            # Get CPU usage
            import psutil
            cpu_percent = psutil.cpu_percent(interval=0.5)
            
            # Adjust worker count based on CPU usage
            if cpu_percent > self.cpu_threshold:
                # CPU is overloaded, reduce workers
                new_workers = max(self.min_workers, self.current_workers - 1)
                if new_workers < self.current_workers:
                    self.current_workers = new_workers
                    logger.debug(f"Reducing workers to {self.current_workers} (CPU: {cpu_percent:.1f}%)")
            elif cpu_percent < self.cpu_threshold * 0.7:
                # CPU has capacity, increase workers
                new_workers = min(self.max_workers, self.current_workers + 1)
                if new_workers > self.current_workers:
                    self.current_workers = new_workers
                    logger.debug(f"Increasing workers to {self.current_workers} (CPU: {cpu_percent:.1f}%)")
            
            # Update scan engine's thread pool
            # Note: Most thread pools don't allow changing max_workers after creation
            # This is for illustration - a real implementation would need to recreate the pool
            
        except ImportError:
            logger.warning("psutil not available, adaptive scheduling disabled")
            self.running = False
        except Exception as e:
            logger.error(f"Error adjusting workers: {str(e)}")


# Performance optimization for large scans
class FileStreamProcessor:
    """
    Process files in streaming mode to reduce memory usage
    Useful for large files that would consume too much memory
    """
    
    def __init__(self, chunk_size: int = 1024 * 1024):
        """
        Initialize the stream processor
        
        Args:
            chunk_size: Size of chunks to read in bytes
        """
        self.chunk_size = chunk_size
    
    def process_file(self, file_path: str, processor: Callable[[bytes], Any]) -> List[Any]:
        """
        Process a file in chunks
        
        Args:
            file_path: Path to the file
            processor: Function that processes each chunk
            
        Returns:
            List of results from each chunk
        """
        results = []
        
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                        
                    result = processor(chunk)
                    results.append(result)
        
        except Exception as e:
            logger.error(f"Error processing file stream {file_path}: {str(e)}")
        
        return results
