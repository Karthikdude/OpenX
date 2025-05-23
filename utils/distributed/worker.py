#!/usr/bin/env python3
"""
Distributed Scanning Worker for OpenX
Implements worker node functionality for distributed scanning
"""

import os
import json
import time
import uuid
import logging
import asyncio
import aiohttp
import socket
import threading
import platform
import psutil
from typing import Dict, List, Set, Tuple, Any, Optional
import sys
import traceback

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from core.scanner import Scanner

logger = logging.getLogger('openx.distributed.worker')

class Worker:
    """
    Distributed scanning worker that connects to a coordinator
    and performs scanning tasks
    
    Implements:
    - Registration with coordinator
    - Heartbeat mechanism
    - Task execution
    - Result reporting
    - Resource monitoring
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the worker
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # Worker settings
        self.name = self.config.get('worker', {}).get('name', f"worker-{socket.gethostname()}")
        self.host = self.config.get('worker', {}).get('host', self.get_local_ip())
        self.port = self.config.get('worker', {}).get('port', 0)  # 0 means no local server
        
        # Coordinator settings
        self.coordinator_url = self.config.get('distributed', {}).get('coordinator_url', 'http://localhost:8080')
        self.heartbeat_interval = self.config.get('distributed', {}).get('heartbeat_interval', 30)
        
        # State
        self.worker_id = None
        self.status = "initializing"
        self.current_task = None
        self.scanner = None
        self.running = False
        
        # Threads
        self.heartbeat_thread = None
        self.monitor_thread = None
        
        # Stats
        self.stats = {
            "tasks_completed": 0,
            "urls_scanned": 0,
            "vulnerabilities_found": 0,
            "uptime": 0,
            "cpu_usage": 0,
            "memory_usage": 0
        }
        
        # Start time
        self.start_time = time.time()
    
    async def register(self):
        """Register with the coordinator"""
        if self.worker_id:
            logger.warning("Worker already registered")
            return
        
        try:
            # Get capabilities
            capabilities = self._get_capabilities()
            
            # Prepare registration data
            data = {
                "name": self.name,
                "host": self.host,
                "port": self.port,
                "capabilities": capabilities
            }
            
            # Send registration request
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.coordinator_url}/api/workers/register",
                    json=data
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        self.worker_id = result.get('worker_id')
                        self.status = "idle"
                        logger.info(f"Registered with coordinator as {self.name} (ID: {self.worker_id})")
                        return True
                    else:
                        error = await response.text()
                        logger.error(f"Registration failed: {error}")
                        return False
        
        except Exception as e:
            logger.error(f"Error registering with coordinator: {str(e)}")
            return False
    
    async def send_heartbeat(self):
        """Send heartbeat to coordinator"""
        if not self.worker_id:
            logger.warning("Worker not registered, cannot send heartbeat")
            return False
        
        try:
            # Update stats
            self._update_stats()
            
            # Prepare heartbeat data
            data = {
                "status": self.status,
                "stats": self.stats
            }
            
            # Send heartbeat request
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.coordinator_url}/api/workers/{self.worker_id}/heartbeat",
                    json=data
                ) as response:
                    if response.status == 200:
                        logger.debug(f"Sent heartbeat to coordinator")
                        return True
                    else:
                        error = await response.text()
                        logger.error(f"Heartbeat failed: {error}")
                        return False
        
        except Exception as e:
            logger.error(f"Error sending heartbeat: {str(e)}")
            return False
    
    async def get_next_task(self):
        """Get next task from coordinator"""
        if not self.worker_id:
            logger.warning("Worker not registered, cannot get task")
            return None
        
        if self.status != "idle":
            logger.warning(f"Worker is not idle ({self.status}), cannot get task")
            return None
        
        try:
            # Send request for next task
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.coordinator_url}/api/workers/{self.worker_id}/next_task"
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        # Check if there are no tasks
                        if result.get('status') == 'no_tasks':
                            logger.debug("No tasks available")
                            return None
                        
                        # Get task details
                        task_id = result.get('task_id')
                        urls = result.get('urls', [])
                        config = result.get('config', {})
                        
                        logger.info(f"Received task {task_id} with {len(urls)} URLs")
                        
                        return {
                            "id": task_id,
                            "urls": urls,
                            "config": config
                        }
                    else:
                        error = await response.text()
                        logger.error(f"Getting next task failed: {error}")
                        return None
        
        except Exception as e:
            logger.error(f"Error getting next task: {str(e)}")
            return None
    
    async def update_task_progress(self, task_id: str, progress: float, results: List[Dict[str, Any]] = None):
        """
        Update task progress
        
        Args:
            task_id (str): Task ID
            progress (float): Progress (0.0 to 1.0)
            results (List[Dict[str, Any]], optional): Partial results
        """
        if not self.worker_id:
            logger.warning("Worker not registered, cannot update task")
            return False
        
        try:
            # Prepare update data
            data = {
                "progress": progress
            }
            
            if results:
                data["results"] = results
            
            # Send update request
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.coordinator_url}/api/tasks/{task_id}/update",
                    json=data
                ) as response:
                    if response.status == 200:
                        logger.debug(f"Updated task {task_id} progress: {progress:.2f}")
                        return True
                    else:
                        error = await response.text()
                        logger.error(f"Updating task progress failed: {error}")
                        return False
        
        except Exception as e:
            logger.error(f"Error updating task progress: {str(e)}")
            return False
    
    async def complete_task(self, task_id: str, status: str = "completed", results: List[Dict[str, Any]] = None, error: str = None):
        """
        Mark task as completed
        
        Args:
            task_id (str): Task ID
            status (str): Task status (completed, failed)
            results (List[Dict[str, Any]], optional): Final results
            error (str, optional): Error message if task failed
        """
        if not self.worker_id:
            logger.warning("Worker not registered, cannot complete task")
            return False
        
        try:
            # Prepare completion data
            data = {
                "status": status
            }
            
            if results:
                data["results"] = results
            
            if error:
                data["error"] = error
            
            # Send completion request
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.coordinator_url}/api/tasks/{task_id}/complete",
                    json=data
                ) as response:
                    if response.status == 200:
                        logger.info(f"Completed task {task_id} with status: {status}")
                        
                        # Update stats
                        self.stats["tasks_completed"] += 1
                        
                        # Reset state
                        self.current_task = None
                        self.status = "idle"
                        
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"Completing task failed: {error_text}")
                        return False
        
        except Exception as e:
            logger.error(f"Error completing task: {str(e)}")
            return False
    
    async def execute_task(self, task: Dict[str, Any]):
        """
        Execute a scanning task
        
        Args:
            task (Dict[str, Any]): Task details
        """
        task_id = task['id']
        urls = task['urls']
        config = task['config']
        
        # Update state
        self.current_task = task_id
        self.status = "busy"
        
        # Initialize scanner if not already done
        if not self.scanner:
            self.scanner = Scanner(config)
        
        # Track results
        results = []
        error = None
        
        try:
            # Process URLs in batches for progress updates
            batch_size = min(100, max(1, len(urls) // 10))
            
            for i in range(0, len(urls), batch_size):
                # Get batch of URLs
                batch = urls[i:i+batch_size]
                
                # Scan batch
                batch_results = await self.scanner.scan_urls(batch)
                
                # Add to results
                results.extend(batch_results)
                
                # Update progress
                progress = min(1.0, (i + len(batch)) / len(urls))
                await self.update_task_progress(task_id, progress, batch_results)
                
                # Update stats
                self.stats["urls_scanned"] += len(batch)
                self.stats["vulnerabilities_found"] += len([r for r in batch_results if r.get('vulnerable', False)])
            
            # Complete task
            await self.complete_task(task_id, "completed", results)
        
        except Exception as e:
            logger.error(f"Error executing task {task_id}: {str(e)}")
            error = f"{str(e)}\n{traceback.format_exc()}"
            
            # Complete task with error
            await self.complete_task(task_id, "failed", results, error)
    
    def _heartbeat_loop(self):
        """Background thread for sending heartbeats"""
        while self.running:
            # Create event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Send heartbeat
                loop.run_until_complete(self.send_heartbeat())
            
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {str(e)}")
            
            finally:
                loop.close()
            
            # Sleep until next heartbeat
            time.sleep(self.heartbeat_interval)
    
    def _task_loop(self):
        """Background thread for executing tasks"""
        # Create event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        while self.running:
            try:
                # Check if we're idle
                if self.status == "idle":
                    # Get next task
                    task = loop.run_until_complete(self.get_next_task())
                    
                    if task:
                        # Execute task
                        loop.run_until_complete(self.execute_task(task))
                
                # Sleep briefly to avoid busy waiting
                time.sleep(1)
            
            except Exception as e:
                logger.error(f"Error in task loop: {str(e)}")
                time.sleep(5)  # Sleep longer after an error
    
    def _monitor_loop(self):
        """Background thread for monitoring system resources"""
        while self.running:
            try:
                # Update stats
                self._update_stats()
                
                # Sleep until next update
                time.sleep(10)
            
            except Exception as e:
                logger.error(f"Error in monitor loop: {str(e)}")
                time.sleep(30)  # Sleep longer after an error
    
    def _update_stats(self):
        """Update worker stats"""
        # Update uptime
        self.stats["uptime"] = int(time.time() - self.start_time)
        
        # Update CPU usage
        self.stats["cpu_usage"] = psutil.cpu_percent()
        
        # Update memory usage
        memory = psutil.virtual_memory()
        self.stats["memory_usage"] = memory.percent
    
    def _get_capabilities(self) -> Dict[str, Any]:
        """
        Get worker capabilities
        
        Returns:
            Dict[str, Any]: Worker capabilities
        """
        return {
            "system": {
                "platform": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total
            },
            "features": {
                "browser_emulation": self.config.get('scanner', {}).get('browser_emulation', False),
                "waf_bypass": self.config.get('scanner', {}).get('waf_bypass', False),
                "enhanced_detection": self.config.get('scanner', {}).get('enhanced_detection', True)
            },
            "version": self.config.get('version', '1.0.0')
        }
    
    async def start(self):
        """Start the worker"""
        if self.running:
            logger.warning("Worker already running")
            return
        
        logger.info(f"Starting worker {self.name}")
        
        # Set running flag
        self.running = True
        self.start_time = time.time()
        
        # Register with coordinator
        registered = await self.register()
        
        if not registered:
            logger.error("Failed to register with coordinator")
            self.running = False
            return False
        
        # Start heartbeat thread
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
        self.heartbeat_thread.daemon = True
        self.heartbeat_thread.start()
        
        # Start monitor thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Start task thread
        self.task_thread = threading.Thread(target=self._task_loop)
        self.task_thread.daemon = True
        self.task_thread.start()
        
        logger.info(f"Worker started and registered with ID: {self.worker_id}")
        return True
    
    async def stop(self):
        """Stop the worker"""
        if not self.running:
            return
        
        logger.info("Stopping worker")
        
        # Set running flag
        self.running = False
        
        # Wait for threads to stop
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=5)
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        if self.task_thread:
            self.task_thread.join(timeout=5)
        
        logger.info("Worker stopped")
    
    @staticmethod
    def get_local_ip():
        """Get local IP address"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't have to be reachable
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

# Run worker if executed directly
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='OpenX Distributed Scanning Worker')
    parser.add_argument('--name', help='Worker name')
    parser.add_argument('--coordinator', help='Coordinator URL')
    parser.add_argument('--config', help='Path to configuration file')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Override config with command line arguments
    if args.name:
        if 'worker' not in config:
            config['worker'] = {}
        config['worker']['name'] = args.name
    
    if args.coordinator:
        if 'distributed' not in config:
            config['distributed'] = {}
        config['distributed']['coordinator_url'] = args.coordinator
    
    # Create and run worker
    worker = Worker(config)
    
    # Run event loop
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(worker.start())
        
        # Keep running until interrupted
        loop.run_forever()
    
    except KeyboardInterrupt:
        pass
    
    finally:
        # Stop worker
        loop.run_until_complete(worker.stop())
        loop.close()
