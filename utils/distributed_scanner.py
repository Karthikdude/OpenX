#!/usr/bin/env python3
"""
Distributed Scanner Module for OpenX
Implements distributed scanning capability across multiple machines
"""

import os
import sys
import json
import logging
import asyncio
import uuid
import time
import socket
import pickle
from typing import Dict, List, Set, Tuple, Any, Optional
from pathlib import Path
import aiohttp
from aiohttp import web

logger = logging.getLogger('openx.distributed_scanner')

class DistributedScanner:
    """
    Manages distributed scanning across multiple machines
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the distributed scanner
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # Distributed scanning settings
        self.distributed_enabled = self.config.get('distributed', {}).get('enabled', False)
        self.is_master = self.config.get('distributed', {}).get('is_master', True)
        self.master_host = self.config.get('distributed', {}).get('master_host', '127.0.0.1')
        self.master_port = self.config.get('distributed', {}).get('master_port', 8080)
        self.worker_port = self.config.get('distributed', {}).get('worker_port', 8081)
        self.worker_id = self.config.get('distributed', {}).get('worker_id', str(uuid.uuid4()))
        
        # Task management
        self.tasks = {}
        self.results = {}
        self.workers = {}
        self.task_queue = asyncio.Queue()
        
        # State tracking
        self.running = False
        self.app = None
        self.runner = None
        self.site = None
    
    async def start_master(self):
        """
        Start the master server for distributed scanning
        """
        if not self.distributed_enabled:
            logger.warning("Distributed scanning is not enabled")
            return False
        
        if not self.is_master:
            logger.warning("This instance is not configured as a master")
            return False
        
        # Create web application
        self.app = web.Application()
        self.app.add_routes([
            web.post('/register', self.handle_register),
            web.post('/results', self.handle_results),
            web.get('/tasks', self.handle_tasks),
            web.get('/status', self.handle_status)
        ])
        
        # Start server
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.master_host, self.master_port)
        await self.site.start()
        
        self.running = True
        logger.info(f"Master server started on {self.master_host}:{self.master_port}")
        
        # Start task distributor
        asyncio.create_task(self.task_distributor())
        
        return True
    
    async def start_worker(self):
        """
        Start the worker for distributed scanning
        """
        if not self.distributed_enabled:
            logger.warning("Distributed scanning is not enabled")
            return False
        
        if self.is_master:
            logger.warning("This instance is configured as a master, not a worker")
            return False
        
        # Create web application for worker
        self.app = web.Application()
        self.app.add_routes([
            web.post('/task', self.handle_task),
            web.get('/status', self.handle_worker_status)
        ])
        
        # Start server
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '0.0.0.0', self.worker_port)
        await self.site.start()
        
        self.running = True
        logger.info(f"Worker server started on port {self.worker_port}")
        
        # Register with master
        await self.register_with_master()
        
        # Start task processor
        asyncio.create_task(self.task_processor())
        
        return True
    
    async def stop(self):
        """
        Stop the distributed scanner
        """
        if self.running:
            if self.site:
                await self.site.stop()
            if self.runner:
                await self.runner.cleanup()
            self.running = False
            logger.info("Distributed scanner stopped")
    
    async def register_with_master(self):
        """
        Register this worker with the master server
        """
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            
            worker_info = {
                'worker_id': self.worker_id,
                'hostname': hostname,
                'ip': ip,
                'port': self.worker_port,
                'capabilities': {
                    'browser': True,
                    'max_concurrency': self.config.get('concurrency', 100)
                }
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://{self.master_host}:{self.master_port}/register",
                    json=worker_info
                ) as response:
                    if response.status == 200:
                        logger.info(f"Successfully registered with master at {self.master_host}:{self.master_port}")
                        return True
                    else:
                        logger.error(f"Failed to register with master: {await response.text()}")
                        return False
        except Exception as e:
            logger.error(f"Error registering with master: {e}")
            return False
    
    async def add_urls_to_scan(self, urls: List[str]):
        """
        Add URLs to the distributed scanning queue
        
        Args:
            urls (List[str]): List of URLs to scan
        """
        if not self.distributed_enabled or not self.is_master:
            logger.warning("Cannot add URLs - not running as a master")
            return
        
        # Create tasks from URLs
        for url in urls:
            task_id = str(uuid.uuid4())
            task = {
                'task_id': task_id,
                'url': url,
                'status': 'pending',
                'created_at': time.time()
            }
            self.tasks[task_id] = task
            await self.task_queue.put(task)
        
        logger.info(f"Added {len(urls)} URLs to distributed scanning queue")
    
    async def task_distributor(self):
        """
        Distribute tasks to available workers
        """
        while self.running:
            try:
                # Wait for tasks
                if self.task_queue.empty():
                    await asyncio.sleep(1)
                    continue
                
                # Get a task
                task = await self.task_queue.get()
                
                # Find an available worker
                if not self.workers:
                    logger.debug("No workers available, waiting...")
                    await asyncio.sleep(5)
                    await self.task_queue.put(task)
                    continue
                
                # Simple round-robin worker selection
                worker_id = list(self.workers.keys())[0]
                worker = self.workers[worker_id]
                
                # Send task to worker
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            f"http://{worker['ip']}:{worker['port']}/task",
                            json=task
                        ) as response:
                            if response.status == 200:
                                logger.debug(f"Task {task['task_id']} sent to worker {worker_id}")
                                self.tasks[task['task_id']]['status'] = 'assigned'
                                self.tasks[task['task_id']]['worker_id'] = worker_id
                                self.tasks[task['task_id']]['assigned_at'] = time.time()
                            else:
                                logger.error(f"Failed to send task to worker: {await response.text()}")
                                await self.task_queue.put(task)
                except Exception as e:
                    logger.error(f"Error sending task to worker: {e}")
                    await self.task_queue.put(task)
                    
                    # Remove worker if it's unreachable
                    logger.warning(f"Removing unreachable worker {worker_id}")
                    self.workers.pop(worker_id, None)
                
                # Rotate workers list (simple round-robin)
                if self.workers:
                    worker_id = list(self.workers.keys())[0]
                    worker = self.workers.pop(worker_id)
                    self.workers[worker_id] = worker
            
            except Exception as e:
                logger.error(f"Error in task distributor: {e}")
                await asyncio.sleep(1)
    
    async def task_processor(self):
        """
        Process tasks received from the master (worker mode)
        """
        while self.running:
            try:
                # Check for new tasks from master
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"http://{self.master_host}:{self.master_port}/tasks",
                        params={'worker_id': self.worker_id}
                    ) as response:
                        if response.status == 200:
                            tasks = await response.json()
                            for task in tasks:
                                # Process the task
                                result = await self.process_task(task)
                                
                                # Send result back to master
                                async with session.post(
                                    f"http://{self.master_host}:{self.master_port}/results",
                                    json=result
                                ) as result_response:
                                    if result_response.status != 200:
                                        logger.error(f"Failed to send result to master: {await result_response.text()}")
            except Exception as e:
                logger.error(f"Error in task processor: {e}")
            
            await asyncio.sleep(5)
    
    async def process_task(self, task):
        """
        Process a scanning task
        
        Args:
            task (Dict[str, Any]): Task to process
            
        Returns:
            Dict[str, Any]: Task result
        """
        # This would normally call the scanner to process the URL
        # For now, we'll just simulate processing
        logger.info(f"Processing task {task['task_id']} for URL {task['url']}")
        
        # Simulate processing time
        await asyncio.sleep(2)
        
        # Create result
        result = {
            'task_id': task['task_id'],
            'url': task['url'],
            'status': 'completed',
            'worker_id': self.worker_id,
            'completed_at': time.time(),
            'result': {
                'is_vulnerable': False,
                'details': 'Simulated scan result'
            }
        }
        
        return result
    
    # API Handlers for master
    
    async def handle_register(self, request):
        """Handle worker registration"""
        try:
            worker_info = await request.json()
            worker_id = worker_info.get('worker_id')
            
            if not worker_id:
                return web.Response(status=400, text="Missing worker_id")
            
            self.workers[worker_id] = worker_info
            logger.info(f"Worker {worker_id} registered from {worker_info.get('ip')}:{worker_info.get('port')}")
            
            return web.Response(status=200, text="Registered")
        except Exception as e:
            logger.error(f"Error handling registration: {e}")
            return web.Response(status=500, text=str(e))
    
    async def handle_results(self, request):
        """Handle task results from workers"""
        try:
            result = await request.json()
            task_id = result.get('task_id')
            
            if not task_id:
                return web.Response(status=400, text="Missing task_id")
            
            if task_id in self.tasks:
                self.tasks[task_id]['status'] = 'completed'
                self.tasks[task_id]['completed_at'] = time.time()
                self.results[task_id] = result
                logger.info(f"Received result for task {task_id}")
            else:
                logger.warning(f"Received result for unknown task {task_id}")
            
            return web.Response(status=200, text="Result received")
        except Exception as e:
            logger.error(f"Error handling results: {e}")
            return web.Response(status=500, text=str(e))
    
    async def handle_tasks(self, request):
        """Handle task requests from workers"""
        try:
            worker_id = request.query.get('worker_id')
            
            if not worker_id or worker_id not in self.workers:
                return web.Response(status=400, text="Invalid worker_id")
            
            # Find pending tasks
            pending_tasks = []
            for task_id, task in self.tasks.items():
                if task['status'] == 'pending':
                    pending_tasks.append(task)
                    if len(pending_tasks) >= 10:  # Limit batch size
                        break
            
            return web.json_response(pending_tasks)
        except Exception as e:
            logger.error(f"Error handling task request: {e}")
            return web.Response(status=500, text=str(e))
    
    async def handle_status(self, request):
        """Handle status requests"""
        try:
            status = {
                'tasks': {
                    'total': len(self.tasks),
                    'pending': sum(1 for t in self.tasks.values() if t['status'] == 'pending'),
                    'assigned': sum(1 for t in self.tasks.values() if t['status'] == 'assigned'),
                    'completed': sum(1 for t in self.tasks.values() if t['status'] == 'completed')
                },
                'workers': len(self.workers),
                'results': len(self.results)
            }
            
            return web.json_response(status)
        except Exception as e:
            logger.error(f"Error handling status request: {e}")
            return web.Response(status=500, text=str(e))
    
    # API Handlers for worker
    
    async def handle_task(self, request):
        """Handle incoming task from master"""
        try:
            task = await request.json()
            task_id = task.get('task_id')
            
            if not task_id:
                return web.Response(status=400, text="Missing task_id")
            
            # Queue task for processing
            asyncio.create_task(self.process_task(task))
            
            return web.Response(status=200, text="Task accepted")
        except Exception as e:
            logger.error(f"Error handling task: {e}")
            return web.Response(status=500, text=str(e))
    
    async def handle_worker_status(self, request):
        """Handle status requests to worker"""
        try:
            status = {
                'worker_id': self.worker_id,
                'hostname': socket.gethostname(),
                'uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0,
                'tasks_processed': self.tasks_processed if hasattr(self, 'tasks_processed') else 0
            }
            
            return web.json_response(status)
        except Exception as e:
            logger.error(f"Error handling worker status request: {e}")
            return web.Response(status=500, text=str(e))
    
    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get all scan results
        
        Returns:
            List[Dict[str, Any]]: List of scan results
        """
        return list(self.results.values())
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of distributed scanning
        
        Returns:
            Dict[str, Any]: Status information
        """
        return {
            'is_master': self.is_master,
            'running': self.running,
            'workers': len(self.workers),
            'tasks': {
                'total': len(self.tasks),
                'pending': sum(1 for t in self.tasks.values() if t['status'] == 'pending'),
                'assigned': sum(1 for t in self.tasks.values() if t['status'] == 'assigned'),
                'completed': sum(1 for t in self.tasks.values() if t['status'] == 'completed')
            },
            'results': len(self.results)
        }
