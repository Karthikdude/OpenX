#!/usr/bin/env python3
"""
Distributed Scanning Coordinator for OpenX
Implements master/worker architecture for distributed scanning
"""

import os
import json
import time
import uuid
import logging
import asyncio
import aiohttp
from aiohttp import web
import socket
import threading
import queue
from typing import Dict, List, Set, Tuple, Any, Optional, Union
from dataclasses import dataclass, asdict, field

logger = logging.getLogger('openx.distributed.coordinator')

@dataclass
class Worker:
    """Worker node information"""
    id: str
    name: str
    host: str
    port: int
    status: str = "idle"  # idle, busy, offline
    capabilities: Dict[str, Any] = field(default_factory=dict)
    last_heartbeat: float = field(default_factory=time.time)
    current_task: Optional[str] = None
    stats: Dict[str, Any] = field(default_factory=lambda: {
        "tasks_completed": 0,
        "urls_scanned": 0,
        "vulnerabilities_found": 0,
        "uptime": 0,
        "cpu_usage": 0,
        "memory_usage": 0
    })

@dataclass
class Task:
    """Scan task information"""
    id: str
    urls: List[str]
    config: Dict[str, Any]
    status: str = "pending"  # pending, running, completed, failed
    worker_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    results: List[Dict[str, Any]] = field(default_factory=list)
    progress: float = 0.0
    error: Optional[str] = None

class Coordinator:
    """
    Distributed scanning coordinator that manages workers and distributes tasks
    
    Implements:
    - Master/worker architecture
    - Task distribution and load balancing
    - Worker registration and heartbeat monitoring
    - Result aggregation
    - Fault tolerance
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the coordinator
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # Coordinator settings
        self.host = self.config.get('distributed', {}).get('host', '0.0.0.0')
        self.port = self.config.get('distributed', {}).get('port', 8080)
        self.heartbeat_interval = self.config.get('distributed', {}).get('heartbeat_interval', 30)
        self.worker_timeout = self.config.get('distributed', {}).get('worker_timeout', 60)
        self.task_chunk_size = self.config.get('distributed', {}).get('task_chunk_size', 100)
        self.auto_retry = self.config.get('distributed', {}).get('auto_retry', True)
        
        # State
        self.workers: Dict[str, Worker] = {}
        self.tasks: Dict[str, Task] = {}
        self.task_queue: queue.Queue = queue.Queue()
        self.results: Dict[str, List[Dict[str, Any]]] = {}
        
        # Web server
        self.app = web.Application()
        self.setup_routes()
        
        # Background tasks
        self.running = False
        self.monitor_thread = None
    
    def setup_routes(self):
        """Set up API routes"""
        self.app.add_routes([
            # Worker management
            web.post('/api/workers/register', self.register_worker),
            web.post('/api/workers/{worker_id}/heartbeat', self.worker_heartbeat),
            web.get('/api/workers', self.list_workers),
            web.get('/api/workers/{worker_id}', self.get_worker),
            
            # Task management
            web.post('/api/tasks', self.create_task),
            web.get('/api/tasks', self.list_tasks),
            web.get('/api/tasks/{task_id}', self.get_task),
            web.post('/api/tasks/{task_id}/cancel', self.cancel_task),
            
            # Task execution
            web.get('/api/workers/{worker_id}/next_task', self.get_next_task),
            web.post('/api/tasks/{task_id}/update', self.update_task),
            web.post('/api/tasks/{task_id}/complete', self.complete_task),
            
            # Status and metrics
            web.get('/api/status', self.get_status),
            web.get('/api/metrics', self.get_metrics)
        ])
    
    async def start(self):
        """Start the coordinator server"""
        if self.running:
            return
        
        self.running = True
        
        # Start worker monitor thread
        self.monitor_thread = threading.Thread(target=self._monitor_workers)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Start web server
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        
        logger.info(f"Coordinator started on http://{self.host}:{self.port}")
    
    async def stop(self):
        """Stop the coordinator server"""
        if not self.running:
            return
        
        self.running = False
        
        # Wait for monitor thread to stop
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("Coordinator stopped")
    
    def _monitor_workers(self):
        """Monitor worker heartbeats and handle timeouts"""
        while self.running:
            current_time = time.time()
            
            # Check for timed-out workers
            for worker_id, worker in list(self.workers.items()):
                if current_time - worker.last_heartbeat > self.worker_timeout:
                    logger.warning(f"Worker {worker_id} timed out")
                    
                    # Mark worker as offline
                    worker.status = "offline"
                    
                    # Reassign worker's task if any
                    if worker.current_task and worker.current_task in self.tasks:
                        task = self.tasks[worker.current_task]
                        logger.info(f"Reassigning task {task.id} from offline worker {worker_id}")
                        
                        # Reset task status
                        task.status = "pending"
                        task.worker_id = None
                        
                        # Add back to queue
                        self.task_queue.put(task.id)
            
            # Sleep for a short interval
            time.sleep(5)
    
    async def register_worker(self, request):
        """
        Register a new worker
        
        POST /api/workers/register
        """
        try:
            data = await request.json()
            
            # Validate required fields
            required_fields = ['name', 'host', 'port', 'capabilities']
            for field in required_fields:
                if field not in data:
                    return web.json_response(
                        {"error": f"Missing required field: {field}"}, 
                        status=400
                    )
            
            # Generate worker ID
            worker_id = str(uuid.uuid4())
            
            # Create worker
            worker = Worker(
                id=worker_id,
                name=data['name'],
                host=data['host'],
                port=data['port'],
                capabilities=data['capabilities'],
                status="idle"
            )
            
            # Add to workers
            self.workers[worker_id] = worker
            
            logger.info(f"Registered new worker: {worker.name} ({worker_id})")
            
            return web.json_response({
                "worker_id": worker_id,
                "status": "registered"
            })
        
        except Exception as e:
            logger.error(f"Error registering worker: {str(e)}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def worker_heartbeat(self, request):
        """
        Update worker heartbeat
        
        POST /api/workers/{worker_id}/heartbeat
        """
        worker_id = request.match_info['worker_id']
        
        # Check if worker exists
        if worker_id not in self.workers:
            return web.json_response(
                {"error": f"Worker not found: {worker_id}"}, 
                status=404
            )
        
        try:
            data = await request.json()
            worker = self.workers[worker_id]
            
            # Update heartbeat timestamp
            worker.last_heartbeat = time.time()
            
            # Update worker status and stats
            if 'status' in data:
                worker.status = data['status']
            
            if 'stats' in data:
                worker.stats.update(data['stats'])
            
            return web.json_response({"status": "ok"})
        
        except Exception as e:
            logger.error(f"Error updating worker heartbeat: {str(e)}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def list_workers(self, request):
        """
        List all registered workers
        
        GET /api/workers
        """
        workers_data = [asdict(worker) for worker in self.workers.values()]
        return web.json_response({"workers": workers_data})
    
    async def get_worker(self, request):
        """
        Get worker details
        
        GET /api/workers/{worker_id}
        """
        worker_id = request.match_info['worker_id']
        
        # Check if worker exists
        if worker_id not in self.workers:
            return web.json_response(
                {"error": f"Worker not found: {worker_id}"}, 
                status=404
            )
        
        return web.json_response(asdict(self.workers[worker_id]))
    
    async def create_task(self, request):
        """
        Create a new scan task
        
        POST /api/tasks
        """
        try:
            data = await request.json()
            
            # Validate required fields
            if 'urls' not in data:
                return web.json_response(
                    {"error": "Missing required field: urls"}, 
                    status=400
                )
            
            # Generate task ID
            task_id = str(uuid.uuid4())
            
            # Create task
            task = Task(
                id=task_id,
                urls=data['urls'],
                config=data.get('config', {})
            )
            
            # Add to tasks
            self.tasks[task_id] = task
            
            # Add to queue
            self.task_queue.put(task_id)
            
            logger.info(f"Created new task: {task_id} with {len(task.urls)} URLs")
            
            return web.json_response({
                "task_id": task_id,
                "status": task.status
            })
        
        except Exception as e:
            logger.error(f"Error creating task: {str(e)}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def list_tasks(self, request):
        """
        List all tasks
        
        GET /api/tasks
        """
        # Get query parameters
        status = request.query.get('status')
        
        # Filter tasks by status if provided
        if status:
            tasks_data = [asdict(task) for task in self.tasks.values() if task.status == status]
        else:
            tasks_data = [asdict(task) for task in self.tasks.values()]
        
        return web.json_response({"tasks": tasks_data})
    
    async def get_task(self, request):
        """
        Get task details
        
        GET /api/tasks/{task_id}
        """
        task_id = request.match_info['task_id']
        
        # Check if task exists
        if task_id not in self.tasks:
            return web.json_response(
                {"error": f"Task not found: {task_id}"}, 
                status=404
            )
        
        return web.json_response(asdict(self.tasks[task_id]))
    
    async def cancel_task(self, request):
        """
        Cancel a task
        
        POST /api/tasks/{task_id}/cancel
        """
        task_id = request.match_info['task_id']
        
        # Check if task exists
        if task_id not in self.tasks:
            return web.json_response(
                {"error": f"Task not found: {task_id}"}, 
                status=404
            )
        
        task = self.tasks[task_id]
        
        # Check if task can be canceled
        if task.status in ["completed", "failed"]:
            return web.json_response(
                {"error": f"Cannot cancel task with status: {task.status}"}, 
                status=400
            )
        
        # Cancel task
        task.status = "canceled"
        
        # If task is assigned to a worker, notify the worker
        if task.worker_id and task.worker_id in self.workers:
            worker = self.workers[task.worker_id]
            worker.current_task = None
            worker.status = "idle"
        
        logger.info(f"Canceled task: {task_id}")
        
        return web.json_response({"status": "canceled"})
    
    async def get_next_task(self, request):
        """
        Get next task for a worker
        
        GET /api/workers/{worker_id}/next_task
        """
        worker_id = request.match_info['worker_id']
        
        # Check if worker exists
        if worker_id not in self.workers:
            return web.json_response(
                {"error": f"Worker not found: {worker_id}"}, 
                status=404
            )
        
        worker = self.workers[worker_id]
        
        # Check if worker is available
        if worker.status != "idle":
            return web.json_response(
                {"error": f"Worker is not idle: {worker.status}"}, 
                status=400
            )
        
        # Try to get a task from the queue
        try:
            task_id = self.task_queue.get_nowait()
            task = self.tasks[task_id]
            
            # Assign task to worker
            task.status = "running"
            task.worker_id = worker_id
            task.started_at = time.time()
            
            # Update worker status
            worker.status = "busy"
            worker.current_task = task_id
            
            logger.info(f"Assigned task {task_id} to worker {worker_id}")
            
            # Return task details
            return web.json_response({
                "task_id": task.id,
                "urls": task.urls,
                "config": task.config
            })
        
        except queue.Empty:
            # No tasks available
            return web.json_response({"status": "no_tasks"})
        
        except Exception as e:
            logger.error(f"Error getting next task: {str(e)}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def update_task(self, request):
        """
        Update task progress
        
        POST /api/tasks/{task_id}/update
        """
        task_id = request.match_info['task_id']
        
        # Check if task exists
        if task_id not in self.tasks:
            return web.json_response(
                {"error": f"Task not found: {task_id}"}, 
                status=404
            )
        
        task = self.tasks[task_id]
        
        try:
            data = await request.json()
            
            # Update task progress
            if 'progress' in data:
                task.progress = data['progress']
            
            # Add partial results if provided
            if 'results' in data:
                task.results.extend(data['results'])
            
            logger.debug(f"Updated task {task_id}: progress={task.progress}")
            
            return web.json_response({"status": "updated"})
        
        except Exception as e:
            logger.error(f"Error updating task: {str(e)}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def complete_task(self, request):
        """
        Mark task as completed
        
        POST /api/tasks/{task_id}/complete
        """
        task_id = request.match_info['task_id']
        
        # Check if task exists
        if task_id not in self.tasks:
            return web.json_response(
                {"error": f"Task not found: {task_id}"}, 
                status=404
            )
        
        task = self.tasks[task_id]
        
        try:
            data = await request.json()
            
            # Update task status
            task.status = data.get('status', 'completed')
            task.completed_at = time.time()
            
            # Add final results if provided
            if 'results' in data:
                task.results.extend(data['results'])
            
            # Set error if task failed
            if task.status == 'failed' and 'error' in data:
                task.error = data['error']
            
            # Update worker status
            if task.worker_id and task.worker_id in self.workers:
                worker = self.workers[task.worker_id]
                worker.status = "idle"
                worker.current_task = None
                
                # Update worker stats
                worker.stats['tasks_completed'] += 1
                worker.stats['urls_scanned'] += len(task.urls)
                worker.stats['vulnerabilities_found'] += len(task.results)
            
            logger.info(f"Completed task {task_id} with status: {task.status}")
            
            return web.json_response({"status": "completed"})
        
        except Exception as e:
            logger.error(f"Error completing task: {str(e)}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def get_status(self, request):
        """
        Get coordinator status
        
        GET /api/status
        """
        # Count workers by status
        worker_counts = {
            "total": len(self.workers),
            "idle": sum(1 for w in self.workers.values() if w.status == "idle"),
            "busy": sum(1 for w in self.workers.values() if w.status == "busy"),
            "offline": sum(1 for w in self.workers.values() if w.status == "offline")
        }
        
        # Count tasks by status
        task_counts = {
            "total": len(self.tasks),
            "pending": sum(1 for t in self.tasks.values() if t.status == "pending"),
            "running": sum(1 for t in self.tasks.values() if t.status == "running"),
            "completed": sum(1 for t in self.tasks.values() if t.status == "completed"),
            "failed": sum(1 for t in self.tasks.values() if t.status == "failed"),
            "canceled": sum(1 for t in self.tasks.values() if t.status == "canceled")
        }
        
        # Calculate overall stats
        total_urls = sum(len(t.urls) for t in self.tasks.values())
        total_vulnerabilities = sum(len(t.results) for t in self.tasks.values())
        
        return web.json_response({
            "status": "running" if self.running else "stopped",
            "uptime": time.time() - self.start_time if hasattr(self, 'start_time') else 0,
            "workers": worker_counts,
            "tasks": task_counts,
            "queue_size": self.task_queue.qsize(),
            "total_urls": total_urls,
            "total_vulnerabilities": total_vulnerabilities
        })
    
    async def get_metrics(self, request):
        """
        Get detailed metrics
        
        GET /api/metrics
        """
        # Worker metrics
        worker_metrics = []
        for worker in self.workers.values():
            worker_metrics.append({
                "id": worker.id,
                "name": worker.name,
                "status": worker.status,
                "tasks_completed": worker.stats["tasks_completed"],
                "urls_scanned": worker.stats["urls_scanned"],
                "vulnerabilities_found": worker.stats["vulnerabilities_found"],
                "cpu_usage": worker.stats["cpu_usage"],
                "memory_usage": worker.stats["memory_usage"]
            })
        
        # Task completion metrics
        completed_tasks = [t for t in self.tasks.values() if t.status == "completed"]
        avg_completion_time = 0
        if completed_tasks:
            avg_completion_time = sum(
                (t.completed_at or 0) - (t.started_at or 0) 
                for t in completed_tasks
            ) / len(completed_tasks)
        
        return web.json_response({
            "workers": worker_metrics,
            "tasks": {
                "avg_completion_time": avg_completion_time,
                "avg_urls_per_task": sum(len(t.urls) for t in self.tasks.values()) / len(self.tasks) if self.tasks else 0,
                "avg_vulnerabilities_per_task": sum(len(t.results) for t in self.tasks.values()) / len(self.tasks) if self.tasks else 0
            }
        })
    
    def distribute_urls(self, urls: List[str], config: Optional[Dict[str, Any]] = None) -> str:
        """
        Distribute URLs for scanning
        
        Args:
            urls (List[str]): List of URLs to scan
            config (Optional[Dict[str, Any]]): Scan configuration
            
        Returns:
            str: Task ID
        """
        # Create task
        task_id = str(uuid.uuid4())
        
        task = Task(
            id=task_id,
            urls=urls,
            config=config or {}
        )
        
        # Add to tasks
        self.tasks[task_id] = task
        
        # Add to queue
        self.task_queue.put(task_id)
        
        logger.info(f"Distributed {len(urls)} URLs for scanning (task: {task_id})")
        
        return task_id
    
    def get_results(self, task_id: str) -> List[Dict[str, Any]]:
        """
        Get results for a task
        
        Args:
            task_id (str): Task ID
            
        Returns:
            List[Dict[str, Any]]: Task results
        """
        if task_id not in self.tasks:
            logger.warning(f"Task not found: {task_id}")
            return []
        
        task = self.tasks[task_id]
        return task.results
    
    def get_all_results(self) -> List[Dict[str, Any]]:
        """
        Get all results from all completed tasks
        
        Returns:
            List[Dict[str, Any]]: All results
        """
        all_results = []
        
        for task in self.tasks.values():
            if task.status == "completed":
                all_results.extend(task.results)
        
        return all_results
    
    async def run_standalone(self):
        """Run the coordinator in standalone mode"""
        self.start_time = time.time()
        await self.start()
        
        try:
            # Keep running until interrupted
            while True:
                await asyncio.sleep(1)
        
        except KeyboardInterrupt:
            logger.info("Shutting down coordinator...")
            await self.stop()
    
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

def main_cli():
    """Entry point for the command-line tool"""
    import argparse
    
    parser = argparse.ArgumentParser(description='OpenX Distributed Scanning Coordinator')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--config', help='Path to configuration file')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Override config with command line arguments
    if 'distributed' not in config:
        config['distributed'] = {}
    
    config['distributed']['host'] = args.host
    config['distributed']['port'] = args.port
    
    # Create and run coordinator
    coordinator = Coordinator(config)
    
    # Get local IP
    local_ip = Coordinator.get_local_ip()
    print(f"Starting coordinator on http://{local_ip}:{args.port}")
    
    # Run event loop
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(coordinator.run_standalone())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()

# Run coordinator if executed directly
if __name__ == '__main__':
    main_cli()
