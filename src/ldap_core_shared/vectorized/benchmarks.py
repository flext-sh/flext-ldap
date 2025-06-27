from __future__ import annotations

from ldap_core_shared.utils.constants import DEFAULT_LARGE_LIMIT, DEFAULT_MAX_ITEMS

"""🚀 Performance Benchmarking Utilities - Ultra High Performance Analysis."""


import asyncio
import gc
import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

# Constants for magic values
BYTES_PER_KB = 1024
DEFAULT_CONFIDENCE_PERCENT = 95

SECONDS_PER_MINUTE = 60

try:
    import numpy as np
    import psutil

    VECTORIZED_AVAILABLE = True
except ImportError:
    # Mock implementations for when vectorized dependencies are not available
    np = None  # type: ignore
    psutil = None  # type: ignore
    VECTORIZED_AVAILABLE = False

try:
    from memory_profiler import profile

    MEMORY_PROFILER_AVAILABLE = True
except ImportError:
    MEMORY_PROFILER_AVAILABLE = False

    def profile(func: Any) -> Any:
        """Dummy decorator when memory_profiler is not available."""
        return func


import contextlib

from ldap_core_shared.utils.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Awaitable

logger = get_logger(__name__)


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""

    name: str
    duration: float
    memory_peak_mb: float
    memory_delta_mb: float
    operations_count: int
    operations_per_second: float
    success_rate: float
    error_count: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkSuite:
    """Collection of benchmark results with statistical analysis."""

    name: str
    results: list[BenchmarkResult] = field(default_factory=list)
    runs: int = 0

    @property
    def average_duration(self) -> float:
        """Calculate average duration."""
        return (
            statistics.mean([r.duration for r in self.results]) if self.results else 0.0
        )

    @property
    def duration_std_dev(self) -> float:
        """Calculate duration standard deviation."""
        return (
            statistics.stdev([r.duration for r in self.results])
            if len(self.results) > 1
            else 0.0
        )

    @property
    def average_ops_per_second(self) -> float:
        """Calculate average operations per second."""
        return (
            statistics.mean([r.operations_per_second for r in self.results])
            if self.results
            else 0.0
        )

    @property
    def peak_memory_mb(self) -> float:
        """Calculate peak memory usage."""
        return max(r.memory_peak_mb for r in self.results) if self.results else 0.0

    @property
    def confidence_interval_95(self) -> tuple[float, float]:
        """Calculate DEFAULT_CONFIDENCE_PERCENT% confidence interval for duration."""
        if len(self.results) < 2:
            return (0.0, 0.0)

        durations = [r.duration for r in self.results]
        mean = statistics.mean(durations)
        std_dev = statistics.stdev(durations)
        margin = 1.96 * (
            std_dev / (len(durations) ** 0.5)
        )  # DEFAULT_CONFIDENCE_PERCENT% CI

        return (mean - margin, mean + margin)


@dataclass
class PerformanceProfile:
    """Detailed performance profile with memory and CPU analysis."""

    operation_name: str
    total_duration: float
    cpu_percent: float
    memory_before_mb: float
    memory_after_mb: float
    memory_peak_mb: float
    gc_collections: int
    context_switches: int
    page_faults: int
    io_read_bytes: int
    io_write_bytes: int


class PerformanceBenchmarker:
    """🚀 Comprehensive performance benchmarking and analysis tool.

    Features:
    - Automated benchmarking with statistical analysis
    - Memory profiling and optimization recommendations
    - Performance comparison between implementations
    - Load testing with realistic scenarios
    - Regression detection and reporting
    """

    def __init__(
        self,
        warmup_runs: int = 3,
        benchmark_runs: int = 10,
        enable_memory_profiling: bool = True,
        enable_gc_tracking: bool = True,
        confidence_level: float = DEFAULT_CONFIDENCE_PERCENT / 100.0,
    ) -> None:
        """Initialize performance benchmarker.

        Args:
            warmup_runs: Number of warmup runs before benchmarking
            benchmark_runs: Number of benchmark runs for statistical analysis
            enable_memory_profiling: Enable detailed memory profiling
            enable_gc_tracking: Enable garbage collection tracking
            confidence_level: Statistical confidence level for results
        """
        self.warmup_runs = warmup_runs
        self.benchmark_runs = benchmark_runs
        self.enable_memory_profiling = enable_memory_profiling
        self.enable_gc_tracking = enable_gc_tracking
        self.confidence_level = confidence_level

        # Benchmark state
        self._suites: dict[str, BenchmarkSuite] = {}
        self._baseline_results: dict[str, BenchmarkResult] = {}
        self._process = psutil.Process() if psutil else None

        logger.info(
            "Performance benchmarker initialized",
            warmup_runs=warmup_runs,
            benchmark_runs=benchmark_runs,
            enable_memory_profiling=enable_memory_profiling,
            enable_gc_tracking=enable_gc_tracking,
        )

    async def benchmark_async_function(
        self,
        name: str,
        func: Callable[..., Awaitable[Any]],
        *args: Any,
        **kwargs: Any,
    ) -> BenchmarkSuite:
        """Benchmark an async function with comprehensive analysis.

        Args:
            name: Benchmark name
            func: Async function to benchmark
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Benchmark suite with statistical analysis
        """
        logger.info("Starting benchmark: %s", name)

        # Create benchmark suite
        suite = BenchmarkSuite(name=name)

        # Warmup runs
        logger.info("Performing %s warmup runs", self.warmup_runs)
        for i in range(self.warmup_runs):
            try:
                await func(*args, **kwargs)
            except Exception as e:
                logger.warning("Warmup run %s failed: %s", i + 1, e)

        # Force garbage collection before benchmarking
        if self.enable_gc_tracking:
            gc.collect()

        # Benchmark runs
        logger.info("Performing %s benchmark runs", self.benchmark_runs)
        for i in range(self.benchmark_runs):
            try:
                result = await self._run_single_benchmark(name, func, *args, **kwargs)
                suite.results.append(result)
                suite.runs += 1

                logger.debug(
                    "Benchmark run %s completed",
                    i + 1,
                    extra={
                        "duration": result.duration,
                        "ops_per_second": result.operations_per_second,
                        "memory_peak_mb": result.memory_peak_mb,
                    },
                )

            except Exception as e:
                logger.exception("Benchmark run %s failed: %s", i + 1, e)

        # Store suite
        self._suites[name] = suite

        logger.info(
            "Benchmark completed: %s",
            name,
            extra={
                "runs": suite.runs,
                "average_duration": suite.average_duration,
                "average_ops_per_second": suite.average_ops_per_second,
                "peak_memory_mb": suite.peak_memory_mb,
            },
        )

        return suite

    async def _run_single_benchmark(
        self,
        name: str,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> BenchmarkResult:
        """Run a single benchmark iteration with detailed profiling."""
        # Get initial system state
        memory_before = self._get_memory_usage_mb()
        gc_before = gc.get_count() if self.enable_gc_tracking else (0, 0, 0)
        io_before = self._get_io_stats()

        # Track peak memory during execution
        memory_peak = memory_before

        # Start timing
        start_time = time.perf_counter()

        try:
            # Execute function
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Track memory peak during execution
            memory_current = self._get_memory_usage_mb()
            memory_peak = max(memory_peak, memory_current)

            success = True
            error_count = 0

        except Exception as e:
            logger.exception("Benchmark function failed: %s", e)
            result = None
            success = False
            error_count = 1

        # Stop timing
        end_time = time.perf_counter()
        duration = end_time - start_time

        # Get final system state
        memory_after = self._get_memory_usage_mb()
        gc_after = gc.get_count() if self.enable_gc_tracking else (0, 0, 0)
        io_after = self._get_io_stats()

        # Calculate metrics
        memory_delta = memory_after - memory_before
        operations_count = self._extract_operations_count(result)
        operations_per_second = operations_count / duration if duration > 0 else 0.0
        success_rate = DEFAULT_MAX_ITEMS if success else 0.0

        # Calculate garbage collection activity
        gc_collections = (
            sum(a - b for a, b in zip(gc_after, gc_before, strict=False))
            if self.enable_gc_tracking
            else 0
        )

        return BenchmarkResult(
            name=name,
            duration=duration,
            memory_peak_mb=memory_peak,
            memory_delta_mb=memory_delta,
            operations_count=operations_count,
            operations_per_second=operations_per_second,
            success_rate=success_rate,
            error_count=error_count,
            metadata={
                "memory_before_mb": memory_before,
                "memory_after_mb": memory_after,
                "gc_collections": gc_collections,
                "io_read_delta": io_after.get("read_bytes", 0)
                - io_before.get("read_bytes", 0),
                "io_write_delta": io_after.get("write_bytes", 0)
                - io_before.get("write_bytes", 0),
                "result_type": type(result).__name__ if result else None,
            },
        )

    def benchmark_comparison(
        self,
        baseline_name: str,
        optimized_name: str,
    ) -> dict[str, Any]:
        """Compare performance between baseline and optimized implementations.

        Args:
            baseline_name: Name of baseline benchmark
            optimized_name: Name of optimized benchmark

        Returns:
            Comparison report with performance improvements
        """
        baseline_suite = self._suites.get(baseline_name)
        optimized_suite = self._suites.get(optimized_name)

        if not baseline_suite or not optimized_suite:
            msg = "Both baseline and optimized benchmarks must be run first"
            raise ValueError(msg)

        # Calculate performance improvements
        duration_improvement = (
            (baseline_suite.average_duration - optimized_suite.average_duration)
            / baseline_suite.average_duration
            * DEFAULT_MAX_ITEMS
        )

        ops_improvement = (
            (
                optimized_suite.average_ops_per_second
                - baseline_suite.average_ops_per_second
            )
            / baseline_suite.average_ops_per_second
            * DEFAULT_MAX_ITEMS
        )

        memory_improvement = (
            (baseline_suite.peak_memory_mb - optimized_suite.peak_memory_mb)
            / baseline_suite.peak_memory_mb
            * DEFAULT_MAX_ITEMS
        )

        comparison = {
            "baseline": {
                "name": baseline_name,
                "average_duration": baseline_suite.average_duration,
                "duration_std_dev": baseline_suite.duration_std_dev,
                "average_ops_per_second": baseline_suite.average_ops_per_second,
                "peak_memory_mb": baseline_suite.peak_memory_mb,
                "confidence_interval": baseline_suite.confidence_interval_95,
            },
            "optimized": {
                "name": optimized_name,
                "average_duration": optimized_suite.average_duration,
                "duration_std_dev": optimized_suite.duration_std_dev,
                "average_ops_per_second": optimized_suite.average_ops_per_second,
                "peak_memory_mb": optimized_suite.peak_memory_mb,
                "confidence_interval": optimized_suite.confidence_interval_95,
            },
            "improvements": {
                "duration_improvement_percent": duration_improvement,
                "ops_improvement_percent": ops_improvement,
                "memory_improvement_percent": memory_improvement,
                "speedup_factor": baseline_suite.average_duration
                / optimized_suite.average_duration,
            },
            "statistical_significance": self._calculate_statistical_significance(
                baseline_suite,
                optimized_suite,
            ),
        }

        logger.info(
            "Performance comparison completed",
            baseline=baseline_name,
            optimized=optimized_name,
            duration_improvement=f"{duration_improvement:.1f}%",
            ops_improvement=f"{ops_improvement:.1f}%",
            memory_improvement=f"{memory_improvement:.1f}%",
            speedup_factor=f"{comparison['improvements']['speedup_factor']:.2f}x",
        )

        return comparison

    async def load_test(
        self,
        name: str,
        func: Callable[..., Any],
        concurrent_requests: int = 10,
        duration_seconds: int = SECONDS_PER_MINUTE,
        ramp_up_seconds: int = 10,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Perform load testing with increasing concurrent requests.

        Args:
            name: Load test name
            func: Function to load test
            concurrent_requests: Maximum concurrent requests
            duration_seconds: Load test duration
            ramp_up_seconds: Ramp up time to reach max concurrency
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Load test results with performance metrics
        """
        logger.info(
            "Starting load test: %s",
            name,
            extra={
                "concurrent_requests": concurrent_requests,
                "duration_seconds": duration_seconds,
            },
        )

        # Initialize load test context
        context = _LoadTestContext(
            name=name,
            func=func,
            args=args,
            kwargs=kwargs,
            concurrent_requests=concurrent_requests,
            duration_seconds=duration_seconds,
            ramp_up_seconds=ramp_up_seconds,
        )

        # Execute load test
        results, errors, memory_samples, cpu_samples = await self._execute_load_test(
            context,
        )

        # Generate final results
        if results:
            return self._build_load_test_results(
                context, results, errors, memory_samples, cpu_samples,
            )
        logger.error("Load test failed: %s - No results collected", name)
        return {"error": "No results collected"}

    def generate_performance_report(self, output_format: str = "text") -> str:
        """Generate comprehensive performance report.

        Args:
            output_format: Output format ('text', 'json', 'markdown')

        Returns:
            Formatted performance report
        """
        if output_format == "markdown":
            return self._generate_markdown_report()
        if output_format == "json":
            return self._generate_json_report()
        return self._generate_text_report()

    def _generate_text_report(self) -> str:
        """Generate text format performance report."""
        lines = ["🚀 Performance Benchmark Report", "=" * 40, ""]

        for name, suite in self._suites.items():
            lines.extend(
                [
                    f"Benchmark: {name}",
                    f"  Runs: {suite.runs}",
                    f"  Average Duration: {suite.average_duration:.4f}s",
                    f"  Duration Std Dev: {suite.duration_std_dev:.4f}s",
                    f"  Average Ops/Second: {suite.average_ops_per_second:.2f}",
                    f"  Peak Memory: {suite.peak_memory_mb:.2f}MB",
                    f"  95% CI: {suite.confidence_interval_95[0]:.4f}s - {suite.confidence_interval_95[1]:.4f}s",
                    "",
                ],
            )

        return "\n".join(lines)

    def _generate_markdown_report(self) -> str:
        """Generate markdown format performance report."""
        lines = ["# 🚀 Performance Benchmark Report", ""]

        # Summary table
        lines.extend(
            [
                "## Summary",
                "",
                "| Benchmark | Runs | Avg Duration (s) | Ops/Second | Peak Memory (MB) |",
                "|-----------|------|------------------|------------|------------------|",
            ],
        )

        for name, suite in self._suites.items():
            lines.append(
                f"| {name} | {suite.runs} | {suite.average_duration:.4f} | "
                f"{suite.average_ops_per_second:.2f} | {suite.peak_memory_mb:.2f} |",
            )

        lines.extend(["", "## Detailed Results", ""])

        for name, suite in self._suites.items():
            lines.extend(
                [
                    f"### {name}",
                    "",
                    f"- **Runs**: {suite.runs}",
                    f"- **Average Duration**: {suite.average_duration:.4f}s ± {suite.duration_std_dev:.4f}s",
                    f"- **Operations per Second**: {suite.average_ops_per_second:.2f}",
                    f"- **Peak Memory Usage**: {suite.peak_memory_mb:.2f}MB",
                    f"- **95% Confidence Interval**: {suite.confidence_interval_95[0]:.4f}s - {suite.confidence_interval_95[1]:.4f}s",
                    "",
                ],
            )

        return "\n".join(lines)

    def _generate_json_report(self) -> str:
        """Generate JSON format performance report."""
        import json

        report_data = {
            "timestamp": time.time(),
            "benchmarks": {},
        }

        for name, suite in self._suites.items():
            report_data["benchmarks"][name] = {
                "runs": suite.runs,
                "average_duration": suite.average_duration,
                "duration_std_dev": suite.duration_std_dev,
                "average_ops_per_second": suite.average_ops_per_second,
                "peak_memory_mb": suite.peak_memory_mb,
                "confidence_interval_95": suite.confidence_interval_95,
                "results": [
                    {
                        "duration": r.duration,
                        "memory_peak_mb": r.memory_peak_mb,
                        "operations_per_second": r.operations_per_second,
                        "success_rate": r.success_rate,
                    }
                    for r in suite.results
                ],
            }

        return json.dumps(report_data, indent=2)

    def _get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        if self._process is not None:
            return self._process.memory_info().rss / BYTES_PER_KB / BYTES_PER_KB
        return 0.0

    def _get_io_stats(self) -> dict[str, int]:
        """Get I/O statistics."""
        try:
            if self._process is not None:
                io_counters = self._process.io_counters()
                return {
                    "read_bytes": io_counters.read_bytes,
                    "write_bytes": io_counters.write_bytes,
                }
        except (AttributeError, OSError):
            pass
        return {"read_bytes": 0, "write_bytes": 0}

    def _extract_operations_count(self, result: Any) -> int:
        """Extract operations count from function result."""
        if result is None:
            return 1

        # Try to extract from common result formats
        if hasattr(result, "total_entries"):
            return result.total_entries
        if hasattr(result, "entries") and hasattr(result.entries, "__len__"):
            return len(result.entries)
        if hasattr(result, "__len__"):
            return len(result)
        return 1

    def _calculate_statistical_significance(
        self,
        baseline: BenchmarkSuite,
        optimized: BenchmarkSuite,
    ) -> dict[str, Any]:
        """Calculate statistical significance of performance difference."""
        if len(baseline.results) < 2 or len(optimized.results) < 2:
            return {"significant": False, "reason": "Insufficient samples"}

        baseline_durations = [r.duration for r in baseline.results]
        optimized_durations = [r.duration for r in optimized.results]

        # Simple t-test approximation
        baseline_mean = statistics.mean(baseline_durations)
        optimized_mean = statistics.mean(optimized_durations)
        baseline_std = statistics.stdev(baseline_durations)
        optimized_std = statistics.stdev(optimized_durations)

        pooled_std = ((baseline_std**2 + optimized_std**2) / 2) ** 0.5
        t_stat = abs(baseline_mean - optimized_mean) / (
            pooled_std
            * ((1 / len(baseline_durations) + 1 / len(optimized_durations)) ** 0.5)
        )

        # Rough significance check (t > 2.0 for DEFAULT_CONFIDENCE_PERCENT% confidence)
        significant = t_stat > 2.0

        return {
            "significant": significant,
            "t_statistic": t_stat,
            "confidence_level": DEFAULT_CONFIDENCE_PERCENT / 100.0
            if significant
            else None,
            "baseline_mean": baseline_mean,
            "optimized_mean": optimized_mean,
        }

    async def _execute_load_test(
        self, context: _LoadTestContext,
    ) -> tuple[list, list, list, list]:
        """Execute the load test with monitoring.

        Args:
            context: Load test context with all parameters

        Returns:
            Tuple of (results, errors, memory_samples, cpu_samples)
        """
        # Initialize collections
        results = []
        errors = []
        memory_samples = []
        cpu_samples = []

        start_time = time.time()
        end_time = start_time + context.duration_seconds

        # Start system monitoring
        monitor_task = asyncio.create_task(
            self._collect_system_metrics(end_time, memory_samples, cpu_samples),
        )

        # Execute load test with controlled concurrency
        await self._run_load_test_loop(context, start_time, end_time, results, errors)

        # Stop monitoring
        monitor_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await monitor_task

        return results, errors, memory_samples, cpu_samples

    async def _collect_system_metrics(
        self,
        end_time: float,
        memory_samples: list,
        cpu_samples: list,
    ) -> None:
        """Collect system metrics during load test.

        Args:
            end_time: Test end time
            memory_samples: List to append memory samples to
            cpu_samples: List to append CPU samples to
        """
        while time.time() < end_time:
            memory_samples.append(self._get_memory_usage_mb())
            if self._process is not None:
                cpu_samples.append(self._process.cpu_percent())
            else:
                cpu_samples.append(0.0)
            await asyncio.sleep(1.0)

    async def _run_load_test_loop(
        self,
        context: _LoadTestContext,
        start_time: float,
        end_time: float,
        results: list,
        errors: list,
    ) -> None:
        """Run the main load test loop with ramp-up.

        Args:
            context: Load test context
            start_time: Test start time
            end_time: Test end time
            results: List to append results to
            errors: List to append errors to
        """
        semaphore = asyncio.Semaphore(context.concurrent_requests)
        tasks: list[asyncio.Task[Any]] = []
        current_time = time.time()

        while current_time < end_time:
            # Calculate current concurrency with ramp-up
            current_concurrency = self._calculate_current_concurrency(
                current_time,
                start_time,
                context.ramp_up_seconds,
                context.concurrent_requests,
            )

            # Launch new tasks up to concurrency limit
            await self._launch_new_tasks(
                context, semaphore, tasks, current_concurrency, end_time,
            )

            # Process completed tasks
            await self._process_completed_tasks(tasks, results, errors)

            await asyncio.sleep(0.1)
            current_time = time.time()

        # Wait for remaining tasks
        await self._process_remaining_tasks(tasks, results, errors)

    def _calculate_current_concurrency(
        self,
        current_time: float,
        start_time: float,
        ramp_up_seconds: int,
        max_concurrent_requests: int,
    ) -> int:
        """Calculate current concurrency level based on ramp-up.

        Args:
            current_time: Current timestamp
            start_time: Test start timestamp
            ramp_up_seconds: Ramp-up duration
            max_concurrent_requests: Maximum concurrent requests

        Returns:
            Current concurrency level
        """
        elapsed = current_time - start_time
        if elapsed < ramp_up_seconds:
            return int((elapsed / ramp_up_seconds) * max_concurrent_requests)
        return max_concurrent_requests

    async def _launch_new_tasks(
        self,
        context: _LoadTestContext,
        semaphore: asyncio.Semaphore,
        tasks: list,
        current_concurrency: int,
        end_time: float,
    ) -> None:
        """Launch new tasks up to concurrency limit.

        Args:
            context: Load test context
            semaphore: Concurrency control semaphore
            tasks: Current tasks list
            current_concurrency: Target concurrency level
            end_time: Test end time
        """
        while len(tasks) < current_concurrency and time.time() < end_time:
            task = asyncio.create_task(
                self._execute_single_request(context, semaphore),
            )
            tasks.append(task)

    async def _execute_single_request(
        self,
        context: _LoadTestContext,
        semaphore: asyncio.Semaphore,
    ) -> tuple[float, bool, str]:
        """Execute a single request with timing and error handling.

        Args:
            context: Load test context
            semaphore: Concurrency control semaphore

        Returns:
            Tuple of (duration, success, error_message)
        """
        async with semaphore:
            request_start = time.perf_counter()
            try:
                if asyncio.iscoroutinefunction(context.func):
                    await context.func(*context.args, **context.kwargs)
                else:
                    context.func(*context.args, **context.kwargs)
                success = True
                error_msg = ""
            except Exception as e:
                success = False
                error_msg = str(e)

            request_duration = time.perf_counter() - request_start
            return request_duration, success, error_msg

    async def _process_completed_tasks(
        self, tasks: list, results: list, errors: list,
    ) -> None:
        """Process completed tasks and collect results.

        Args:
            tasks: List of current tasks
            results: List to append results to
            errors: List to append errors to
        """
        done_tasks = [task for task in tasks if task.done()]
        for task in done_tasks:
            try:
                duration, success, error_msg = await task
                results.append((duration, success))
                if not success:
                    errors.append(error_msg)
            except Exception as e:
                errors.append(str(e))

            tasks.remove(task)

    async def _process_remaining_tasks(
        self, tasks: list, results: list, errors: list,
    ) -> None:
        """Process any remaining tasks at test end.

        Args:
            tasks: List of remaining tasks
            results: List to append results to
            errors: List to append errors to
        """
        if tasks:
            remaining_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in remaining_results:
                if isinstance(result, Exception):
                    errors.append(str(result))
                else:
                    duration, success, error_msg = result
                    results.append((duration, success))
                    if not success:
                        errors.append(error_msg)

    def _build_load_test_results(
        self,
        context: _LoadTestContext,
        results: list,
        errors: list,
        memory_samples: list,
        cpu_samples: list,
    ) -> dict[str, Any]:
        """Build final load test results dictionary.

        Args:
            context: Load test context
            results: Test results
            errors: Test errors
            memory_samples: Memory usage samples
            cpu_samples: CPU usage samples

        Returns:
            Load test results dictionary
        """
        durations = [r[0] for r in results]
        successes = [r[1] for r in results]

        # Calculate basic metrics
        total_requests = len(results)
        successful_requests = sum(successes)
        failed_requests = total_requests - successful_requests
        success_rate = (successful_requests / total_requests) * DEFAULT_MAX_ITEMS
        throughput = total_requests / context.duration_seconds

        # Calculate response time statistics
        response_times = self._calculate_response_time_stats(durations)

        # Calculate system metrics
        system_metrics = self._calculate_system_metrics(memory_samples, cpu_samples)

        # Build final result
        load_test_result = {
            "name": context.name,
            "configuration": {
                "concurrent_requests": context.concurrent_requests,
                "duration_seconds": context.duration_seconds,
                "ramp_up_seconds": context.ramp_up_seconds,
            },
            "results": {
                "total_requests": total_requests,
                "successful_requests": successful_requests,
                "failed_requests": failed_requests,
                "success_rate_percent": success_rate,
                "throughput_rps": throughput,
            },
            "response_times": response_times,
            "system_metrics": system_metrics,
            "errors": {
                "total_errors": len(errors),
                "unique_errors": len(set(errors)),
                "error_samples": errors[:10],  # First 10 errors
            },
        }

        self._log_load_test_completion(context.name, load_test_result)
        return load_test_result

    def _calculate_response_time_stats(
        self, durations: list[float],
    ) -> dict[str, float]:
        """Calculate response time statistics.

        Args:
            durations: List of response time durations

        Returns:
            Response time statistics dictionary
        """
        if not durations:
            return {}

        avg_response_time = statistics.mean(durations)
        min_response_time = min(durations)
        max_response_time = max(durations)
        if np is not None:
            p95_response_time = np.percentile(durations, DEFAULT_CONFIDENCE_PERCENT)
            p99_response_time = np.percentile(durations, 99)
        else:
            # Fallback calculation without numpy
            sorted_durations = sorted(durations)
            p95_index = int(len(sorted_durations) * 0.95)
            p99_index = int(len(sorted_durations) * 0.99)
            p95_response_time = sorted_durations[
                min(p95_index, len(sorted_durations) - 1)
            ]
            p99_response_time = sorted_durations[
                min(p99_index, len(sorted_durations) - 1)
            ]

        return {
            "average_ms": avg_response_time * DEFAULT_LARGE_LIMIT,
            "min_ms": min_response_time * DEFAULT_LARGE_LIMIT,
            "max_ms": max_response_time * DEFAULT_LARGE_LIMIT,
            "p95_ms": p95_response_time * DEFAULT_LARGE_LIMIT,
            "p99_ms": p99_response_time * DEFAULT_LARGE_LIMIT,
        }

    def _calculate_system_metrics(
        self, memory_samples: list, cpu_samples: list,
    ) -> dict[str, float]:
        """Calculate system metrics.

        Args:
            memory_samples: Memory usage samples
            cpu_samples: CPU usage samples

        Returns:
            System metrics dictionary
        """
        return {
            "peak_memory_mb": max(memory_samples) if memory_samples else 0,
            "avg_memory_mb": statistics.mean(memory_samples) if memory_samples else 0,
            "peak_cpu_percent": max(cpu_samples) if cpu_samples else 0,
            "avg_cpu_percent": statistics.mean(cpu_samples) if cpu_samples else 0,
        }

    def _log_load_test_completion(self, name: str, result: dict[str, Any]) -> None:
        """Log load test completion with key metrics.

        Args:
            name: Test name
            result: Test results dictionary
        """
        logger.info(
            "Load test completed: %s",
            name,
            extra={
                "total_requests": result["results"]["total_requests"],
                "success_rate": f"{result['results']['success_rate_percent']:.1f}%",
                "throughput": f"{result['results']['throughput_rps']:.1f} RPS",
                "avg_response_time": f"{result['response_times']['average_ms']:.1f}ms",
                "p95_response_time": f"{result['response_times']['p95_ms']:.1f}ms",
            },
        )


@dataclass
class _LoadTestContext:
    """Internal context for load test execution."""

    name: str
    func: Callable
    args: tuple
    kwargs: dict
    concurrent_requests: int
    duration_seconds: int
    ramp_up_seconds: int


# Factory function for easy integration
def create_performance_benchmarker(**kwargs) -> PerformanceBenchmarker:
    """Factory function to create performance benchmarker.

    Args:
        **kwargs: Configuration options

    Returns:
        Configured performance benchmarker
    """
    return PerformanceBenchmarker(**kwargs)
