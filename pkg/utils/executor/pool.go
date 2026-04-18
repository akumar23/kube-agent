package executor

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
)

// Task represents a unit of work for the worker pool.
type Task struct {
	// Name is an identifier used in logging (e.g. container name, image name).
	Name    string
	Execute func(ctx context.Context) (interface{}, error)
}

// Result holds the outcome of a single task.
type Result struct {
	Name     string
	Data     interface{}
	Error    error
	Duration time.Duration
}

// Pool manages bounded concurrent execution of tasks.
type Pool struct {
	workers  int
	tasks    []Task
	mu       sync.Mutex
	log      logr.Logger
	shutdown atomic.Bool
	running  atomic.Bool
}

// NewPool creates a pool with the given worker count (clamped to at least 1).
func NewPool(workers int, log logr.Logger) *Pool {
	if workers <= 0 {
		workers = 1
	}
	return &Pool{
		workers: workers,
		tasks:   make([]Task, 0),
		log:     log,
	}
}

// Submit adds a task to the queue. Returns an error if the pool is already
// running or has been shut down.
func (p *Pool) Submit(task Task) error {
	if p.shutdown.Load() {
		return fmt.Errorf("pool is shutting down")
	}
	if p.running.Load() {
		return fmt.Errorf("pool is already running")
	}
	if task.Name == "" {
		return fmt.Errorf("task must have a name")
	}
	if task.Execute == nil {
		return fmt.Errorf("task must have an execute function")
	}
	p.mu.Lock()
	p.tasks = append(p.tasks, task)
	p.mu.Unlock()
	return nil
}

// Execute runs all submitted tasks concurrently and returns one Result per task.
func (p *Pool) Execute(ctx context.Context) []Result {
	return p.ExecuteWithProgress(ctx, nil)
}

// ExecuteWithProgress runs tasks and calls progressFn(completed, total) after each one.
func (p *Pool) ExecuteWithProgress(ctx context.Context, progressFn func(completed, total int)) []Result {
	if !p.running.CompareAndSwap(false, true) {
		p.log.Info("executor pool already running")
		return nil
	}
	defer p.running.Store(false)

	p.mu.Lock()
	taskCount := len(p.tasks)
	if taskCount == 0 {
		p.mu.Unlock()
		return []Result{}
	}
	tasksCopy := make([]Task, taskCount)
	copy(tasksCopy, p.tasks)
	p.mu.Unlock()

	p.log.V(1).Info("starting task execution", "workers", p.workers, "tasks", taskCount)
	start := time.Now()

	taskChan := make(chan taskWithIndex, taskCount)
	resultChan := make(chan resultWithIndex, taskCount)
	var completed atomic.Int32

	workerCount := min(p.workers, taskCount)
	var wg sync.WaitGroup
	for i := range workerCount {
		wg.Add(1)
		go p.worker(ctx, i, taskChan, resultChan, &wg, &completed, taskCount, progressFn)
	}

	for i, task := range tasksCopy {
		select {
		case taskChan <- taskWithIndex{task: task, index: i}:
		case <-ctx.Done():
			p.log.Info("context cancelled while queuing tasks")
			close(taskChan)
			goto wait
		}
	}
	close(taskChan)

wait:
	wg.Wait()
	close(resultChan)

	results := make([]Result, taskCount)
	for res := range resultChan {
		if res.index >= 0 && res.index < taskCount {
			results[res.index] = res.result
		}
	}
	// Fill in any tasks that didn't run due to context cancellation.
	for i := range results {
		if results[i].Name == "" {
			results[i] = Result{
				Name:  tasksCopy[i].Name,
				Error: fmt.Errorf("task not executed: %w", ctx.Err()),
			}
		}
	}

	p.log.V(1).Info("task execution complete",
		"total", taskCount,
		"successful", CountSuccessful(results),
		"failed", CountFailed(results),
		"duration", time.Since(start))
	return results
}

func (p *Pool) worker(
	ctx context.Context,
	id int,
	taskChan <-chan taskWithIndex,
	resultChan chan<- resultWithIndex,
	wg *sync.WaitGroup,
	completed *atomic.Int32,
	total int,
	progressFn func(int, int),
) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-taskChan:
			if !ok {
				return
			}
			result := p.executeTask(ctx, item.task)
			select {
			case resultChan <- resultWithIndex{result: result, index: item.index}:
			case <-ctx.Done():
				return
			}
			if progressFn != nil {
				progressFn(int(completed.Add(1)), total)
			}
		}
	}
}

func (p *Pool) executeTask(ctx context.Context, task Task) Result {
	start := time.Now()
	select {
	case <-ctx.Done():
		return Result{
			Name:     task.Name,
			Error:    fmt.Errorf("cancelled before execution: %w", ctx.Err()),
			Duration: time.Since(start),
		}
	default:
	}
	data, err := task.Execute(ctx)
	dur := time.Since(start)
	if err != nil {
		p.log.V(1).Info("task failed", "name", task.Name, "error", err, "duration", dur)
	}
	return Result{Name: task.Name, Data: data, Error: err, Duration: dur}
}

type taskWithIndex struct {
	task  Task
	index int
}

type resultWithIndex struct {
	result Result
	index  int
}
