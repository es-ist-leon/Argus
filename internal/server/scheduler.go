package server

import (
	"context"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/argus/argus/pkg/models"
	"github.com/google/uuid"
)

// ScheduledTask represents a task to run at specified times
type ScheduledTask struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Command     models.Command         `json:"command"`
	Schedule    Schedule               `json:"schedule"`
	TargetAgent string                 `json:"target_agent"`
	TargetGroup string                 `json:"target_group"`
	Enabled     bool                   `json:"enabled"`
	LastRun     time.Time              `json:"last_run"`
	NextRun     time.Time              `json:"next_run"`
	RunCount    int                    `json:"run_count"`
	CreatedAt   time.Time              `json:"created_at"`
	CreatedBy   string                 `json:"created_by"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Schedule defines when a task should run
type Schedule struct {
	Type     ScheduleType `json:"type"`
	Interval string       `json:"interval"` // For interval type: "5m", "1h", "24h"
	Cron     string       `json:"cron"`     // For cron type: "0 0 * * *"
	Once     time.Time    `json:"once"`     // For once type
	Times    []string     `json:"times"`    // For daily type: ["09:00", "17:00"]
	Days     []int        `json:"days"`     // For weekly type: [1, 3, 5] (Mon, Wed, Fri)
}

type ScheduleType string

const (
	ScheduleOnce     ScheduleType = "once"
	ScheduleInterval ScheduleType = "interval"
	ScheduleDaily    ScheduleType = "daily"
	ScheduleWeekly   ScheduleType = "weekly"
	ScheduleCron     ScheduleType = "cron"
)

// Scheduler manages scheduled tasks
type Scheduler struct {
	mu       sync.RWMutex
	tasks    map[string]*ScheduledTask
	cmdChan  chan *models.Command
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	ticker   *time.Ticker
	dataDir  string
}

// NewScheduler creates a new scheduler
func NewScheduler(cmdChan chan *models.Command, dataDir string) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		tasks:   make(map[string]*ScheduledTask),
		cmdChan: cmdChan,
		ctx:     ctx,
		cancel:  cancel,
		dataDir: dataDir,
	}
}

// Start begins the scheduler loop
func (s *Scheduler) Start() {
	s.ticker = time.NewTicker(10 * time.Second)
	s.wg.Add(1)
	go s.run()
	log.Println("Scheduler started")
}

// Stop gracefully stops the scheduler
func (s *Scheduler) Stop() {
	s.cancel()
	if s.ticker != nil {
		s.ticker.Stop()
	}
	s.wg.Wait()
	log.Println("Scheduler stopped")
}

func (s *Scheduler) run() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			s.checkTasks()
		}
	}
}

func (s *Scheduler) checkTasks() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	for _, task := range s.tasks {
		if !task.Enabled {
			continue
		}

		if task.NextRun.IsZero() {
			task.NextRun = s.calculateNextRun(task, now)
			continue
		}

		if now.After(task.NextRun) {
			s.executeTask(task)
			task.LastRun = now
			task.RunCount++

			// Calculate next run
			if task.Schedule.Type == ScheduleOnce {
				task.Enabled = false
			} else {
				task.NextRun = s.calculateNextRun(task, now)
			}
		}
	}
}

func (s *Scheduler) executeTask(task *ScheduledTask) {
	cmd := task.Command
	cmd.ID = uuid.New().String()
	cmd.CreatedAt = time.Now()

	if task.TargetAgent != "" {
		cmd.TargetAgent = task.TargetAgent
	} else if task.TargetGroup != "" {
		cmd.TargetGroup = task.TargetGroup
	}

	select {
	case s.cmdChan <- &cmd:
		log.Printf("Scheduled task executed: %s (%s)", task.Name, task.ID)
	default:
		log.Printf("Failed to queue scheduled task: %s (channel full)", task.Name)
	}
}

func (s *Scheduler) calculateNextRun(task *ScheduledTask, from time.Time) time.Time {
	switch task.Schedule.Type {
	case ScheduleOnce:
		return task.Schedule.Once

	case ScheduleInterval:
		duration, err := time.ParseDuration(task.Schedule.Interval)
		if err != nil {
			log.Printf("Invalid interval for task %s: %v", task.ID, err)
			return time.Time{}
		}
		if task.LastRun.IsZero() {
			return from.Add(duration)
		}
		return task.LastRun.Add(duration)

	case ScheduleDaily:
		// Find next occurrence of any scheduled time today or tomorrow
		for _, timeStr := range task.Schedule.Times {
			t, err := time.Parse("15:04", timeStr)
			if err != nil {
				continue
			}
			next := time.Date(from.Year(), from.Month(), from.Day(),
				t.Hour(), t.Minute(), 0, 0, from.Location())
			if next.After(from) {
				return next
			}
		}
		// All times passed today, schedule for first time tomorrow
		if len(task.Schedule.Times) > 0 {
			t, _ := time.Parse("15:04", task.Schedule.Times[0])
			return time.Date(from.Year(), from.Month(), from.Day()+1,
				t.Hour(), t.Minute(), 0, 0, from.Location())
		}

	case ScheduleWeekly:
		// Find next occurrence on specified days
		sortedDays := make([]int, len(task.Schedule.Days))
		copy(sortedDays, task.Schedule.Days)
		sort.Ints(sortedDays)

		currentDay := int(from.Weekday())
		for i := 0; i < 8; i++ {
			checkDay := (currentDay + i) % 7
			for _, day := range sortedDays {
				if day == checkDay {
					next := from.AddDate(0, 0, i)
					if len(task.Schedule.Times) > 0 {
						t, _ := time.Parse("15:04", task.Schedule.Times[0])
						next = time.Date(next.Year(), next.Month(), next.Day(),
							t.Hour(), t.Minute(), 0, 0, from.Location())
					}
					if next.After(from) {
						return next
					}
				}
			}
		}
	}

	return time.Time{}
}

// AddTask adds a new scheduled task
func (s *Scheduler) AddTask(task *ScheduledTask) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if task.ID == "" {
		task.ID = uuid.New().String()
	}
	task.CreatedAt = time.Now()
	task.NextRun = s.calculateNextRun(task, time.Now())

	s.tasks[task.ID] = task
	log.Printf("Scheduled task added: %s (next run: %s)", task.Name, task.NextRun)
	return nil
}

// RemoveTask removes a scheduled task
func (s *Scheduler) RemoveTask(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tasks[id]; ok {
		delete(s.tasks, id)
		return true
	}
	return false
}

// GetTask retrieves a task by ID
func (s *Scheduler) GetTask(id string) (*ScheduledTask, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	task, ok := s.tasks[id]
	return task, ok
}

// ListTasks returns all tasks
func (s *Scheduler) ListTasks() []*ScheduledTask {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tasks := make([]*ScheduledTask, 0, len(s.tasks))
	for _, task := range s.tasks {
		tasks = append(tasks, task)
	}
	return tasks
}

// EnableTask enables a task
func (s *Scheduler) EnableTask(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if task, ok := s.tasks[id]; ok {
		task.Enabled = true
		task.NextRun = s.calculateNextRun(task, time.Now())
		return true
	}
	return false
}

// DisableTask disables a task
func (s *Scheduler) DisableTask(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if task, ok := s.tasks[id]; ok {
		task.Enabled = false
		return true
	}
	return false
}

// UpdateTask updates an existing task
func (s *Scheduler) UpdateTask(task *ScheduledTask) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tasks[task.ID]; ok {
		task.NextRun = s.calculateNextRun(task, time.Now())
		s.tasks[task.ID] = task
		return true
	}
	return false
}
