package container

// EventType is the type of the event.
type EventType int

// String returns the event type as a string.
func (t EventType) String() string {
	switch t {
	case Added:
		return "added"
	case Removed:
		return "removed"
	default:
		return "unknown"
	}
}

// Event types.
const (
	Unknown EventType = iota
	Added
	Removed
)

// Event contains information about a container
// event.
type Event struct {
	Type       EventType
	Name       string
	CGroupPath string
}
