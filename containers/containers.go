package containers

type EventType int

const (
	Unkown EventType = iota
	Added
	Removed
)

// ContainerEvent contains information about a container
// event.
type ContainerEvent struct {
	Type       EventType
	Name       string
	CGroupPath string
}
