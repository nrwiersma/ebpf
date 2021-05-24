package k8s

import (
	"fmt"
	"strings"

	"github.com/nrwiersma/ebpf/container"
	corev1 "k8s.io/api/core/v1"
)

type podEvents struct {
	cgroupRoot string
}

func (e podEvents) AddEvents(pod *corev1.Pod) []container.Event {
	if pod.Status.Phase != corev1.PodRunning {
		return nil
	}

	return []container.Event{{
		Type:       container.Added,
		Name:       e.name(pod),
		CGroupPath: e.cgroupPath(pod),
	}}
}

func (e podEvents) UpdateEvents(_, newPod *corev1.Pod) []container.Event {
	evnt := container.Event{
		Name:       e.name(newPod),
		CGroupPath: e.cgroupPath(newPod),
	}

	switch newPod.Status.Phase {
	case corev1.PodPending:
		return nil
	case corev1.PodRunning:
		evnt.Type = container.Added
	default:
		evnt.Type = container.Removed
	}
	return []container.Event{evnt}
}

func (e podEvents) DeleteEvents(pod *corev1.Pod) []container.Event {
	return []container.Event{{
		Type:       container.Removed,
		Name:       e.name(pod),
		CGroupPath: e.cgroupPath(pod),
	}}
}

func (e podEvents) name(pod *corev1.Pod) string {
	return pod.Namespace + "/" + pod.Name
}

func (e podEvents) cgroupPath(pod *corev1.Pod) string {
	return fmt.Sprintf("%s/kubepods/%s/pod%s", e.cgroupRoot, strings.ToLower(string(pod.Status.QOSClass)), string(pod.UID))
}

type containerEvents struct {
	cgroupRoot string
}

func (e containerEvents) AddEvents(pod *corev1.Pod) []container.Event {
	events := make([]container.Event, 0, len(pod.Status.ContainerStatuses))
	for _, cont := range pod.Status.ContainerStatuses {
		if cont.State.Running == nil {
			continue
		}

		events = append(events, container.Event{
			Type:       container.Added,
			Name:       e.name(pod, cont),
			CGroupPath: e.cgroupPath(pod, cont),
		})
	}

	return events
}

func (e containerEvents) UpdateEvents(_, newPod *corev1.Pod) []container.Event {
	events := make([]container.Event, 0, len(newPod.Status.ContainerStatuses))
	for _, cont := range newPod.Status.ContainerStatuses {
		evnt := container.Event{
			Name:       newPod.Namespace + "/" + newPod.Name,
			CGroupPath: e.cgroupPath(newPod, cont),
		}

		switch {
		case cont.State.Waiting != nil:
			return nil
		case cont.State.Running != nil:
			evnt.Type = container.Added
		default:
			evnt.Type = container.Removed
		}

		events = append(events, evnt)
	}

	return events
}

func (e containerEvents) DeleteEvents(pod *corev1.Pod) []container.Event {
	events := make([]container.Event, 0, len(pod.Status.ContainerStatuses))
	for _, cont := range pod.Status.ContainerStatuses {
		events = append(events, container.Event{
			Type:       container.Removed,
			Name:       e.name(pod, cont),
			CGroupPath: e.cgroupPath(pod, cont),
		})
	}

	return events
}

func (e containerEvents) name(pod *corev1.Pod, cont corev1.ContainerStatus) string {
	return pod.Namespace + "/" + pod.Name + ":" + cont.ContainerID
}

const containerSep = "://"

func (e containerEvents) cgroupPath(pod *corev1.Pod, cont corev1.ContainerStatus) string {
	idx := strings.Index(cont.ContainerID, containerSep)
	if idx == -1 {
		panic("malformed cotainer id: " + cont.ContainerID)
	}
	contID := cont.ContainerID[idx+len(containerSep):]

	return fmt.Sprintf("%s/kubepods/%s/pod%s/%s",
		e.cgroupRoot,
		strings.ToLower(string(pod.Status.QOSClass)),
		string(pod.UID),
		contID,
	)
}
