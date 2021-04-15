package k8s

import (
	"fmt"
	"strings"

	"github.com/nrwiersma/ebpf/containers"
	corev1 "k8s.io/api/core/v1"
)

type podEvents struct {
	cgroupRoot string
}

func (e podEvents) AddEvents(pod *corev1.Pod) []containers.ContainerEvent {
	if pod.Status.Phase != corev1.PodRunning {
		return nil
	}

	return []containers.ContainerEvent{{
		Type:       containers.Added,
		Name:       e.name(pod),
		CGroupPath: e.cgroupPath(pod),
	}}
}

func (e podEvents) UpdateEvents(_, newPod *corev1.Pod) []containers.ContainerEvent {
	evnt := containers.ContainerEvent{
		Name:       e.name(newPod),
		CGroupPath: e.cgroupPath(newPod),
	}

	switch newPod.Status.Phase {
	case corev1.PodPending:
		return nil
	case corev1.PodRunning:
		evnt.Type = containers.Added
	default:
		evnt.Type = containers.Removed
	}
	return []containers.ContainerEvent{evnt}
}

func (e podEvents) DeleteEvents(pod *corev1.Pod) []containers.ContainerEvent {
	return []containers.ContainerEvent{{
		Type:       containers.Removed,
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

func (e containerEvents) AddEvents(pod *corev1.Pod) []containers.ContainerEvent {
	var events []containers.ContainerEvent
	for _, cont := range pod.Status.ContainerStatuses {
		if cont.State.Running != nil {
			continue
		}

		events = append(events, containers.ContainerEvent{
			Type:       containers.Added,
			Name:       e.name(pod, cont),
			CGroupPath: e.cgroupPath(pod, cont),
		})
	}

	return events
}

func (e containerEvents) UpdateEvents(_, newPod *corev1.Pod) []containers.ContainerEvent {
	var events []containers.ContainerEvent
	for _, cont := range newPod.Status.ContainerStatuses {
		evnt := containers.ContainerEvent{
			Name:       newPod.Namespace + "/" + newPod.Name,
			CGroupPath: e.cgroupPath(newPod, cont),
		}

		switch {
		case cont.State.Waiting != nil:
			return nil
		case cont.State.Running != nil:
			evnt.Type = containers.Added
		default:
			evnt.Type = containers.Removed
		}

		events = append(events, evnt)
	}

	return events
}

func (e containerEvents) DeleteEvents(pod *corev1.Pod) []containers.ContainerEvent {
	var events []containers.ContainerEvent
	for _, cont := range pod.Status.ContainerStatuses {
		events = append(events, containers.ContainerEvent{
			Type:       containers.Removed,
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
