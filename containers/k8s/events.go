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
		Name:       pod.Namespace + "/" + pod.Name,
		CGroupPath: e.cgroupPath(pod),
	}}
}

func (e podEvents) UpdateEvents(_, newPod *corev1.Pod) []containers.ContainerEvent {
	evnt := containers.ContainerEvent{
		Name:       newPod.Namespace + "/" + newPod.Name,
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
		Name:       pod.Namespace + "/" + pod.Name,
		CGroupPath: e.cgroupPath(pod),
	}}
}

func (e podEvents) cgroupPath(pod *corev1.Pod) string {
	return fmt.Sprintf("%s/kubepods/%s/pod%s", e.cgroupRoot, strings.ToLower(string(pod.Status.QOSClass)), string(pod.UID))
}


