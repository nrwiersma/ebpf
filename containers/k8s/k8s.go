package k8s

import (
	"fmt"
	"strings"
	"time"

	"github.com/nrwiersma/ebpf/containers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Service is a kubernetes container service.
type Service struct {
	node       string
	ignoreNS   []string
	cgroupRoot string

	events chan containers.ContainerEvent

	doneCh chan struct{}
}

// New returns a kuberenetes container service.
func New(node, cgroupRoot string, ignoreNs []string) (*Service, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	client, err := k8s.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return NewWithClient(client, node, cgroupRoot, ignoreNs)
}

// NewWithClient returns a kuberenetes container service using the
// given kubernetes client.
func NewWithClient(client *k8s.Clientset, node, cgroupRoot string, ignoreNs []string) (*Service, error) {
	svc := &Service{
		node:       node,
		ignoreNS:   ignoreNs,
		cgroupRoot: cgroupRoot,
		events:     make(chan containers.ContainerEvent, 100),
		doneCh:     make(chan struct{}),
	}

	fac := informers.NewSharedInformerFactory(client, time.Minute)
	fac.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    svc.onAddPod(),
		UpdateFunc: svc.onUpdatePod(),
		DeleteFunc: svc.onDeletePod(),
	})

	go fac.Start(svc.doneCh)

	for typ, ok := range fac.WaitForCacheSync(svc.doneCh) {
		if !ok {
			return nil, fmt.Errorf("could not sync k8s object caches for %q", typ)
		}
	}

	return svc, nil
}

func (s *Service) onAddPod() func(obj interface{}) {
	return func(obj interface{}) {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return
		}

		// TODO: add pod from mapping

		if !s.shouldEmit(pod) || pod.Status.Phase != corev1.PodRunning {
			return
		}

		s.events <- containers.ContainerEvent{
			Type:       containers.Added,
			Name:       pod.Namespace + "/" + pod.Name,
			CGroupPath: cgroupPath(s.cgroupRoot, pod),
		}
		return
	}
}

func (s *Service) onUpdatePod() func(oldObj, newObj interface{}) {
	return func(oldObj, newObj interface{}) {
		pod, ok := newObj.(*corev1.Pod)
		if !ok {
			return
		}

		// TODO: check old ips vs new ips for changes

		if !s.shouldEmit(pod) {
			return
		}

		evnt := containers.ContainerEvent{
			Name:       pod.Namespace + "/" + pod.Name,
			CGroupPath: cgroupPath(s.cgroupRoot, pod),
		}

		switch pod.Status.Phase {
		case corev1.PodPending:
			return
		case corev1.PodRunning:
			evnt.Type = containers.Added
		default:
			evnt.Type = containers.Removed
		}

		s.events <- evnt
		return
	}
}

func (s *Service) onDeletePod() func(obj interface{}) {
	return func(obj interface{}) {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return
		}

		// TODO: remove pod from mapping

		if !s.shouldEmit(pod) {
			return
		}

		s.events <- containers.ContainerEvent{
			Type:       containers.Removed,
			Name:       pod.Namespace + "/" + pod.Name,
			CGroupPath: cgroupPath(s.cgroupRoot, pod),
		}
		return
	}
}

func (s *Service) shouldEmit(pod *corev1.Pod) bool {
	if pod.Spec.NodeName != s.node {
		return false
	}

	for _, ns := range s.ignoreNS {
		if pod.Namespace == ns {
			return false
		}
	}

	return true
}

// Events returns a channel of pod events.
func (s *Service) Events() <-chan containers.ContainerEvent {
	return s.events
}

// Name resolves an IP and port combination into a pod name.
func (s *Service) Name(ip uint32, port uint16) string {
	return ""
}

// Close closes the container service.
func (s *Service) Close() error {
	close(s.doneCh)
	close(s.events)

	return nil
}

func cgroupPath(root string, pod *corev1.Pod) string {
	return fmt.Sprintf("%s/kubepods/%s/pod%s", root, strings.ToLower(string(pod.Status.QOSClass)), string(pod.UID))
}
